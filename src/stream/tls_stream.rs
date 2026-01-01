//! Fake TLS 1.3 stream wrappers
//!
//! This module provides stateful async stream wrappers that handle
//! TLS record framing with proper partial read/write handling.
//!
//! These are "fake" TLS streams - they wrap data in valid TLS 1.3
//! Application Data records but don't perform actual TLS encryption.
//! The actual encryption is handled by the crypto layer underneath.
//!
//! Key design principles:
//! - Explicit state machines for all async operations
//! - Never lose data on partial reads
//! - Atomic TLS record formation for writes
//! - Proper handling of all TLS record types

use bytes::{Bytes, BytesMut, BufMut};
use std::io::{self, Error, ErrorKind, Result};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt, ReadBuf};

use crate::protocol::constants::{
    TLS_VERSION, TLS_RECORD_APPLICATION, TLS_RECORD_CHANGE_CIPHER,
    TLS_RECORD_HANDSHAKE, TLS_RECORD_ALERT, MAX_TLS_RECORD_SIZE,
};
use super::state::{StreamState, HeaderBuffer, YieldBuffer, WriteBuffer};

// ============= Constants =============

/// TLS record header size
const TLS_HEADER_SIZE: usize = 5;

/// Maximum TLS record payload size (16KB as per TLS spec)
const MAX_TLS_PAYLOAD: usize = 16384;

/// Maximum pending write buffer
const MAX_PENDING_WRITE: usize = 64 * 1024;

// ============= TLS Record Types =============

/// Parsed TLS record header
#[derive(Debug, Clone, Copy)]
struct TlsRecordHeader {
    /// Record type (0x17 = Application Data, 0x14 = Change Cipher, etc.)
    record_type: u8,
    /// TLS version bytes
    version: [u8; 2],
    /// Payload length
    length: u16,
}

impl TlsRecordHeader {
    /// Parse header from 5 bytes
    fn parse(header: &[u8; 5]) -> Option<Self> {
        let record_type = header[0];
        let version = [header[1], header[2]];
        let length = u16::from_be_bytes([header[3], header[4]]);
        
        Some(Self {
            record_type,
            version,
            length,
        })
    }
    
    /// Validate the header
    fn validate(&self) -> Result<()> {
        // Check version (accept TLS 1.0 for ClientHello, TLS 1.2/1.3 for others)
        if self.version != [0x03, 0x01] && self.version != TLS_VERSION {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid TLS version: {:02x?}", self.version),
            ));
        }
        
        // Check length
        if self.length as usize > MAX_TLS_RECORD_SIZE {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("TLS record too large: {} bytes", self.length),
            ));
        }
        
        Ok(())
    }
    
    /// Check if this is an application data record
    fn is_application_data(&self) -> bool {
        self.record_type == TLS_RECORD_APPLICATION
    }
    
    /// Check if this is a change cipher spec record (should be skipped)
    fn is_change_cipher_spec(&self) -> bool {
        self.record_type == TLS_RECORD_CHANGE_CIPHER
    }
    
    /// Build header bytes
    fn to_bytes(&self) -> [u8; 5] {
        [
            self.record_type,
            self.version[0],
            self.version[1],
            (self.length >> 8) as u8,
            self.length as u8,
        ]
    }
}

// ============= FakeTlsReader State =============

/// State machine states for FakeTlsReader
#[derive(Debug)]
enum TlsReaderState {
    /// Ready to read a new TLS record
    Idle,
    
    /// Reading the 5-byte TLS record header
    ReadingHeader {
        /// Header buffer (5 bytes)
        header: HeaderBuffer<TLS_HEADER_SIZE>,
    },
    
    /// Reading the TLS record body
    ReadingBody {
        /// Parsed record type
        record_type: u8,
        /// Total body length
        length: usize,
        /// Buffer for body data
        buffer: BytesMut,
    },
    
    /// Have decrypted data ready to yield to caller
    Yielding {
        /// Buffer containing data to yield
        buffer: YieldBuffer,
    },
    
    /// Stream encountered an error and cannot be used
    Poisoned {
        /// The error that caused poisoning
        error: Option<io::Error>,
    },
}

impl StreamState for TlsReaderState {
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Poisoned { .. })
    }
    
    fn is_poisoned(&self) -> bool {
        matches!(self, Self::Poisoned { .. })
    }
    
    fn state_name(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::ReadingHeader { .. } => "ReadingHeader",
            Self::ReadingBody { .. } => "ReadingBody",
            Self::Yielding { .. } => "Yielding",
            Self::Poisoned { .. } => "Poisoned",
        }
    }
}

// ============= FakeTlsReader =============

/// Reader that unwraps TLS 1.3 records with proper state machine
///
/// This reader handles partial reads correctly by maintaining internal state
/// and never losing any data that has been read from upstream.
///
/// # State Machine
///
/// ┌──────────┐                    ┌───────────────┐
/// │   Idle   │ -----------------> │ ReadingHeader │
/// └──────────┘                    └───────┬───────┘
///      ▲                                  │
///      │                           header complete
///      │                                  │
///      │                                  │
///      │                          ┌───────────────┐
///      │        skip record       │  ReadingBody  │
///      │ <-------- (CCS) -------- │               │
///      │                          └───────┬───────┘
///      │                                  │
///      │                              body complete
///      │      drained                     │
///      │ <-----------------┐              │
///      │                   │      ┌───────────────┐
///      │                   └----- │   Yielding    │
///      │                          └───────────────┘
///      │
///      │    errors /w any state
///      │
/// ┌───────────────────────────────────────────────┐
/// │                    Poisoned                   │
/// └───────────────────────────────────────────────┘
///
pub struct FakeTlsReader<R> {
    /// Upstream reader
    upstream: R,
    /// Current state
    state: TlsReaderState,
}

impl<R> FakeTlsReader<R> {
    /// Create new fake TLS reader
    pub fn new(upstream: R) -> Self {
        Self {
            upstream,
            state: TlsReaderState::Idle,
        }
    }
    
    /// Get reference to upstream
    pub fn get_ref(&self) -> &R {
        &self.upstream
    }
    
    /// Get mutable reference to upstream
    pub fn get_mut(&mut self) -> &mut R {
        &mut self.upstream
    }
    
    /// Consume and return upstream
    pub fn into_inner(self) -> R {
        self.upstream
    }
    
    /// Check if stream is in poisoned state
    pub fn is_poisoned(&self) -> bool {
        self.state.is_poisoned()
    }
    
    /// Get current state name (for debugging)
    pub fn state_name(&self) -> &'static str {
        self.state.state_name()
    }
    
    /// Transition to poisoned state
    fn poison(&mut self, error: io::Error) {
        self.state = TlsReaderState::Poisoned { error: Some(error) };
    }
    
    /// Take error from poisoned state
    fn take_poison_error(&mut self) -> io::Error {
        match &mut self.state {
            TlsReaderState::Poisoned { error } => {
                error.take().unwrap_or_else(|| {
                    io::Error::new(ErrorKind::Other, "stream previously poisoned")
                })
            }
            _ => io::Error::new(ErrorKind::Other, "stream not poisoned"),
        }
    }
}

/// Result of polling for header completion
enum HeaderPollResult {
    /// Need more data
    Pending,
    /// EOF at record boundary (clean close)
    Eof,
    /// Header complete, parsed successfully
    Complete(TlsRecordHeader),
    /// Error occurred
    Error(io::Error),
}

/// Result of polling for body completion
enum BodyPollResult {
    /// Need more data
    Pending,
    /// Body complete
    Complete(Bytes),
    /// Error occurred
    Error(io::Error),
}

impl<R: AsyncRead + Unpin> AsyncRead for FakeTlsReader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        let this = self.get_mut();
        
        loop {
            // Take ownership of state to avoid borrow conflicts
            let state = std::mem::replace(&mut this.state, TlsReaderState::Idle);
            
            match state {
                // Poisoned state - return error
                TlsReaderState::Poisoned { error } => {
                    this.state = TlsReaderState::Poisoned { error: None };
                    let err = error.unwrap_or_else(|| {
                        io::Error::new(ErrorKind::Other, "stream previously poisoned")
                    });
                    return Poll::Ready(Err(err));
                }
                
                // Have buffered data to yield
                TlsReaderState::Yielding { mut buffer } => {
                    if buf.remaining() == 0 {
                        this.state = TlsReaderState::Yielding { buffer };
                        return Poll::Ready(Ok(()));
                    }
                    
                    // Copy as much as possible to output
                    let to_copy = buffer.remaining().min(buf.remaining());
                    let dst = buf.initialize_unfilled_to(to_copy);
                    let copied = buffer.copy_to(dst);
                    buf.advance(copied);
                    
                    // If buffer is drained, transition to Idle
                    if buffer.is_empty() {
                        this.state = TlsReaderState::Idle;
                    } else {
                        this.state = TlsReaderState::Yielding { buffer };
                    }
                    
                    return Poll::Ready(Ok(()));
                }
                
                // Ready to read a new TLS record
                TlsReaderState::Idle => {
                    if buf.remaining() == 0 {
                        this.state = TlsReaderState::Idle;
                        return Poll::Ready(Ok(()));
                    }
                    
                    // Start reading header
                    this.state = TlsReaderState::ReadingHeader {
                        header: HeaderBuffer::new(),
                    };
                    // Continue to ReadingHeader
                }
                
                // Reading TLS record header
                TlsReaderState::ReadingHeader { mut header } => {
                    // Poll to fill header
                    let result = poll_read_header(&mut this.upstream, cx, &mut header);
                    
                    match result {
                        HeaderPollResult::Pending => {
                            this.state = TlsReaderState::ReadingHeader { header };
                            return Poll::Pending;
                        }
                        HeaderPollResult::Eof => {
                            this.state = TlsReaderState::Idle;
                            return Poll::Ready(Ok(()));
                        }
                        HeaderPollResult::Error(e) => {
                            this.poison(Error::new(e.kind(), e.to_string()));
                            return Poll::Ready(Err(e));
                        }
                        HeaderPollResult::Complete(parsed) => {
                            // Validate header
                            if let Err(e) = parsed.validate() {
                                this.poison(Error::new(e.kind(), e.to_string()));
                                return Poll::Ready(Err(e));
                            }
                            
                            let length = parsed.length as usize;
                            
                            // Transition to reading body
                            this.state = TlsReaderState::ReadingBody {
                                record_type: parsed.record_type,
                                length,
                                buffer: BytesMut::with_capacity(length),
                            };
                        }
                    }
                }
                
                // Reading TLS record body
                TlsReaderState::ReadingBody { record_type, length, mut buffer } => {
                    let result = poll_read_body(&mut this.upstream, cx, &mut buffer, length);
                    
                    match result {
                        BodyPollResult::Pending => {
                            this.state = TlsReaderState::ReadingBody { record_type, length, buffer };
                            return Poll::Pending;
                        }
                        BodyPollResult::Error(e) => {
                            this.poison(Error::new(e.kind(), e.to_string()));
                            return Poll::Ready(Err(e));
                        }
                        BodyPollResult::Complete(data) => {
                            // Handle different record types
                            match record_type {
                                TLS_RECORD_CHANGE_CIPHER => {
                                    // Skip Change Cipher Spec, read next record
                                    this.state = TlsReaderState::Idle;
                                    continue;
                                }
                                TLS_RECORD_APPLICATION => {
                                    // Application data - yield to caller
                                    if data.is_empty() {
                                        this.state = TlsReaderState::Idle;
                                        continue;
                                    }
                                    
                                    this.state = TlsReaderState::Yielding {
                                        buffer: YieldBuffer::new(data),
                                    };
                                    // Continue to yield
                                }
                                TLS_RECORD_ALERT => {
                                    // TLS Alert - treat as EOF
                                    this.state = TlsReaderState::Idle;
                                    return Poll::Ready(Ok(()));
                                }
                                TLS_RECORD_HANDSHAKE => {
                                    let err = Error::new(
                                        ErrorKind::InvalidData,
                                        "unexpected TLS handshake record"
                                    );
                                    this.poison(Error::new(err.kind(), err.to_string()));
                                    return Poll::Ready(Err(err));
                                }
                                _ => {
                                    let err = Error::new(
                                        ErrorKind::InvalidData,
                                        format!("unknown TLS record type: 0x{:02x}", record_type)
                                    );
                                    this.poison(Error::new(err.kind(), err.to_string()));
                                    return Poll::Ready(Err(err));
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Poll to read and fill header buffer (standalone function to avoid borrow issues)
fn poll_read_header<R: AsyncRead + Unpin>(
    upstream: &mut R,
    cx: &mut Context<'_>,
    header: &mut HeaderBuffer<TLS_HEADER_SIZE>,
) -> HeaderPollResult {
    while !header.is_complete() {
        let unfilled = header.unfilled_mut();
        let mut read_buf = ReadBuf::new(unfilled);
        
        match Pin::new(&mut *upstream).poll_read(cx, &mut read_buf) {
            Poll::Pending => return HeaderPollResult::Pending,
            Poll::Ready(Err(e)) => return HeaderPollResult::Error(e),
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    // EOF
                    if header.as_slice().is_empty() {
                        return HeaderPollResult::Eof;
                    } else {
                        return HeaderPollResult::Error(Error::new(
                            ErrorKind::UnexpectedEof,
                            format!("unexpected EOF in TLS header (got {} of 5 bytes)", 
                                header.as_slice().len())
                        ));
                    }
                }
                header.advance(n);
            }
        }
    }
    
    // Parse header
    let header_bytes = *header.as_array();
    match TlsRecordHeader::parse(&header_bytes) {
        Some(h) => HeaderPollResult::Complete(h),
        None => HeaderPollResult::Error(Error::new(
            ErrorKind::InvalidData,
            "failed to parse TLS header"
        )),
    }
}

/// Poll to read record body (standalone function to avoid borrow issues)
fn poll_read_body<R: AsyncRead + Unpin>(
    upstream: &mut R,
    cx: &mut Context<'_>,
    buffer: &mut BytesMut,
    target_len: usize,
) -> BodyPollResult {
    while buffer.len() < target_len {
        let remaining = target_len - buffer.len();
        
        // Read into a temporary buffer
        let mut temp = vec![0u8; remaining.min(8192)];
        let mut read_buf = ReadBuf::new(&mut temp);
        
        match Pin::new(&mut *upstream).poll_read(cx, &mut read_buf) {
            Poll::Pending => return BodyPollResult::Pending,
            Poll::Ready(Err(e)) => return BodyPollResult::Error(e),
            Poll::Ready(Ok(())) => {
                let n = read_buf.filled().len();
                if n == 0 {
                    return BodyPollResult::Error(Error::new(
                        ErrorKind::UnexpectedEof,
                        format!("unexpected EOF in TLS body (got {} of {} bytes)",
                            buffer.len(), target_len)
                    ));
                }
                buffer.extend_from_slice(&temp[..n]);
            }
        }
    }
    
    BodyPollResult::Complete(buffer.split().freeze())
}

impl<R: AsyncRead + Unpin> FakeTlsReader<R> {
    /// Read exactly n bytes through TLS layer
    ///
    /// This is a convenience method that accumulates data across
    /// multiple TLS records until exactly n bytes are available.
    pub async fn read_exact(&mut self, n: usize) -> Result<Bytes> {
        if self.is_poisoned() {
            return Err(self.take_poison_error());
        }
        
        let mut result = BytesMut::with_capacity(n);
        
        while result.len() < n {
            let mut buf = vec![0u8; n - result.len()];
            let read = AsyncReadExt::read(self, &mut buf).await?;
            
            if read == 0 {
                return Err(Error::new(
                    ErrorKind::UnexpectedEof,
                    format!("expected {} bytes, got {}", n, result.len())
                ));
            }
            
            result.extend_from_slice(&buf[..read]);
        }
        
        Ok(result.freeze())
    }
}

// ============= FakeTlsWriter State =============

/// State machine states for FakeTlsWriter
#[derive(Debug)]
enum TlsWriterState {
    /// Ready to accept new data
    Idle,
    
    /// Writing a complete TLS record
    WritingRecord {
        /// Complete record (header + body) to write
        record: WriteBuffer,
        /// Original payload size (for return value calculation)
        payload_size: usize,
    },
    
    /// Stream encountered an error and cannot be used
    Poisoned {
        /// The error that caused poisoning
        error: Option<io::Error>,
    },
}

impl StreamState for TlsWriterState {
    fn is_terminal(&self) -> bool {
        matches!(self, Self::Poisoned { .. })
    }
    
    fn is_poisoned(&self) -> bool {
        matches!(self, Self::Poisoned { .. })
    }
    
    fn state_name(&self) -> &'static str {
        match self {
            Self::Idle => "Idle",
            Self::WritingRecord { .. } => "WritingRecord",
            Self::Poisoned { .. } => "Poisoned",
        }
    }
}

// ============= FakeTlsWriter =============

/// Writer that wraps data in TLS 1.3 records with proper state machine
///
/// This writer handles partial writes correctly by:
/// - Building complete TLS records before writing
/// - Maintaining internal state for partial record writes
/// - Never splitting a record mid-write to upstream
///
/// # State Machine
///
/// ┌──────────┐     write      ┌─────────────────┐
/// │   Idle   │ -------------> │  WritingRecord  │
/// │          │ <------------- │                 │
/// └──────────┘    complete    └─────────────────┘
///      │                              │
///      │          < errors >          │ 
///      │                              │
/// ┌─────────────────────────────────────────────┐
/// │                Poisoned                     │
/// └─────────────────────────────────────────────┘
///
/// # Record Formation
///
/// Data is chunked into records of at most MAX_TLS_PAYLOAD bytes.
/// Each record has a 5-byte header prepended.
pub struct FakeTlsWriter<W> {
    /// Upstream writer
    upstream: W,
    /// Current state
    state: TlsWriterState,
}

impl<W> FakeTlsWriter<W> {
    /// Create new fake TLS writer
    pub fn new(upstream: W) -> Self {
        Self {
            upstream,
            state: TlsWriterState::Idle,
        }
    }
    
    /// Get reference to upstream
    pub fn get_ref(&self) -> &W {
        &self.upstream
    }
    
    /// Get mutable reference to upstream
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.upstream
    }
    
    /// Consume and return upstream
    pub fn into_inner(self) -> W {
        self.upstream
    }
    
    /// Check if stream is in poisoned state
    pub fn is_poisoned(&self) -> bool {
        self.state.is_poisoned()
    }
    
    /// Get current state name (for debugging)
    pub fn state_name(&self) -> &'static str {
        self.state.state_name()
    }
    
    /// Check if there's a pending record to write
    pub fn has_pending(&self) -> bool {
        matches!(&self.state, TlsWriterState::WritingRecord { record, .. } if !record.is_empty())
    }
    
    /// Transition to poisoned state
    fn poison(&mut self, error: io::Error) {
        self.state = TlsWriterState::Poisoned { error: Some(error) };
    }
    
    /// Take error from poisoned state
    fn take_poison_error(&mut self) -> io::Error {
        match &mut self.state {
            TlsWriterState::Poisoned { error } => {
                error.take().unwrap_or_else(|| {
                    io::Error::new(ErrorKind::Other, "stream previously poisoned")
                })
            }
            _ => io::Error::new(ErrorKind::Other, "stream not poisoned"),
        }
    }
    
    /// Build a TLS Application Data record
    fn build_record(data: &[u8]) -> BytesMut {
        let header = TlsRecordHeader {
            record_type: TLS_RECORD_APPLICATION,
            version: TLS_VERSION,
            length: data.len() as u16,
        };
        
        let mut record = BytesMut::with_capacity(TLS_HEADER_SIZE + data.len());
        record.extend_from_slice(&header.to_bytes());
        record.extend_from_slice(data);
        record
    }
}

/// Result of flushing pending record
enum FlushResult {
    /// All data flushed, returns payload size
    Complete(usize),
    /// Need to wait for upstream
    Pending,
    /// Error occurred
    Error(io::Error),
}

impl<W: AsyncWrite + Unpin> FakeTlsWriter<W> {
    /// Try to flush pending record to upstream (standalone logic)
    fn poll_flush_record_inner(
        upstream: &mut W,
        cx: &mut Context<'_>,
        record: &mut WriteBuffer,
    ) -> FlushResult {
        while !record.is_empty() {
            let data = record.pending();
            match Pin::new(&mut *upstream).poll_write(cx, data) {
                Poll::Pending => return FlushResult::Pending,
                
                Poll::Ready(Err(e)) => return FlushResult::Error(e),
                
                Poll::Ready(Ok(0)) => {
                    return FlushResult::Error(Error::new(
                        ErrorKind::WriteZero,
                        "upstream returned 0 bytes written"
                    ));
                }
                
                Poll::Ready(Ok(n)) => {
                    record.advance(n);
                }
            }
        }
        
        FlushResult::Complete(0)
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for FakeTlsWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        let this = self.get_mut();
        
        // Take ownership of state
        let state = std::mem::replace(&mut this.state, TlsWriterState::Idle);
        
        match state {
            TlsWriterState::Poisoned { error } => {
                this.state = TlsWriterState::Poisoned { error: None };
                let err = error.unwrap_or_else(|| {
                    Error::new(ErrorKind::Other, "stream previously poisoned")
                });
                return Poll::Ready(Err(err));
            }
            
            TlsWriterState::WritingRecord { mut record, payload_size } => {
                // Continue flushing existing record
                match Self::poll_flush_record_inner(&mut this.upstream, cx, &mut record) {
                    FlushResult::Pending => {
                        this.state = TlsWriterState::WritingRecord { record, payload_size };
                        return Poll::Pending;
                    }
                    FlushResult::Error(e) => {
                        this.poison(Error::new(e.kind(), e.to_string()));
                        return Poll::Ready(Err(e));
                    }
                    FlushResult::Complete(_) => {
                        this.state = TlsWriterState::Idle;
                        // Fall through to handle new write
                    }
                }
            }
            
            TlsWriterState::Idle => {
                this.state = TlsWriterState::Idle;
            }
        }
        
        // Now in Idle state
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        
        // Chunk to maximum TLS payload size
        let chunk_size = buf.len().min(MAX_TLS_PAYLOAD);
        let chunk = &buf[..chunk_size];
        
        // Build the complete record
        let record_data = Self::build_record(chunk);
        
        // Try to write directly first
        match Pin::new(&mut this.upstream).poll_write(cx, &record_data) {
            Poll::Ready(Ok(n)) if n == record_data.len() => {
                // Complete record written
                Poll::Ready(Ok(chunk_size))
            }
            
            Poll::Ready(Ok(n)) => {
                // Partial write - buffer the rest
                let mut write_buffer = WriteBuffer::with_max_size(MAX_PENDING_WRITE);
                let _ = write_buffer.extend(&record_data[n..]);
                
                this.state = TlsWriterState::WritingRecord {
                    record: write_buffer,
                    payload_size: chunk_size,
                };
                
                // We've accepted chunk_size bytes from caller
                Poll::Ready(Ok(chunk_size))
            }
            
            Poll::Ready(Err(e)) => {
                this.poison(Error::new(e.kind(), e.to_string()));
                Poll::Ready(Err(e))
            }
            
            Poll::Pending => {
                // Buffer the entire record
                let mut write_buffer = WriteBuffer::with_max_size(MAX_PENDING_WRITE);
                let _ = write_buffer.extend(&record_data);
                
                this.state = TlsWriterState::WritingRecord {
                    record: write_buffer,
                    payload_size: chunk_size,
                };
                
                // Wake to try again
                cx.waker().wake_by_ref();
                
                // We've accepted chunk_size bytes from caller
                Poll::Ready(Ok(chunk_size))
            }
        }
    }
    
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        
        // Take ownership of state
        let state = std::mem::replace(&mut this.state, TlsWriterState::Idle);
        
        match state {
            TlsWriterState::Poisoned { error } => {
                this.state = TlsWriterState::Poisoned { error: None };
                let err = error.unwrap_or_else(|| {
                    Error::new(ErrorKind::Other, "stream previously poisoned")
                });
                return Poll::Ready(Err(err));
            }
            
            TlsWriterState::WritingRecord { mut record, payload_size } => {
                match Self::poll_flush_record_inner(&mut this.upstream, cx, &mut record) {
                    FlushResult::Pending => {
                        this.state = TlsWriterState::WritingRecord { record, payload_size };
                        return Poll::Pending;
                    }
                    FlushResult::Error(e) => {
                        this.poison(Error::new(e.kind(), e.to_string()));
                        return Poll::Ready(Err(e));
                    }
                    FlushResult::Complete(_) => {
                        this.state = TlsWriterState::Idle;
                    }
                }
            }
            
            TlsWriterState::Idle => {
                this.state = TlsWriterState::Idle;
            }
        }
        
        // Flush upstream
        Pin::new(&mut this.upstream).poll_flush(cx)
    }
    
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let this = self.get_mut();
        
        // Take ownership of state
        let state = std::mem::replace(&mut this.state, TlsWriterState::Idle);
        
        match state {
            TlsWriterState::WritingRecord { mut record, payload_size } => {
                // Try to flush pending (best effort)
                match Self::poll_flush_record_inner(&mut this.upstream, cx, &mut record) {
                    FlushResult::Pending => {
                        // Can't complete flush, continue with shutdown anyway
                        this.state = TlsWriterState::Idle;
                    }
                    FlushResult::Error(_) => {
                        // Ignore errors during shutdown
                        this.state = TlsWriterState::Idle;
                    }
                    FlushResult::Complete(_) => {
                        this.state = TlsWriterState::Idle;
                    }
                }
            }
            _ => {
                this.state = TlsWriterState::Idle;
            }
        }
        
        // Shutdown upstream
        Pin::new(&mut this.upstream).poll_shutdown(cx)
    }
}

impl<W: AsyncWrite + Unpin> FakeTlsWriter<W> {
    /// Write all data wrapped in TLS records (async method)
    ///
    /// This convenience method handles chunking large data into
    /// multiple TLS records automatically.
    pub async fn write_all_tls(&mut self, data: &[u8]) -> Result<()> {
        let mut written = 0;
        while written < data.len() {
            let chunk_size = (data.len() - written).min(MAX_TLS_PAYLOAD);
            let chunk = &data[written..written + chunk_size];
            
            AsyncWriteExt::write_all(self, chunk).await?;
            written += chunk_size;
        }
        
        self.flush().await
    }
}

// ============= Tests =============

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    
    // ============= Test Helpers =============
    
    /// Build a valid TLS Application Data record
    fn build_tls_record(data: &[u8]) -> Vec<u8> {
        let mut record = vec![
            TLS_RECORD_APPLICATION,
            TLS_VERSION[0],
            TLS_VERSION[1],
            (data.len() >> 8) as u8,
            data.len() as u8,
        ];
        record.extend_from_slice(data);
        record
    }
    
    /// Build a Change Cipher Spec record
    fn build_ccs_record() -> Vec<u8> {
        vec![
            TLS_RECORD_CHANGE_CIPHER,
            TLS_VERSION[0],
            TLS_VERSION[1],
            0x00, 0x01,  // length = 1
            0x01,        // CCS byte
        ]
    }
    
    /// Mock reader that returns data in chunks
    struct ChunkedReader {
        data: VecDeque<u8>,
        chunk_size: usize,
    }
    
    impl ChunkedReader {
        fn new(data: &[u8], chunk_size: usize) -> Self {
            Self {
                data: data.iter().copied().collect(),
                chunk_size,
            }
        }
    }
    
    impl AsyncRead for ChunkedReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<Result<()>> {
            if self.data.is_empty() {
                return Poll::Ready(Ok(()));
            }
            
            let to_read = self.chunk_size.min(self.data.len()).min(buf.remaining());
            for _ in 0..to_read {
                if let Some(byte) = self.data.pop_front() {
                    buf.put_slice(&[byte]);
                }
            }
            
            Poll::Ready(Ok(()))
        }
    }
    
    // ============= FakeTlsReader Tests =============
    
    #[tokio::test]
    async fn test_tls_reader_single_record() {
        let payload = b"Hello, TLS!";
        let record = build_tls_record(payload);
        
        let reader = ChunkedReader::new(&record, 100);
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let mut buf = vec![0u8; payload.len()];
        tls_reader.read_exact(&mut buf).await.unwrap();
        
        assert_eq!(&buf, payload);
    }
    
    #[tokio::test]
    async fn test_tls_reader_multiple_records() {
        let payload1 = b"First record";
        let payload2 = b"Second record";
        
        let mut data = build_tls_record(payload1);
        data.extend_from_slice(&build_tls_record(payload2));
        
        let reader = ChunkedReader::new(&data, 100);
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let mut buf1 = vec![0u8; payload1.len()];
        tls_reader.read_exact(&mut buf1).await.unwrap();
        assert_eq!(&buf1, payload1);
        
        let mut buf2 = vec![0u8; payload2.len()];
        tls_reader.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, payload2);
    }
    
    #[tokio::test]
    async fn test_tls_reader_partial_header() {
        // Read header byte by byte
        let payload = b"Test";
        let record = build_tls_record(payload);
        
        let reader = ChunkedReader::new(&record, 1); // 1 byte at a time!
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let mut buf = vec![0u8; payload.len()];
        tls_reader.read_exact(&mut buf).await.unwrap();
        
        assert_eq!(&buf, payload);
    }
    
    #[tokio::test]
    async fn test_tls_reader_partial_body() {
        let payload = b"This is a longer payload that will be read in parts";
        let record = build_tls_record(payload);
        
        let reader = ChunkedReader::new(&record, 7); // Awkward chunk size
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let mut buf = vec![0u8; payload.len()];
        tls_reader.read_exact(&mut buf).await.unwrap();
        
        assert_eq!(&buf, payload);
    }
    
    #[tokio::test]
    async fn test_tls_reader_skip_ccs() {
        // CCS record followed by application data
        let mut data = build_ccs_record();
        let payload = b"After CCS";
        data.extend_from_slice(&build_tls_record(payload));
        
        let reader = ChunkedReader::new(&data, 100);
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let mut buf = vec![0u8; payload.len()];
        tls_reader.read_exact(&mut buf).await.unwrap();
        
        assert_eq!(&buf, payload);
    }
    
    #[tokio::test]
    async fn test_tls_reader_multiple_ccs() {
        // Multiple CCS records
        let mut data = build_ccs_record();
        data.extend_from_slice(&build_ccs_record());
        let payload = b"After multiple CCS";
        data.extend_from_slice(&build_tls_record(payload));
        
        let reader = ChunkedReader::new(&data, 3); // Small chunks
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let mut buf = vec![0u8; payload.len()];
        tls_reader.read_exact(&mut buf).await.unwrap();
        
        assert_eq!(&buf, payload);
    }
    
    #[tokio::test]
    async fn test_tls_reader_eof() {
        let reader = ChunkedReader::new(&[], 100);
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let mut buf = vec![0u8; 10];
        let read = tls_reader.read(&mut buf).await.unwrap();
        
        assert_eq!(read, 0);
    }
    
    #[tokio::test]
    async fn test_tls_reader_state_names() {
        let reader = ChunkedReader::new(&[], 100);
        let tls_reader = FakeTlsReader::new(reader);
        
        assert_eq!(tls_reader.state_name(), "Idle");
        assert!(!tls_reader.is_poisoned());
    }
    
    // ============= FakeTlsWriter Tests =============
    
    #[tokio::test]
    async fn test_tls_writer_single_write() {
        let (client, mut server) = duplex(4096);
        let mut writer = FakeTlsWriter::new(client);
        
        let payload = b"Hello, TLS!";
        writer.write_all(payload).await.unwrap();
        writer.flush().await.unwrap();
        
        // Read the TLS record from server
        let mut header = [0u8; 5];
        server.read_exact(&mut header).await.unwrap();
        
        assert_eq!(header[0], TLS_RECORD_APPLICATION);
        assert_eq!(&header[1..3], &TLS_VERSION);
        
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        assert_eq!(length, payload.len());
        
        let mut body = vec![0u8; length];
        server.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, payload);
    }
    
    #[tokio::test]
    async fn test_tls_writer_large_data_chunking() {
        let (client, mut server) = duplex(65536);
        let mut writer = FakeTlsWriter::new(client);
        
        // Write data larger than MAX_TLS_PAYLOAD
        let payload: Vec<u8> = (0..20000).map(|i| (i % 256) as u8).collect();
        writer.write_all(&payload).await.unwrap();
        writer.flush().await.unwrap();
        
        // Read back - should be multiple records
        let mut received = Vec::new();
        let mut records_count = 0;
        
        while received.len() < payload.len() {
            let mut header = [0u8; 5];
            if server.read_exact(&mut header).await.is_err() {
                break;
            }
            
            assert_eq!(header[0], TLS_RECORD_APPLICATION);
            records_count += 1;
            
            let length = u16::from_be_bytes([header[3], header[4]]) as usize;
            assert!(length <= MAX_TLS_PAYLOAD);
            
            let mut body = vec![0u8; length];
            server.read_exact(&mut body).await.unwrap();
            received.extend_from_slice(&body);
        }
        
        assert_eq!(received, payload);
        assert!(records_count >= 2); // Should have multiple records
    }
    
    #[tokio::test]
    async fn test_tls_stream_roundtrip() {
        let (client, server) = duplex(4096);
        
        let mut writer = FakeTlsWriter::new(client);
        let mut reader = FakeTlsReader::new(server);
        
        let original = b"Hello, fake TLS!";
        writer.write_all_tls(original).await.unwrap();
        writer.flush().await.unwrap();
        
        let received = reader.read_exact(original.len()).await.unwrap();
        assert_eq!(&received[..], original);
    }
    
    #[tokio::test]
    async fn test_tls_stream_roundtrip_large() {
        let (client, server) = duplex(4096);
        
        let mut writer = FakeTlsWriter::new(client);
        let mut reader = FakeTlsReader::new(server);
        
        let original: Vec<u8> = (0..50000).map(|i| (i % 256) as u8).collect();
        
        // Write in background
        let write_data = original.clone();
        let write_handle = tokio::spawn(async move {
            writer.write_all_tls(&write_data).await.unwrap();
            writer.shutdown().await.unwrap();
        });
        
        // Read
        let mut received = Vec::new();
        let mut buf = vec![0u8; 1024];
        loop {
            let n = reader.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&buf[..n]);
        }
        
        write_handle.await.unwrap();
        assert_eq!(received, original);
    }
    
    #[tokio::test]
    async fn test_tls_writer_state_names() {
        let (client, _server) = duplex(4096);
        let writer = FakeTlsWriter::new(client);
        
        assert_eq!(writer.state_name(), "Idle");
        assert!(!writer.is_poisoned());
        assert!(!writer.has_pending());
    }
    
    // ============= Error Handling Tests =============
    
    #[tokio::test]
    async fn test_tls_reader_invalid_version() {
        let invalid_record = vec![
            TLS_RECORD_APPLICATION,
            0x04, 0x00,  // Invalid version
            0x00, 0x05,  // length = 5
            0x01, 0x02, 0x03, 0x04, 0x05,
        ];
        
        let reader = ChunkedReader::new(&invalid_record, 100);
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let mut buf = vec![0u8; 5];
        let result = tls_reader.read(&mut buf).await;
        
        assert!(result.is_err());
        assert!(tls_reader.is_poisoned());
    }
    
    #[tokio::test]
    async fn test_tls_reader_unexpected_eof_header() {
        // Partial header
        let partial = vec![TLS_RECORD_APPLICATION, 0x03];
        
        let reader = ChunkedReader::new(&partial, 100);
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let mut buf = vec![0u8; 10];
        let result = tls_reader.read(&mut buf).await;
        
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_tls_reader_unexpected_eof_body() {
        // Valid header but truncated body
        let mut record = vec![
            TLS_RECORD_APPLICATION,
            TLS_VERSION[0], TLS_VERSION[1],
            0x00, 0x10,  // length = 16
        ];
        record.extend_from_slice(&[0u8; 8]); // Only 8 bytes of body
        
        let reader = ChunkedReader::new(&record, 100);
        let mut tls_reader = FakeTlsReader::new(reader);
        
        let mut buf = vec![0u8; 16];
        let result = tls_reader.read(&mut buf).await;
        
        assert!(result.is_err());
    }
    
    // ============= Header Parsing Tests =============
    
    #[test]
    fn test_tls_record_header_parse() {
        let header = [0x17, 0x03, 0x03, 0x01, 0x00];
        let parsed = TlsRecordHeader::parse(&header).unwrap();
        
        assert_eq!(parsed.record_type, TLS_RECORD_APPLICATION);
        assert_eq!(parsed.version, TLS_VERSION);
        assert_eq!(parsed.length, 256);
    }
    
    #[test]
    fn test_tls_record_header_validate() {
        let valid = TlsRecordHeader {
            record_type: TLS_RECORD_APPLICATION,
            version: TLS_VERSION,
            length: 100,
        };
        assert!(valid.validate().is_ok());
        
        let invalid_version = TlsRecordHeader {
            record_type: TLS_RECORD_APPLICATION,
            version: [0x04, 0x00],
            length: 100,
        };
        assert!(invalid_version.validate().is_err());
        
        let too_large = TlsRecordHeader {
            record_type: TLS_RECORD_APPLICATION,
            version: TLS_VERSION,
            length: 20000,
        };
        assert!(too_large.validate().is_err());
    }
    
    #[test]
    fn test_tls_record_header_to_bytes() {
        let header = TlsRecordHeader {
            record_type: TLS_RECORD_APPLICATION,
            version: TLS_VERSION,
            length: 0x1234,
        };
        
        let bytes = header.to_bytes();
        assert_eq!(bytes, [0x17, 0x03, 0x03, 0x12, 0x34]);
    }
}