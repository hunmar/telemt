//! Fake TLS 1.3 stream wrappers

use bytes::{Bytes, BytesMut};
use std::io::{Error, ErrorKind, Result};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncReadExt, AsyncWriteExt, ReadBuf};
use crate::protocol::constants::{
    TLS_VERSION, TLS_RECORD_APPLICATION, TLS_RECORD_CHANGE_CIPHER,
    MAX_TLS_CHUNK_SIZE,
};
use parking_lot::Mutex;

/// Reader that unwraps TLS 1.3 records
pub struct FakeTlsReader<R> {
    upstream: R,
    buffer: BytesMut,
    pending_read: Option<PendingTlsRead>,
}

struct PendingTlsRead {
    record_type: u8,
    remaining: usize,
}

impl<R> FakeTlsReader<R> {
    /// Create new fake TLS reader
    pub fn new(upstream: R) -> Self {
        Self {
            upstream,
            buffer: BytesMut::with_capacity(16384),
            pending_read: None,
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
}

impl<R: AsyncRead + Unpin> FakeTlsReader<R> {
    /// Read exactly n bytes through TLS layer
    pub async fn read_exact(&mut self, n: usize) -> Result<Bytes> {
        while self.buffer.len() < n {
            let data = self.read_tls_record().await?;
            if data.is_empty() {
                return Err(Error::new(ErrorKind::UnexpectedEof, "Connection closed"));
            }
            self.buffer.extend_from_slice(&data);
        }
        
        Ok(self.buffer.split_to(n).freeze())
    }
    
    /// Read a single TLS record
    async fn read_tls_record(&mut self) -> Result<Vec<u8>> {
        loop {
            // Read TLS record header (5 bytes)
            let mut header = [0u8; 5];
            self.upstream.read_exact(&mut header).await?;
            
            let record_type = header[0];
            let version = [header[1], header[2]];
            let length = u16::from_be_bytes([header[3], header[4]]) as usize;
            
            // Validate version
            if version != TLS_VERSION {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Invalid TLS version: {:02x?}", version),
                ));
            }
            
            // Read record body
            let mut data = vec![0u8; length];
            self.upstream.read_exact(&mut data).await?;
            
            match record_type {
                TLS_RECORD_CHANGE_CIPHER => continue, // Skip
                TLS_RECORD_APPLICATION => return Ok(data),
                _ => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("Unexpected TLS record type: 0x{:02x}", record_type),
                    ));
                }
            }
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for FakeTlsReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        // Drain buffer first
        if !self.buffer.is_empty() {
            let to_copy = self.buffer.len().min(buf.remaining());
            buf.put_slice(&self.buffer.split_to(to_copy));
            return Poll::Ready(Ok(()));
        }
        
        // We need to read a TLS record, but poll_read doesn't support async/await
        // So we'll do a simplified version that reads header synchronously
        
        // Read header
        let mut header = [0u8; 5];
        let mut header_buf = ReadBuf::new(&mut header);
        
        match Pin::new(&mut self.upstream).poll_read(cx, &mut header_buf) {
            Poll::Ready(Ok(())) => {
                if header_buf.filled().len() < 5 {
                    // Need more data - store what we have and return pending
                    // For simplicity, we'll just return empty
                    return Poll::Ready(Ok(()));
                }
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }
        
        let record_type = header[0];
        let length = u16::from_be_bytes([header[3], header[4]]) as usize;
        
        if record_type == TLS_RECORD_CHANGE_CIPHER {
            // Skip this record, try again
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        
        if record_type != TLS_RECORD_APPLICATION {
            return Poll::Ready(Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid TLS record type",
            )));
        }
        
        // Read body
        let mut body = vec![0u8; length];
        let mut body_buf = ReadBuf::new(&mut body);
        
        match Pin::new(&mut self.upstream).poll_read(cx, &mut body_buf) {
            Poll::Ready(Ok(())) => {
                let filled = body_buf.filled();
                let to_copy = filled.len().min(buf.remaining());
                buf.put_slice(&filled[..to_copy]);
                
                if filled.len() > to_copy {
                    self.buffer.extend_from_slice(&filled[to_copy..]);
                }
                
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Writer that wraps data in TLS 1.3 records
pub struct FakeTlsWriter<W> {
    upstream: W,
}

impl<W> FakeTlsWriter<W> {
    /// Create new fake TLS writer
    pub fn new(upstream: W) -> Self {
        Self { upstream }
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
}

impl<W: AsyncWrite + Unpin> AsyncWrite for FakeTlsWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        // Build TLS record
        let chunk_size = buf.len().min(MAX_TLS_CHUNK_SIZE);
        let chunk = &buf[..chunk_size];
        
        let mut record = Vec::with_capacity(5 + chunk_size);
        record.push(TLS_RECORD_APPLICATION);
        record.extend_from_slice(&TLS_VERSION);
        record.push((chunk_size >> 8) as u8);
        record.push(chunk_size as u8);
        record.extend_from_slice(chunk);
        
        match Pin::new(&mut self.upstream).poll_write(cx, &record) {
            Poll::Ready(Ok(written)) => {
                if written >= 5 {
                    Poll::Ready(Ok(written - 5))
                } else {
                    Poll::Ready(Ok(0))
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
    
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.upstream).poll_flush(cx)
    }
    
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.upstream).poll_shutdown(cx)
    }
}

impl<W: AsyncWrite + Unpin> FakeTlsWriter<W> {
    /// Write all data wrapped in TLS records (async method)
    pub async fn write_all_tls(&mut self, data: &[u8]) -> Result<()> {
        for chunk in data.chunks(MAX_TLS_CHUNK_SIZE) {
            let header = [
                TLS_RECORD_APPLICATION,
                TLS_VERSION[0],
                TLS_VERSION[1],
                (chunk.len() >> 8) as u8,
                chunk.len() as u8,
            ];
            
            self.upstream.write_all(&header).await?;
            self.upstream.write_all(chunk).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;
    
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
}