use crate::error::{ProxyError, Result};
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const RELAY_MAGIC: &[u8; 4] = b"TMR1";
const RELAY_VERSION: u8 = 1;
const RELAY_STATUS_OK: u8 = 0;
const RELAY_STATUS_AUTH_FAILED: u8 = 1;
const RELAY_STATUS_INVALID_REQUEST: u8 = 2;
const RELAY_STATUS_CONNECT_REFUSED: u8 = 3;
const RELAY_STATUS_NETWORK_UNREACHABLE: u8 = 4;
const RELAY_STATUS_TIMED_OUT: u8 = 5;
const RELAY_STATUS_INTERNAL_ERROR: u8 = 6;

#[derive(Debug, Clone, Copy)]
pub struct RelayBoundAddr {
    pub addr: SocketAddr,
}

pub async fn connect_relay<S>(
    stream: &mut S,
    target: SocketAddr,
    token: Option<&str>,
) -> Result<RelayBoundAddr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let token = token.unwrap_or("").as_bytes();
    if token.len() > u8::MAX as usize {
        return Err(ProxyError::Config(
            "shadowsocks relay_token must be at most 255 bytes".to_string(),
        ));
    }

    let mut request = Vec::with_capacity(4 + 1 + 1 + token.len() + 1 + 16 + 2);
    request.extend_from_slice(RELAY_MAGIC);
    request.push(RELAY_VERSION);
    request.push(token.len() as u8);
    request.extend_from_slice(token);
    encode_socket_addr(&mut request, target);
    stream.write_all(&request).await.map_err(ProxyError::Io)?;
    stream.flush().await.map_err(ProxyError::Io)?;

    let mut header = [0u8; 6];
    stream.read_exact(&mut header).await.map_err(ProxyError::Io)?;
    if &header[..4] != RELAY_MAGIC {
        return Err(ProxyError::Proxy(
            "invalid shadowsocks relay response magic".to_string(),
        ));
    }
    if header[4] != RELAY_VERSION {
        return Err(ProxyError::Proxy(format!(
            "unsupported shadowsocks relay version {}",
            header[4]
        )));
    }

    let status = header[5];
    let bound_addr = read_socket_addr(stream).await?;
    if status != RELAY_STATUS_OK {
        return Err(map_relay_status(status, target, bound_addr));
    }

    Ok(RelayBoundAddr { addr: bound_addr })
}

fn encode_socket_addr(buf: &mut Vec<u8>, addr: SocketAddr) {
    match addr {
        SocketAddr::V4(addr) => {
            buf.push(1u8);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            buf.push(4u8);
            buf.extend_from_slice(&addr.ip().octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
}

async fn read_socket_addr<S>(stream: &mut S) -> Result<SocketAddr>
where
    S: AsyncRead + Unpin,
{
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await.map_err(ProxyError::Io)?;
    match atyp[0] {
        1 => {
            let mut body = [0u8; 6];
            stream.read_exact(&mut body).await.map_err(ProxyError::Io)?;
            let ip = IpAddr::from([body[0], body[1], body[2], body[3]]);
            let port = u16::from_be_bytes([body[4], body[5]]);
            Ok(SocketAddr::new(ip, port))
        }
        4 => {
            let mut body = [0u8; 18];
            stream.read_exact(&mut body).await.map_err(ProxyError::Io)?;
            let ip = IpAddr::from(<[u8; 16]>::try_from(&body[..16]).map_err(|_| {
                ProxyError::Proxy("invalid shadowsocks relay IPv6 address".to_string())
            })?);
            let port = u16::from_be_bytes([body[16], body[17]]);
            Ok(SocketAddr::new(ip, port))
        }
        atyp => Err(ProxyError::Proxy(format!(
            "invalid shadowsocks relay address type {atyp}"
        ))),
    }
}

fn map_relay_status(status: u8, target: SocketAddr, bound_addr: SocketAddr) -> ProxyError {
    match status {
        RELAY_STATUS_AUTH_FAILED => {
            ProxyError::Proxy("shadowsocks relay authentication failed".to_string())
        }
        RELAY_STATUS_INVALID_REQUEST => {
            ProxyError::Proxy("shadowsocks relay rejected request".to_string())
        }
        RELAY_STATUS_CONNECT_REFUSED => ProxyError::ConnectionRefused {
            addr: target.to_string(),
        },
        RELAY_STATUS_NETWORK_UNREACHABLE => ProxyError::Proxy(format!(
            "shadowsocks relay network unreachable for {target}"
        )),
        RELAY_STATUS_TIMED_OUT => ProxyError::ConnectionTimeout {
            addr: target.to_string(),
        },
        RELAY_STATUS_INTERNAL_ERROR => ProxyError::Proxy(format!(
            "shadowsocks relay internal error for {target} (bound={bound_addr})"
        )),
        other => ProxyError::Proxy(format!(
            "unknown shadowsocks relay status {other} for {target}"
        )),
    }
}
