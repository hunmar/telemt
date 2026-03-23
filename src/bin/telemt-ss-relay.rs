use std::env;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};

const RELAY_MAGIC: &[u8; 4] = b"TMR1";
const RELAY_VERSION: u8 = 1;
const RELAY_STATUS_OK: u8 = 0;
const RELAY_STATUS_AUTH_FAILED: u8 = 1;
const RELAY_STATUS_INVALID_REQUEST: u8 = 2;
const RELAY_STATUS_CONNECT_REFUSED: u8 = 3;
const RELAY_STATUS_NETWORK_UNREACHABLE: u8 = 4;
const RELAY_STATUS_TIMED_OUT: u8 = 5;
const RELAY_STATUS_INTERNAL_ERROR: u8 = 6;

#[derive(Clone)]
struct RelayConfig {
    listen_addr: SocketAddr,
    token: Option<Vec<u8>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Arc::new(parse_args(env::args().skip(1))?);
    eprintln!("telemt-ss-relay listening on {}", config.listen_addr);
    let listener = TcpListener::bind(config.listen_addr).await?;

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        let config = Arc::clone(&config);
        tokio::spawn(async move {
            if let Err(error) = handle_client(stream, config).await {
                eprintln!("telemt-ss-relay client {peer_addr}: {error}");
            }
        });
    }
}

fn parse_args<I>(mut args: I) -> Result<RelayConfig, Box<dyn std::error::Error>>
where
    I: Iterator<Item = String>,
{
    let mut listen_addr = String::from("127.0.0.1:19080");
    let mut token: Option<String> = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--listen" => {
                listen_addr = args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing value for --listen")
                })?;
            }
            "--token" => {
                token = Some(args.next().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "missing value for --token")
                })?);
            }
            "-h" | "--help" => {
                println!("Usage: telemt-ss-relay [--listen ip:port] [--token token]");
                std::process::exit(0);
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown argument: {arg}"),
                )
                .into());
            }
        }
    }

    let listen_addr = listen_addr.parse().map_err(|error| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid --listen socket address: {error}"),
        )
    })?;
    let token = token.map(|value| value.into_bytes());
    if token.as_ref().is_some_and(|value| value.len() > u8::MAX as usize) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--token must be at most 255 bytes",
        )
        .into());
    }

    Ok(RelayConfig { listen_addr, token })
}

async fn handle_client(mut inbound: TcpStream, config: Arc<RelayConfig>) -> io::Result<()> {
    inbound.set_nodelay(true).ok();
    let target = read_request(&mut inbound, config.token.as_deref()).await?;

    let mut outbound = match TcpStream::connect(target).await {
        Ok(stream) => stream,
        Err(error) => {
            let status = match error.kind() {
                io::ErrorKind::ConnectionRefused => RELAY_STATUS_CONNECT_REFUSED,
                io::ErrorKind::TimedOut => RELAY_STATUS_TIMED_OUT,
                io::ErrorKind::AddrNotAvailable
                | io::ErrorKind::NotFound
                | io::ErrorKind::NetworkUnreachable
                | io::ErrorKind::HostUnreachable => RELAY_STATUS_NETWORK_UNREACHABLE,
                _ => RELAY_STATUS_INTERNAL_ERROR,
            };
            let _ = write_response(&mut inbound, status, None).await;
            return Err(error);
        }
    };
    outbound.set_nodelay(true).ok();

    let bound_addr = outbound.local_addr()?;
    write_response(&mut inbound, RELAY_STATUS_OK, Some(bound_addr)).await?;
    let _ = copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
}

async fn read_request(stream: &mut TcpStream, expected_token: Option<&[u8]>) -> io::Result<SocketAddr> {
    let mut header = [0u8; 6];
    stream.read_exact(&mut header).await?;
    if &header[..4] != RELAY_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid relay magic",
        ));
    }
    if header[4] != RELAY_VERSION {
        let _ = write_response(stream, RELAY_STATUS_INVALID_REQUEST, None).await;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported relay version {}", header[4]),
        ));
    }

    let token_len = header[5] as usize;
    let mut token = vec![0u8; token_len];
    stream.read_exact(&mut token).await?;
    if expected_token != Some(token.as_slice()) {
        let _ = write_response(stream, RELAY_STATUS_AUTH_FAILED, None).await;
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "relay token mismatch",
        ));
    }

    read_socket_addr(stream).await
}

async fn read_socket_addr(stream: &mut TcpStream) -> io::Result<SocketAddr> {
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;
    match atyp[0] {
        1 => {
            let mut body = [0u8; 6];
            stream.read_exact(&mut body).await?;
            let ip = IpAddr::V4(Ipv4Addr::new(body[0], body[1], body[2], body[3]));
            let port = u16::from_be_bytes([body[4], body[5]]);
            Ok(SocketAddr::new(ip, port))
        }
        4 => {
            let mut body = [0u8; 18];
            stream.read_exact(&mut body).await?;
            let ip = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&body[..16]).map_err(
                |_| io::Error::new(io::ErrorKind::InvalidData, "invalid IPv6 address"),
            )?));
            let port = u16::from_be_bytes([body[16], body[17]]);
            Ok(SocketAddr::new(ip, port))
        }
        atyp => {
            let _ = write_response(stream, RELAY_STATUS_INVALID_REQUEST, None).await;
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported relay address type {atyp}"),
            ))
        }
    }
}

async fn write_response(
    stream: &mut TcpStream,
    status: u8,
    bound_addr: Option<SocketAddr>,
) -> io::Result<()> {
    let bound_addr =
        bound_addr.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    let mut reply = vec![0u8; 7];
    reply[..4].copy_from_slice(RELAY_MAGIC);
    reply[4] = RELAY_VERSION;
    reply[5] = status;
    match bound_addr {
        SocketAddr::V4(addr) => {
            reply[6] = 1u8;
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
        }
        SocketAddr::V6(addr) => {
            reply[6] = 4u8;
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    stream.write_all(&reply).await
}
