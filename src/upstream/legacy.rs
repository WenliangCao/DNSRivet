//! Plain DNS over UDP/TCP port 53 (`legacy` upstream type).
//!
//! UDP first; TCP only to chase a TC-truncated response, and only for TCP
//! clients (UDP clients get the TC bit passed through and retry themselves).

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

pub async fn query(addr: SocketAddr, query: &[u8], tcp_retry: bool) -> Result<Vec<u8>, String> {
    let response = query_udp(addr, query).await?;
    let truncated = response.len() >= 12 && response[2] & 0x02 != 0;
    if truncated
        && tcp_retry
        && let Ok(full) = query_tcp(addr, query).await
    {
        return Ok(full);
    }
    Ok(response)
}

async fn query_udp(addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>, String> {
    let bind = SocketAddr::new(
        if addr.is_ipv4() {
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
        },
        0,
    );
    let sock = UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
    sock.connect(addr).await.map_err(|e| e.to_string())?;
    sock.send(query).await.map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 4096];
    loop {
        let n = sock.recv(&mut buf).await.map_err(|e| e.to_string())?;
        // Drop stray datagrams whose ID doesn't match ours.
        if n >= 12 && buf[..2] == query[..2] {
            buf.truncate(n);
            return Ok(buf);
        }
    }
}

async fn query_tcp(addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>, String> {
    let len = u16::try_from(query.len()).map_err(|_| "query too large".to_string())?;
    let mut stream = TcpStream::connect(addr).await.map_err(|e| e.to_string())?;
    let mut framed = Vec::with_capacity(2 + query.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(query);
    stream.write_all(&framed).await.map_err(|e| e.to_string())?;

    let mut lenbuf = [0u8; 2];
    stream
        .read_exact(&mut lenbuf)
        .await
        .map_err(|e| e.to_string())?;
    let mut response = vec![0u8; u16::from_be_bytes(lenbuf) as usize];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|e| e.to_string())?;
    Ok(response)
}
