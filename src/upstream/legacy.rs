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
        // Accept only a datagram matching our ID and our question (RFC 5452);
        // keep waiting on anything else so the genuine reply can still arrive.
        if n >= 12
            && buf[..2] == query[..2]
            && crate::wire::validate_response(query, &buf[..n]).is_ok()
        {
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
    // TCP has no stray-datagram problem, but the ID must still round-trip.
    if response.len() < 12 || response[..2] != query[..2] {
        return Err("tcp response ID mismatch".into());
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    fn query_bytes(id: u16) -> Vec<u8> {
        let mut message = Vec::from(id.to_be_bytes());
        message.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        message.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
        message
    }

    async fn tcp_responder(respond_with_id: u16) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut lenbuf = [0u8; 2];
            stream.read_exact(&mut lenbuf).await.unwrap();
            let mut received = vec![0u8; u16::from_be_bytes(lenbuf) as usize];
            stream.read_exact(&mut received).await.unwrap();
            received[..2].copy_from_slice(&respond_with_id.to_be_bytes());
            received[2] |= 0x80;
            let len = u16::try_from(received.len()).unwrap();
            stream.write_all(&len.to_be_bytes()).await.unwrap();
            stream.write_all(&received).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn tcp_accepts_matching_id() {
        let addr = tcp_responder(0x1234).await;
        let response = query_tcp(addr, &query_bytes(0x1234)).await.unwrap();
        assert_eq!(&response[..2], &0x1234u16.to_be_bytes());
    }

    #[tokio::test]
    async fn tcp_rejects_id_mismatch() {
        let addr = tcp_responder(0xbeef).await;
        let err = query_tcp(addr, &query_bytes(0x1234)).await.unwrap_err();
        assert!(err.contains("ID mismatch"));
    }
}
