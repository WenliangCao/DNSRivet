//! Plain DNS over UDP/TCP port 53 (`legacy` upstream type).
//!
//! UDP first; TCP only to chase a TC-truncated response, and only for TCP
//! clients (UDP clients get the TC bit passed through and retry themselves).

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

pub async fn query(addr: SocketAddr, query: &[u8], tcp_retry: bool) -> Result<Vec<u8>, String> {
    let response = query_udp(addr, query).await?;
    if is_truncated(&response) && tcp_retry {
        return query_tcp(addr, query).await;
    }
    Ok(response)
}

/// Whether a response has the TC bit set (RFC 1035 §4.1.1).
pub fn is_truncated(response: &[u8]) -> bool {
    response.len() >= 12 && response[2] & 0x02 != 0
}

pub async fn query_udp(addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>, String> {
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
    // One extra byte detects OS-level truncation without a 64 KiB allocation
    // per query. Never forward a clipped datagram with TC left clear.
    const MAX_UDP_RESPONSE: usize = 4096;
    let mut buf = vec![0u8; MAX_UDP_RESPONSE + 1];
    loop {
        let n = sock.recv(&mut buf).await.map_err(|e| e.to_string())?;
        // Accept only a datagram matching our ID and our question (RFC 5452);
        // keep waiting on anything else so the genuine reply can still arrive.
        if n >= 12
            && buf[..2] == query[..2]
            && crate::wire::validate_response(query, &buf[..n]).is_ok()
        {
            buf.truncate(n);
            if n > MAX_UDP_RESPONSE {
                crate::wire::truncate_to(&mut buf, MAX_UDP_RESPONSE);
                // A compressed question can refer into bytes truncation removes
                // or rewrites. Keep the post-mutation guarantee at this boundary.
                crate::wire::validate_response(query, &buf)
                    .map_err(|err| format!("truncated udp response rejected: {err}"))?;
            }
            return Ok(buf);
        }
    }
}

pub async fn query_tcp(addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>, String> {
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
    // TCP has no stray-datagram problem, but the ID must still round-trip
    // and, as over UDP, the response must answer our question (RFC 5452).
    if response.len() < 12 || response[..2] != query[..2] {
        return Err("tcp response ID mismatch".into());
    }
    crate::wire::validate_response(query, &response)
        .map_err(|e| format!("tcp response rejected: {e}"))?;
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

    fn query_with_edns() -> Vec<u8> {
        let mut message = query_bytes(0x1234);
        message[11] = 1;
        message.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 6, 0, 12, 0, 2, 0, 0]);
        message
    }

    #[tokio::test]
    async fn udp_preserves_query_and_truncated_response_bytes() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let request = query_with_edns();
        let mut response = request.clone();
        response[2] |= 0x82; // QR and TC: UDP clients receive this unchanged.
        response[3] |= 0x80;
        let expected_request = request.clone();
        let sent_response = response.clone();
        let responder = tokio::spawn(async move {
            let mut received = [0u8; 512];
            let (n, peer) = socket.recv_from(&mut received).await.unwrap();
            assert_eq!(&received[..n], expected_request);
            socket.send_to(&sent_response, peer).await.unwrap();
        });

        let received = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            query(addr, &request, false),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received, response);
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_retry_preserves_query_and_response_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let socket = UdpSocket::bind(addr).await.unwrap();
        let request = query_with_edns();
        let mut response = request.clone();
        response[2] |= 0x80;
        response[3] |= 0x80;
        let expected_request = request.clone();
        let sent_response = response.clone();
        let responder = tokio::spawn(async move {
            let mut received = [0u8; 512];
            let (n, peer) = socket.recv_from(&mut received).await.unwrap();
            assert_eq!(&received[..n], expected_request);
            let mut truncated = sent_response.clone();
            truncated[2] |= 0x02;
            socket.send_to(&truncated, peer).await.unwrap();

            let (mut stream, _) = listener.accept().await.unwrap();
            let mut len = [0; 2];
            stream.read_exact(&mut len).await.unwrap();
            assert_eq!(u16::from_be_bytes(len) as usize, expected_request.len());
            stream.read_exact(&mut received[..n]).await.unwrap();
            assert_eq!(&received[..n], expected_request);
            stream
                .write_all(&(sent_response.len() as u16).to_be_bytes())
                .await
                .unwrap();
            stream.write_all(&sent_response).await.unwrap();
        });

        let received = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            query(addr, &request, true),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(received, response);
        responder.await.unwrap();
    }

    fn response_of_size(request: &[u8], size: usize) -> Vec<u8> {
        let mut response = request.to_vec();
        response[2] |= 0x80;
        response[6..8].copy_from_slice(&1u16.to_be_bytes());
        // A NULL RR can carry arbitrary octets, including an exact 4096-byte packet.
        response.extend_from_slice(&[0xc0, 0x0c, 0, 10, 0, 1, 0, 0, 0, 60]);
        let data_len = u16::try_from(size - response.len() - 2).unwrap();
        response.extend_from_slice(&data_len.to_be_bytes());
        response.resize(size, 0);
        response
    }

    #[tokio::test]
    async fn oversized_udp_responses_are_marked_truncated_and_tcp_gets_the_full_answer() {
        for size in [4096, 4097, 6344] {
            for tcp_retry in [false, true] {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let socket = UdpSocket::bind(addr).await.unwrap();
                let request = query_bytes(0x1234);
                let full = response_of_size(&request, size);
                let sent = full.clone();
                let responder = tokio::spawn(async move {
                    let mut received = [0; 512];
                    let (_, peer) = socket.recv_from(&mut received).await.unwrap();
                    socket.send_to(&sent, peer).await.unwrap();
                    if size > 4096 && tcp_retry {
                        let (mut stream, _) = listener.accept().await.unwrap();
                        let len = stream.read_u16().await.unwrap();
                        stream
                            .read_exact(&mut received[..usize::from(len)])
                            .await
                            .unwrap();
                        stream.write_u16(sent.len() as u16).await.unwrap();
                        stream.write_all(&sent).await.unwrap();
                    }
                });
                let response = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    query(addr, &request, tcp_retry),
                )
                .await
                .unwrap()
                .unwrap();
                if size <= 4096 || tcp_retry {
                    assert_eq!(response, full);
                } else {
                    assert!(is_truncated(&response));
                    assert_eq!(response.len(), request.len());
                    assert_eq!(&response[6..12], &[0; 6]);
                    crate::wire::validate_response(&request, &response).unwrap();
                }
                responder.await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn clipping_rejects_a_question_pointing_into_removed_bytes() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let request = query_bytes(0x1234);
        let sent = request.clone();
        let responder = tokio::spawn(async move {
            let mut received = [0; 512];
            let (_, peer) = socket.recv_from(&mut received).await.unwrap();
            let mut response = sent[..12].to_vec();
            response[2] |= 0x80;
            response[7] = 1;
            // The question is valid before clipping but references NULL RDATA.
            response.extend_from_slice(&[0xc0, 29, 0, 1, 0, 1]);
            response.extend_from_slice(&[0, 0, 10, 0, 1, 0, 0, 0, 60, 0x0f, 0xe4, 1, b'a', 0]);
            response.resize(4097, 0);
            crate::wire::validate_response(&sent, &response).unwrap();
            socket.send_to(&response, peer).await.unwrap();
        });
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(1), query_udp(addr, &request))
                .await
                .unwrap();
        assert!(
            result
                .unwrap_err()
                .contains("truncated udp response rejected")
        );
        responder.await.unwrap();
    }

    #[tokio::test]
    async fn failed_tcp_retry_is_an_upstream_failure_not_a_truncated_tcp_answer() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut received = [0; 512];
            let (n, peer) = socket.recv_from(&mut received).await.unwrap();
            received[2] |= 0x82;
            socket.send_to(&received[..n], peer).await.unwrap();
        });
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            query(addr, &query_bytes(1), true),
        )
        .await
        .unwrap();
        assert!(result.is_err());
        responder.await.unwrap();
    }

    async fn tcp_responder(respond_with_id: u16, wrong_question: bool) -> std::net::SocketAddr {
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
            if wrong_question {
                received[13] = b'z';
            }
            let len = u16::try_from(received.len()).unwrap();
            stream.write_all(&len.to_be_bytes()).await.unwrap();
            stream.write_all(&received).await.unwrap();
        });
        addr
    }

    #[tokio::test]
    async fn tcp_accepts_matching_id() {
        let addr = tcp_responder(0x1234, false).await;
        let response = query_tcp(addr, &query_bytes(0x1234)).await.unwrap();
        assert_eq!(&response[..2], &0x1234u16.to_be_bytes());
    }

    #[tokio::test]
    async fn tcp_rejects_id_mismatch() {
        let addr = tcp_responder(0xbeef, false).await;
        let err = query_tcp(addr, &query_bytes(0x1234)).await.unwrap_err();
        assert!(err.contains("ID mismatch"));
    }

    #[tokio::test]
    async fn tcp_rejects_answer_to_a_different_question() {
        let addr = tcp_responder(0x1234, true).await;
        let err = query_tcp(addr, &query_bytes(0x1234)).await.unwrap_err();
        assert!(err.contains("rejected"), "{err}");
    }
}
