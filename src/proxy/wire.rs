//! Small DNS wire helpers used on the cache hot path.
//!
//! Hickory remains the protocol implementation for upstream transports. These
//! helpers deliberately parse only the fields needed for cache safety, TTL
//! aging, and UDP response truncation.

const HEADER_LEN: usize = 12;
const TYPE_CNAME: u16 = 5;
const TYPE_SOA: u16 = 6;
const TYPE_OPT: u16 = 41;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct QueryMeta {
    pub qname: Vec<u8>,
    pub qtype: u16,
    pub qclass: u16,
    pub do_bit: bool,
    /// AD/CD request bits. They can change DNSSEC-aware upstream responses.
    pub dnssec_header_bits: u8,
    pub udp_size: usize,
}

/// Return cache metadata for a conventional recursive, single-question query.
/// Queries with EDNS options, TSIG, unsupported EDNS versions, or unusual
/// header semantics bypass the cache rather than risk reusing the wrong reply.
pub fn parse_query_meta(message: &[u8]) -> Option<QueryMeta> {
    if message.len() < HEADER_LEN {
        return None;
    }
    let flags = read_u16(message, 2)?;
    if flags & 0x8000 != 0 // response
        || flags & 0x7800 != 0 // non-QUERY opcode
        || flags & 0x0100 == 0 // recursion not desired
        || read_u16(message, 4)? != 1
    {
        return None;
    }

    let (qname, mut offset) = read_name(message, HEADER_LEN)?;
    let qtype = read_u16(message, offset)?;
    let qclass = read_u16(message, offset + 2)?;
    offset += 4;

    let answer_count = read_u16(message, 6)? as usize;
    let authority_count = read_u16(message, 8)? as usize;
    for _ in 0..answer_count + authority_count {
        offset = parse_rr(message, offset)?.end;
    }

    let mut udp_size = 512;
    let mut do_bit = false;
    let mut saw_opt = false;
    for _ in 0..read_u16(message, 10)? {
        let rr = parse_rr(message, offset)?;
        offset = rr.end;
        if rr.kind != TYPE_OPT || saw_opt {
            return None;
        }
        // EDNS options such as ECS and COOKIE can affect the response and are
        // intentionally not represented in the cache key.
        if rr.rdlen != 0 || message.get(rr.ttl_offset + 1).copied()? != 0 {
            return None;
        }
        saw_opt = true;
        udp_size = usize::from(rr.class).clamp(512, 4096);
        do_bit = read_u32(message, rr.ttl_offset)? & 0x8000 != 0;
    }
    if offset != message.len() {
        return None;
    }

    Some(QueryMeta {
        qname,
        qtype,
        qclass,
        do_bit,
        dnssec_header_bits: message[3] & 0x30,
        udp_size,
    })
}

/// Extract the client's advertised UDP payload size even when the query must
/// bypass the cache (for example because it carries EDNS COOKIE or padding).
pub fn udp_payload_size(message: &[u8]) -> usize {
    let Some(mut offset) = questions_end(message) else {
        return 512;
    };
    let Some(answer_count) = read_u16(message, 6) else {
        return 512;
    };
    let Some(authority_count) = read_u16(message, 8) else {
        return 512;
    };
    for _ in 0..usize::from(answer_count) + usize::from(authority_count) {
        let Some(rr) = parse_rr(message, offset) else {
            return 512;
        };
        offset = rr.end;
    }
    let Some(additional_count) = read_u16(message, 10) else {
        return 512;
    };
    for _ in 0..additional_count {
        let Some(rr) = parse_rr(message, offset) else {
            return 512;
        };
        if rr.kind == TYPE_OPT {
            return usize::from(rr.class).clamp(512, 4096);
        }
        offset = rr.end;
    }
    512
}

/// Decrease every resource-record TTL by the number of whole seconds elapsed.
/// OPT's TTL-shaped field contains EDNS flags and must never be modified.
pub fn adjust_ttls(message: &mut [u8], elapsed_secs: u64) -> bool {
    if message.len() < HEADER_LEN {
        return false;
    }
    let Some(mut offset) = questions_end(message) else {
        return false;
    };
    let count = match total_rr_count(message) {
        Some(count) => count,
        None => return false,
    };
    let elapsed = elapsed_secs.min(u64::from(u32::MAX)) as u32;

    for _ in 0..count {
        let Some(rr) = parse_rr(message, offset) else {
            return false;
        };
        if rr.kind != TYPE_OPT {
            let Some(ttl) = read_u32(message, rr.ttl_offset) else {
                return false;
            };
            message[rr.ttl_offset..rr.ttl_offset + 4]
                .copy_from_slice(&ttl.saturating_sub(elapsed).to_be_bytes());
        }
        offset = rr.end;
    }
    offset == message.len()
}

/// Determine how long a successful response is safe to cache.
///
/// Positive answers use the minimum answer/authority TTL, capped at one day.
/// NXDOMAIN/NODATA uses RFC 2308's min(SOA TTL, SOA.MINIMUM), clamped to the
/// project's 60–600 second negative-cache window.
pub fn cache_ttl(message: &[u8], query_type: u16) -> Option<u32> {
    if message.len() < HEADER_LEN || message[2] & 0x80 == 0 || message[2] & 0x02 != 0 {
        return None;
    }
    let rcode = message[3] & 0x0f;
    if !matches!(rcode, 0 | 3) {
        return None;
    }

    let answers = read_u16(message, 6)? as usize;
    let authorities = read_u16(message, 8)? as usize;
    let additionals = read_u16(message, 10)? as usize;
    let mut offset = questions_end(message)?;
    let mut positive_min: Option<u32> = None;
    let mut soa_min: Option<u32> = None;
    let mut has_requested_answer = false;
    let mut has_cname = false;

    for index in 0..answers + authorities + additionals {
        let rr = parse_rr(message, offset)?;
        let in_answer = index < answers;
        let in_authority = index >= answers && index < answers + authorities;

        if in_answer || in_authority {
            positive_min = Some(positive_min.map_or(rr.ttl, |ttl| ttl.min(rr.ttl)));
        }
        if in_answer {
            has_requested_answer |= rr.kind == query_type;
            has_cname |= rr.kind == TYPE_CNAME;
        }
        if in_authority && rr.kind == TYPE_SOA {
            let minimum = soa_minimum(message, &rr)?;
            let negative = rr.ttl.min(minimum);
            soa_min = Some(soa_min.map_or(negative, |ttl| ttl.min(negative)));
        }
        offset = rr.end;
    }
    if offset != message.len() {
        return None;
    }

    let negative = rcode == 3 || (rcode == 0 && soa_min.is_some() && !has_requested_answer);
    if negative {
        let mut ttl = soa_min?;
        if has_cname {
            ttl = ttl.min(positive_min?);
        }
        return Some(ttl.clamp(60, 600));
    }

    let ttl = positive_min?;
    (ttl > 0).then_some(ttl.min(86_400))
}

/// Truncate an oversized UDP response to its header and question section and
/// set TC so a conforming client retries over TCP.
pub fn truncate_to(message: &mut Vec<u8>, limit: usize) {
    if message.len() <= limit || message.len() < HEADER_LEN {
        return;
    }
    message[2] |= 0x02;
    message[6..12].fill(0);

    match questions_end(message) {
        Some(end) if end <= limit => message.truncate(end),
        _ => {
            message[4..6].fill(0);
            message.truncate(HEADER_LEN);
        }
    }
}

#[derive(Clone, Copy)]
struct ResourceRecord {
    kind: u16,
    class: u16,
    ttl: u32,
    ttl_offset: usize,
    rdata_offset: usize,
    rdlen: usize,
    end: usize,
}

fn parse_rr(message: &[u8], offset: usize) -> Option<ResourceRecord> {
    let offset = skip_name(message, offset)?;
    let kind = read_u16(message, offset)?;
    let class = read_u16(message, offset + 2)?;
    let ttl_offset = offset.checked_add(4)?;
    let ttl = read_u32(message, ttl_offset)?;
    let rdlen = read_u16(message, offset + 8)? as usize;
    let rdata_offset = offset.checked_add(10)?;
    let end = rdata_offset.checked_add(rdlen)?;
    (end <= message.len()).then_some(ResourceRecord {
        kind,
        class,
        ttl,
        ttl_offset,
        rdata_offset,
        rdlen,
        end,
    })
}

fn questions_end(message: &[u8]) -> Option<usize> {
    let mut offset = HEADER_LEN;
    for _ in 0..read_u16(message, 4)? {
        offset = skip_name(message, offset)?.checked_add(4)?;
        if offset > message.len() {
            return None;
        }
    }
    Some(offset)
}

fn total_rr_count(message: &[u8]) -> Option<usize> {
    Some(
        usize::from(read_u16(message, 6)?)
            + usize::from(read_u16(message, 8)?)
            + usize::from(read_u16(message, 10)?),
    )
}

fn soa_minimum(message: &[u8], rr: &ResourceRecord) -> Option<u32> {
    let rdata_end = rr.rdata_offset.checked_add(rr.rdlen)?;
    let mut offset = skip_name(message, rr.rdata_offset)?;
    if offset > rdata_end {
        return None;
    }
    offset = skip_name(message, offset)?;
    // SERIAL, REFRESH, RETRY, EXPIRE, MINIMUM.
    if offset.checked_add(20)? > rdata_end {
        return None;
    }
    read_u32(message, offset + 16)
}

fn skip_name(message: &[u8], offset: usize) -> Option<usize> {
    read_name(message, offset).map(|(_, end)| end)
}

/// Decode a possibly-compressed name into canonical lowercase wire form.
fn read_name(message: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    let mut name = Vec::new();
    let mut cursor = start;
    let mut end = None;
    let mut jumps = 0usize;
    loop {
        let len = *message.get(cursor)?;
        if len & 0xc0 == 0xc0 {
            let next = *message.get(cursor + 1)?;
            let pointer = (usize::from(len & 0x3f) << 8) | usize::from(next);
            if pointer >= message.len() || jumps >= 128 {
                return None;
            }
            end.get_or_insert(cursor + 2);
            cursor = pointer;
            jumps += 1;
            continue;
        }
        if len & 0xc0 != 0 || len > 63 {
            return None;
        }
        cursor += 1;
        if len == 0 {
            name.push(0);
            return (name.len() <= 255).then_some((name, end.unwrap_or(cursor)));
        }
        let label_end = cursor.checked_add(usize::from(len))?;
        let label = message.get(cursor..label_end)?;
        name.push(len);
        name.extend(label.iter().map(u8::to_ascii_lowercase));
        if name.len() >= 255 {
            return None;
        }
        cursor = label_end;
    }
}

fn read_u16(message: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *message.get(offset)?,
        *message.get(offset + 1)?,
    ]))
}

fn read_u32(message: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *message.get(offset)?,
        *message.get(offset + 1)?,
        *message.get(offset + 2)?,
        *message.get(offset + 3)?,
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn question(id: u16, with_opt: bool) -> Vec<u8> {
        let mut message = Vec::from(id.to_be_bytes());
        message.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, u8::from(with_opt)]);
        message.extend_from_slice(&[7, b'E', b'x', b'A', b'm', b'P', b'l', b'E']);
        message.extend_from_slice(&[3, b'C', b'O', b'M', 0, 0, 1, 0, 1]);
        if with_opt {
            message.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0]);
        }
        message
    }

    fn positive_response(id: u16, ttl: u32, with_opt: bool) -> Vec<u8> {
        let mut message = question(id, false);
        message[2] = 0x81;
        message[3] = 0x80;
        message[6..8].copy_from_slice(&1u16.to_be_bytes());
        message[10..12].copy_from_slice(&u16::from(with_opt).to_be_bytes());
        message.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        message.extend_from_slice(&ttl.to_be_bytes());
        message.extend_from_slice(&[0, 4, 1, 2, 3, 4]);
        if with_opt {
            message.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0]);
        }
        message
    }

    fn negative_response(soa_ttl: u32, minimum: u32) -> Vec<u8> {
        let mut message = question(1, false);
        message[2] = 0x81;
        message[3] = 0x83;
        message[8..10].copy_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&[0xc0, 0x0c, 0, TYPE_SOA as u8, 0, 1]);
        message.extend_from_slice(&soa_ttl.to_be_bytes());
        message.extend_from_slice(&24u16.to_be_bytes());
        message.extend_from_slice(&[0xc0, 0x0c, 0xc0, 0x0c]);
        message.extend_from_slice(&1u32.to_be_bytes());
        message.extend_from_slice(&2u32.to_be_bytes());
        message.extend_from_slice(&3u32.to_be_bytes());
        message.extend_from_slice(&4u32.to_be_bytes());
        message.extend_from_slice(&minimum.to_be_bytes());
        message
    }

    #[test]
    fn parses_query_key_edns_size_and_do() {
        let meta = parse_query_meta(&question(0x1234, true)).unwrap();
        assert_eq!(meta.qname, b"\x07example\x03com\0");
        assert_eq!(meta.qtype, 1);
        assert_eq!(meta.qclass, 1);
        assert_eq!(meta.udp_size, 4096);
        assert!(meta.do_bit);
    }

    #[test]
    fn bypasses_non_recursive_and_edns_option_queries() {
        let mut no_rd = question(1, false);
        no_rd[2] = 0;
        assert!(parse_query_meta(&no_rd).is_none());

        let mut option = question(1, true);
        *option.last_mut().unwrap() = 1;
        option.push(0);
        assert!(parse_query_meta(&option).is_none());
        assert_eq!(udp_payload_size(&option), 4096);
    }

    #[test]
    fn ages_record_ttls_but_not_opt_flags() {
        let mut response = positive_response(1, 120, true);
        assert!(adjust_ttls(&mut response, 20));
        let answer_ttl = questions_end(&response).unwrap() + 6;
        assert_eq!(read_u32(&response, answer_ttl), Some(100));
        let opt = parse_rr(&response, questions_end(&response).unwrap() + 16).unwrap();
        assert_eq!(read_u32(&response, opt.ttl_offset), Some(0x8000));
    }

    #[test]
    fn chooses_positive_ttl_and_truncates_at_question() {
        let mut response = positive_response(1, 120, false);
        assert_eq!(cache_ttl(&response, 1), Some(120));
        let question_end = questions_end(&response).unwrap();
        truncate_to(&mut response, question_end);
        assert_eq!(response.len(), question_end);
        assert_ne!(response[2] & 0x02, 0);
        assert_eq!(&response[6..12], &[0; 6]);
    }

    #[test]
    fn clamps_rfc2308_negative_ttl() {
        assert_eq!(cache_ttl(&negative_response(30, 15), 1), Some(60));
        assert_eq!(cache_ttl(&negative_response(1200, 900), 1), Some(600));
    }
}
