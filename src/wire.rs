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
pub struct QueryKey {
    pub qname: Vec<u8>,
    pub qtype: u16,
    pub qclass: u16,
    pub do_bit: bool,
    /// OPT negotiation is per client; non-EDNS clients must not receive OPT.
    pub edns: bool,
    /// AD/CD request bits. They can change DNSSEC-aware upstream responses.
    pub dnssec_header_bits: u8,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct QueryMeta {
    pub key: QueryKey,
    /// Transport limit; it does not affect which cached answer is selected.
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
        key: QueryKey {
            qname,
            qtype,
            qclass,
            do_bit,
            edns: saw_opt,
            dnssec_header_bits: message[3] & 0x30,
        },
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
            message[rr.ttl_offset..rr.ttl_offset + 4]
                .copy_from_slice(&rr.ttl.saturating_sub(elapsed).to_be_bytes());
        }
        offset = rr.end;
    }
    offset == message.len()
}

/// Determine how long a successful response is safe to cache.
///
/// Positive answers use the minimum answer/authority TTL, capped at one day.
/// NXDOMAIN/NODATA uses RFC 2308's min(SOA TTL, SOA.MINIMUM), capped at
/// 600 seconds. A zero TTL is never cached, and short TTLs are not extended.
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
        return (ttl > 0).then_some(ttl.min(600));
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

/// Why an upstream response was rejected as an answer to a given query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationError {
    TooShort,
    NotAResponse,
    OpcodeMismatch,
    QdCountMismatch,
    QuestionMismatch,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            ValidationError::TooShort => "response shorter than a DNS header",
            ValidationError::NotAResponse => "QR flag not set",
            ValidationError::OpcodeMismatch => "opcode differs from the query",
            ValidationError::QdCountMismatch => "QDCOUNT differs from the query",
            ValidationError::QuestionMismatch => "question differs from the query",
        })
    }
}

/// RFC 5452 §4.2: accept a response only when it matches the outstanding
/// query — QR set, same opcode, same QDCOUNT, and (for single-question
/// queries) the same canonicalized QNAME/QTYPE/QCLASS. DNS IDs are
/// deliberately not compared here: encrypted transports pin them to 0 on the
/// wire, so ID equality is enforced by the legacy transport alone.
///
/// A query with QDCOUNT = 0 (for example an RFC 7873 cookie probe) degrades
/// to count equality; there is no question to compare.
pub fn validate_response(query: &[u8], response: &[u8]) -> Result<(), ValidationError> {
    if query.len() < HEADER_LEN || response.len() < HEADER_LEN {
        return Err(ValidationError::TooShort);
    }
    if response[2] & 0x80 == 0 {
        return Err(ValidationError::NotAResponse);
    }
    if (query[2] ^ response[2]) & 0x78 != 0 {
        return Err(ValidationError::OpcodeMismatch);
    }
    let qd_query = read_u16(query, 4).ok_or(ValidationError::TooShort)?;
    let qd_response = read_u16(response, 4).ok_or(ValidationError::TooShort)?;
    if qd_response != qd_query {
        return Err(ValidationError::QdCountMismatch);
    }
    if qd_query != 1 {
        return Ok(());
    }
    match questions_match(query, response) {
        Some(true) => Ok(()),
        _ => Err(ValidationError::QuestionMismatch),
    }
}

/// Compare expanded QNAME/QTYPE/QCLASS without allocating canonical names.
fn questions_match(query: &[u8], response: &[u8]) -> Option<bool> {
    // walk_name bounds the expanded wire name, including the root, to 255 bytes.
    // Keep the query on the stack and compare response labels as they are walked.
    let mut name = [0u8; 255];
    let mut name_len = 0;
    let query_end = walk_name(query, HEADER_LEN, |label| {
        name[name_len..name_len + label.len()].copy_from_slice(label);
        name_len += label.len();
    })?;
    let sent_fields = query.get(query_end..query_end + 4)?;

    let mut echoed_len = 0;
    let mut matches = true;
    let response_end = walk_name(response, HEADER_LEN, |label| {
        matches &= name[..name_len]
            .get(echoed_len..echoed_len + label.len())
            .is_some_and(|sent| sent.eq_ignore_ascii_case(label));
        echoed_len += label.len();
    })?;
    let echoed_fields = response.get(response_end..response_end + 4)?;
    Some(matches && name_len == echoed_len && sent_fields == echoed_fields)
}

/// True for a client QUERY carrying more than one question. RFC 9619 requires
/// such a message to be answered with FORMERR and never forwarded.
pub fn is_multi_question_query(message: &[u8]) -> bool {
    message.len() >= HEADER_LEN
        && message[2] & 0x80 == 0
        && message[2] & 0x78 == 0
        && read_u16(message, 4).is_some_and(|count| count > 1)
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
    walk_name(message, offset, |_| {})
}

/// Decode a possibly-compressed name into canonical lowercase wire form.
fn read_name(message: &[u8], start: usize) -> Option<(Vec<u8>, usize)> {
    let mut name = [0u8; 255];
    let mut name_len = 0;
    let end = walk_name(message, start, |label| {
        name[name_len..name_len + label.len()].copy_from_slice(label);
        name_len += label.len();
    })?;
    name[..name_len].make_ascii_lowercase();
    Some((name[..name_len].to_vec(), end))
}

/// Validate the full expanded name, visiting each wire label (length included).
fn walk_name(message: &[u8], start: usize, mut visit: impl FnMut(&[u8])) -> Option<usize> {
    let mut cursor = start;
    let mut end = None;
    let mut jumps = 0usize;
    let mut name_len = 0usize;
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
            visit(&message[cursor - 1..cursor]);
            return Some(end.unwrap_or(cursor));
        }
        let label_end = cursor.checked_add(usize::from(len))?;
        let label = message.get(cursor - 1..label_end)?;
        name_len += 1 + usize::from(len);
        // The expanded name must leave one byte for its terminating root label.
        if name_len >= 255 {
            return None;
        }
        visit(label);
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
        assert_eq!(meta.key.qname, b"\x07example\x03com\0");
        assert_eq!(meta.key.qtype, 1);
        assert_eq!(meta.key.qclass, 1);
        assert_eq!(meta.udp_size, 4096);
        assert!(meta.key.do_bit);
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
    fn respects_negative_ttl_expiry_and_only_caps_the_upper_bound() {
        for (soa_ttl, minimum, expected) in [
            (0, 60, None),
            (60, 0, None),
            (1, 60, Some(1)),
            (30, 15, Some(15)),
            (1200, 900, Some(600)),
        ] {
            for rcode in [0, 3] {
                let mut response = negative_response(soa_ttl, minimum);
                response[3] = 0x80 | rcode;
                assert_eq!(cache_ttl(&response, 1), expected);
            }
        }
    }

    #[test]
    fn accepts_matching_response_case_insensitively() {
        // The test fixtures use mixed-case names; canonicalization must make
        // the comparison case-insensitive.
        let query = question(7, false);
        let mut response = positive_response(7, 60, false);
        response[HEADER_LEN..25].make_ascii_lowercase();
        assert_eq!(validate_response(&query, &response), Ok(()));
    }

    #[test]
    fn rejects_mismatched_responses_with_specific_errors() {
        let query = question(7, false);
        let good = positive_response(7, 60, false);

        let mut not_a_response = good.clone();
        not_a_response[2] &= !0x80;
        assert_eq!(
            validate_response(&query, &not_a_response),
            Err(ValidationError::NotAResponse)
        );

        let mut wrong_opcode = good.clone();
        wrong_opcode[2] |= 0x08;
        assert_eq!(
            validate_response(&query, &wrong_opcode),
            Err(ValidationError::OpcodeMismatch)
        );

        let mut wrong_name = good.clone();
        wrong_name[13] = b'z'; // first label byte of the echoed question
        assert_eq!(
            validate_response(&query, &wrong_name),
            Err(ValidationError::QuestionMismatch)
        );

        let mut wrong_type = good.clone();
        wrong_type[26] = 28; // A -> AAAA in the echoed question
        assert_eq!(
            validate_response(&query, &wrong_type),
            Err(ValidationError::QuestionMismatch)
        );

        let mut wrong_class = good.clone();
        wrong_class[28] = 3; // IN -> CH in the echoed question
        assert_eq!(
            validate_response(&query, &wrong_class),
            Err(ValidationError::QuestionMismatch)
        );

        // Minimal header-only SERVFAIL with QDCOUNT=0: count mismatch.
        let mut minimal = vec![0u8; 12];
        minimal[..2].copy_from_slice(&7u16.to_be_bytes());
        minimal[2] = 0x80;
        minimal[3] = 0x82;
        assert_eq!(
            validate_response(&query, &minimal),
            Err(ValidationError::QdCountMismatch)
        );
    }

    #[test]
    fn question_less_queries_degrade_to_count_equality() {
        let mut probe = vec![0u8; 12];
        probe[..2].copy_from_slice(&9u16.to_be_bytes());
        probe[2] = 0x00;
        let mut reply = probe.clone();
        reply[2] = 0x80;
        assert_eq!(validate_response(&probe, &reply), Ok(()));

        let full = positive_response(9, 60, false);
        assert_eq!(
            validate_response(&probe, &full),
            Err(ValidationError::QdCountMismatch)
        );
    }

    #[test]
    fn detects_multi_question_queries_only() {
        let mut multi = question(1, false);
        multi[4..6].copy_from_slice(&2u16.to_be_bytes());
        assert!(is_multi_question_query(&multi));
        assert!(!is_multi_question_query(&question(1, false)));

        let mut response = multi.clone();
        response[2] |= 0x80;
        assert!(!is_multi_question_query(&response));

        let mut status = multi;
        status[2] |= 0x10; // non-QUERY opcode
        assert!(!is_multi_question_query(&status));
    }

    fn named_question(name: &[u8]) -> Vec<u8> {
        let mut message = vec![0, 1, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        message.extend_from_slice(name);
        message.extend_from_slice(&[0, 1, 0, 1]);
        message
    }

    fn compressed_question(name: &[u8], prefix_len: usize) -> Vec<u8> {
        let mut message = named_question(&name[..prefix_len]);
        message.truncate(HEADER_LEN + prefix_len);
        // Point beyond QTYPE/QCLASS to a suffix stored later in the message.
        // walk_name has always permitted both forward and backward pointers.
        let suffix = message.len() + 6;
        let pointer = 0xc000 | u16::try_from(suffix).unwrap();
        message.extend_from_slice(&pointer.to_be_bytes());
        message.extend_from_slice(&[0, 1, 0, 1]);
        message.extend_from_slice(&name[prefix_len..]);
        message
    }

    #[test]
    fn validates_questions_across_compression_encodings() {
        for name in [
            b"\0".as_slice(),
            b"\x07ExAmPlE\x03COM\0",
            b"\x03www\x07ExAmPlE\x03COM\0",
            b"\x03A\xffZ\0", // Only ASCII octets are folded.
        ] {
            let encodings = [
                named_question(name),
                compressed_question(name, 0),
                compressed_question(name, usize::from(name[0]) + usize::from(name[0] != 0)),
            ];
            for query in &encodings {
                for encoded in &encodings {
                    let mut response = encoded.clone();
                    response[2] |= 0x80;
                    // Fold only label payloads, not compression pointer bytes.
                    let mut offset = HEADER_LEN;
                    while response[offset] & 0xc0 == 0 {
                        let len = usize::from(response[offset]);
                        response[offset + 1..offset + 1 + len].make_ascii_lowercase();
                        if len == 0 {
                            break;
                        }
                        offset += 1 + len;
                    }
                    assert_eq!(validate_response(query, &response), Ok(()));
                }
            }
        }
    }

    #[test]
    fn distinguishes_names_lengths_label_boundaries_and_non_ascii_octets() {
        for (sent, echoed) in [
            (b"\x02ab\x01c\0".as_slice(), b"\x01a\x02bc\0".as_slice()),
            (b"\x01a\0", b"\x01a\x01b\0"),
            (b"\0", b"\x01a\0"),
            (b"\x01\xc0\0", b"\x01\xe0\0"),
        ] {
            let query = named_question(sent);
            let mut response = named_question(echoed);
            response[2] |= 0x80;
            assert_eq!(
                validate_response(&query, &response),
                Err(ValidationError::QuestionMismatch)
            );
            let query = named_question(echoed);
            let mut response = named_question(sent);
            response[2] |= 0x80;
            assert_eq!(
                validate_response(&query, &response),
                Err(ValidationError::QuestionMismatch)
            );
        }
    }

    #[test]
    fn rejects_malformed_questions_on_either_side() {
        let query = question(7, false);
        let response = positive_response(7, 60, false);
        for payload in [
            b"".as_slice(),
            b"\x03ab",
            b"\x01a",
            b"\xc0",
            b"\xc0\xff",         // Out of bounds.
            b"\xc0\x0c",         // Self pointer.
            b"\xc0\x0e\xc0\x0c", // Two-pointer cycle.
            b"\x01a\xc0\x0c",    // Cycle containing a label.
            b"\x40\0",
            b"\x80\0",
        ] {
            let mut malformed = query[..HEADER_LEN].to_vec();
            malformed.extend_from_slice(payload);
            assert_eq!(
                validate_response(&malformed, &response),
                Err(ValidationError::QuestionMismatch)
            );
            malformed[2] |= 0x80;
            assert_eq!(
                validate_response(&query, &malformed),
                Err(ValidationError::QuestionMismatch)
            );
        }
        // Every truncation within the name or QTYPE/QCLASS must be rejected.
        for end in HEADER_LEN..query.len() {
            assert_eq!(
                validate_response(&query[..end], &response),
                Err(ValidationError::QuestionMismatch)
            );
            let mut truncated = query[..end].to_vec();
            truncated[2] |= 0x80;
            assert_eq!(
                validate_response(&query, &truncated),
                Err(ValidationError::QuestionMismatch)
            );
        }
    }

    #[test]
    fn validates_expanded_question_length_boundary() {
        for (last_label_len, valid) in [(61, true), (62, false)] {
            let mut name = Vec::new();
            for length in [63, 63, 63, last_label_len] {
                name.push(length);
                name.resize(name.len() + usize::from(length), b'A');
            }
            name.push(0);
            let expected = if valid {
                Ok(())
            } else {
                Err(ValidationError::QuestionMismatch)
            };
            for query in [named_question(&name), compressed_question(&name, 0)] {
                for mut response in [named_question(&name), compressed_question(&name, 64)] {
                    response[2] |= 0x80;
                    assert_eq!(validate_response(&query, &response), expected);
                }
            }
        }
    }

    #[test]
    fn validates_question_compression_jump_boundary() {
        let query = named_question(b"\0");
        for (jumps, expected) in [(128, Ok(())), (129, Err(ValidationError::QuestionMismatch))] {
            let mut compressed = compressed_question(b"\0", 0);
            compressed.pop(); // Replace the suffix root with a forward pointer chain.
            for _ in 1..jumps {
                let pointer = 0xc000 | u16::try_from(compressed.len() + 2).unwrap();
                compressed.extend_from_slice(&pointer.to_be_bytes());
            }
            compressed.push(0);
            let mut response = query.clone();
            response[2] |= 0x80;
            assert_eq!(validate_response(&compressed, &response), expected);
            compressed[2] |= 0x80;
            assert_eq!(validate_response(&query, &compressed), expected);
        }
    }

    #[test]
    fn response_validation_keeps_non_single_question_and_rcode_policy() {
        for count in [0u16, 2] {
            let mut query = vec![0; HEADER_LEN];
            query[4..6].copy_from_slice(&count.to_be_bytes());
            let mut response = query.clone();
            response[2] |= 0x80;
            assert_eq!(validate_response(&query, &response), Ok(()));
        }
        let query = question(7, true);
        for rcode in 0..16 {
            let mut response = positive_response(0, 0, true);
            response[3] = 0x80 | rcode;
            assert_eq!(validate_response(&query, &response), Ok(()));
        }
    }

    #[test]
    fn accepts_question_pointer_to_an_earlier_root_label() {
        let query = named_question(b"\0");
        let mut response = query[..HEADER_LEN].to_vec();
        response[0] = 0; // The first ID octet doubles as the root label target.
        response[2] |= 0x80;
        response.extend_from_slice(&[0xc0, 0, 0, 1, 0, 1]);
        assert_eq!(validate_response(&query, &response), Ok(()));
    }

    /// Run with `mbx test --release benchmark_wire_validation -- --ignored --nocapture`.
    #[test]
    #[ignore = "manual wire validation hot-path benchmark"]
    fn benchmark_wire_validation() {
        use std::hint::black_box;
        use std::time::Instant;

        const ITERATIONS: usize = 1_000_000;
        const SAMPLES: usize = 7;
        let short = b"\x07ExAmPlE\x03COM\0".to_vec();
        let mut long = Vec::new();
        for length in [63, 63, 63, 61] {
            long.push(length);
            long.resize(long.len() + usize::from(length), b'A');
        }
        long.push(0);
        for (name_kind, name) in [("short", short), ("long", long)] {
            let query = named_question(&name);
            for (encoding, mut response) in [
                ("uncompressed", query.clone()),
                ("compressed", compressed_question(&name, 0)),
                (
                    "compressed-suffix",
                    compressed_question(&name, usize::from(name[0]) + 1),
                ),
            ] {
                response[2] |= 0x80;
                assert_eq!(validate_response(&query, &response), Ok(()));
                for _ in 0..100_000 {
                    black_box(validate_response(black_box(&query), black_box(&response))).unwrap();
                }
                let mut samples = [0.0; SAMPLES];
                for sample in &mut samples {
                    let start = Instant::now();
                    for _ in 0..ITERATIONS {
                        black_box(validate_response(black_box(&query), black_box(&response)))
                            .unwrap();
                    }
                    *sample = start.elapsed().as_nanos() as f64 / ITERATIONS as f64;
                }
                samples.sort_by(f64::total_cmp);
                println!(
                    "validate {name_kind} {encoding}: median={:.1} ns/op min={:.1} max={:.1}",
                    samples[SAMPLES / 2],
                    samples[0],
                    samples[SAMPLES - 1]
                );
            }
            let mut samples = [0.0; SAMPLES];
            for sample in &mut samples {
                let start = Instant::now();
                for _ in 0..ITERATIONS {
                    black_box(parse_query_meta(black_box(&query))).unwrap();
                }
                *sample = start.elapsed().as_nanos() as f64 / ITERATIONS as f64;
            }
            samples.sort_by(f64::total_cmp);
            println!(
                "query meta {name_kind}: median={:.1} ns/op min={:.1} max={:.1}",
                samples[SAMPLES / 2],
                samples[0],
                samples[SAMPLES - 1]
            );
        }
    }

    #[test]
    fn walks_compressed_uncompressed_and_root_names() {
        let message = b"\x07ExAmPlE\x03COM\0\x03WWW\xc0\x00";
        let cases = [
            (0, 13, b"\x07example\x03com\0".as_slice()),
            (13, 19, b"\x03www\x07example\x03com\0".as_slice()),
            (12, 13, b"\0".as_slice()),
        ];
        for (start, end, expected) in cases {
            assert_eq!(skip_name(message, start), Some(end));
            let (name, decoded_end) = read_name(message, start).unwrap();
            assert_eq!(name, expected);
            assert_eq!(decoded_end, end);
        }
    }

    #[test]
    fn rejects_malformed_names_even_when_only_skipping() {
        let malformed = [
            b"".as_slice(),
            b"\x03ab",
            b"\x01a",
            b"\xc0",
            b"\xc0\x02",
            b"\xc0\x02\x03ab",
            b"\xc0\x00",
            b"\xc0\x02\xc0\x00",
            b"\x40\0",
            b"\x80\0",
        ];
        for message in malformed {
            assert!(
                skip_name(message, 0).is_none(),
                "malformed name: {message:?}"
            );
            assert!(
                read_name(message, 0).is_none(),
                "malformed name: {message:?}"
            );
        }
    }

    #[test]
    fn enforces_expanded_name_length_with_and_without_compression() {
        for (last_label_len, valid) in [(61, true), (62, false)] {
            let mut message = Vec::new();
            for length in [63, 63, 63, last_label_len] {
                message.push(length as u8);
                message.resize(message.len() + length, b'a');
            }
            message.push(0);
            let pointer_offset = message.len();
            message.extend_from_slice(&[0xc0, 0]);

            for (start, end) in [(0, pointer_offset), (pointer_offset, message.len())] {
                if valid {
                    assert_eq!(skip_name(&message, start), Some(end));
                    let (name, decoded_end) = read_name(&message, start).unwrap();
                    assert_eq!(name.len(), 255);
                    assert_eq!(decoded_end, end);
                } else {
                    assert_eq!(pointer_offset, 256);
                    assert!(skip_name(&message, start).is_none());
                    assert!(read_name(&message, start).is_none());
                }
            }
        }
    }

    #[test]
    fn permits_128_compression_jumps_but_rejects_129() {
        let mut message = vec![0];
        let mut previous = 0;
        for _ in 0..128 {
            let offset = message.len();
            let pointer = 0xc000 | u16::try_from(previous).unwrap();
            message.extend_from_slice(&pointer.to_be_bytes());
            previous = offset;
        }
        assert_eq!(skip_name(&message, previous), Some(message.len()));
        assert_eq!(
            read_name(&message, previous),
            Some((vec![0], message.len()))
        );

        let over_limit = message.len();
        let pointer = 0xc000 | u16::try_from(previous).unwrap();
        message.extend_from_slice(&pointer.to_be_bytes());
        assert!(skip_name(&message, over_limit).is_none());
        assert!(read_name(&message, over_limit).is_none());
    }
}
