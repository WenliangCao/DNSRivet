use crate::wire::{self, QueryKey, QueryMeta};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::{Duration, Instant};

struct Entry {
    response: Box<[u8]>,
    /// TTLs in response and ttl are relative to this whole-second boundary.
    aged_at: Instant,
    ttl: u32,
}

pub struct Cache {
    entries: Option<Mutex<LruCache<QueryKey, Entry>>>,
}

impl Cache {
    pub fn new(enabled: bool, capacity: usize) -> Self {
        let entries = enabled.then(|| {
            let capacity = NonZeroUsize::new(capacity.max(1)).expect("capacity is at least one");
            Mutex::new(LruCache::new(capacity))
        });
        Self { entries }
    }

    pub fn query_meta(&self, query: &[u8]) -> Option<QueryMeta> {
        self.entries.as_ref()?;
        wire::parse_query_meta(query)
    }

    /// Copy a hit into caller-owned storage; a miss leaves it unchanged.
    pub fn get_into(&self, meta: &QueryMeta, request_id: [u8; 2], response: &mut Vec<u8>) -> bool {
        let Some(entries) = &self.entries else {
            return false;
        };
        let mut entries = entries.lock().unwrap();
        let Some(entry) = entries.get_mut(&meta.key) else {
            return false;
        };
        let elapsed = entry.aged_at.elapsed().as_secs();
        if elapsed >= u64::from(entry.ttl) {
            entries.pop(&meta.key);
            return false;
        }
        // Age the canonical entry once per whole second, not every client copy.
        // Preserve the fractional second; resetting to now would extend TTLs.
        if elapsed > 0 {
            if !wire::adjust_ttls(&mut entry.response, elapsed) {
                entries.pop(&meta.key);
                return false;
            }
            entry.ttl -= elapsed as u32; // elapsed < ttl above
            entry.aged_at += Duration::from_secs(elapsed);
        }
        response.clear();
        response.extend_from_slice(&entry.response);
        drop(entries);
        response[..2].copy_from_slice(&request_id);
        true
    }

    #[cfg(test)]
    fn get(&self, meta: &QueryMeta, request_id: [u8; 2]) -> Option<Vec<u8>> {
        let mut response = Vec::new();
        self.get_into(meta, request_id, &mut response)
            .then_some(response)
    }

    pub fn insert(&self, meta: &QueryMeta, response: &[u8]) {
        let Some(entries) = &self.entries else {
            return;
        };
        let Some(ttl) = wire::cache_ttl(response, meta.key.qtype) else {
            return;
        };
        let mut stored: Box<[u8]> = response.into();
        stored[..2].fill(0);
        entries.lock().unwrap().put(
            meta.key.clone(),
            Entry {
                response: stored,
                aged_at: Instant::now(),
                ttl,
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn query(id: u16) -> Vec<u8> {
        let mut message = Vec::from(id.to_be_bytes());
        message.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        message.extend_from_slice(&[1, b'a', 0, 0, 1, 0, 1]);
        message
    }

    fn response(id: u16, ttl: u32) -> Vec<u8> {
        response_with_records(id, ttl, 1)
    }

    fn response_with_records(id: u16, ttl: u32, count: u16) -> Vec<u8> {
        let mut message = query(id);
        message[2] = 0x81;
        message[3] = 0x80;
        message[6..8].copy_from_slice(&count.to_be_bytes());
        for _ in 0..count {
            message.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
            message.extend_from_slice(&ttl.to_be_bytes());
            message.extend_from_slice(&[0, 4, 1, 1, 1, 1]);
        }
        message
    }

    fn edns_query(id: u16, udp_size: u16) -> Vec<u8> {
        let mut message = query(id);
        message[11] = 1;
        message.extend_from_slice(&[0, 0, 41]);
        message.extend_from_slice(&udp_size.to_be_bytes());
        message.extend_from_slice(&[0; 6]);
        message
    }

    #[test]
    fn restores_each_clients_id() {
        let cache = Cache::new(true, 2);
        let first = query(1);
        let meta = wire::parse_query_meta(&first).unwrap();
        cache.insert(&meta, &response(1, 60));
        let got = cache.get(&meta, 0xabcdu16.to_be_bytes()).unwrap();
        assert_eq!(&got[..2], &0xabcdu16.to_be_bytes());
    }

    #[test]
    fn fresh_cache_hits_preserve_every_byte_except_the_id() {
        let meta = wire::parse_query_meta(&edns_query(1, 4096)).unwrap();
        let cache = Cache::new(true, 2);
        let mut original = response_with_records(1, 120, 32);
        original[11] = 1;
        original.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0]);
        cache.insert(&meta, &original);

        let request_id = [0xab, 0xcd];
        let got = cache.get(&meta, request_id).unwrap();
        original[..2].copy_from_slice(&request_id);
        assert_eq!(got, original);
    }

    #[test]
    fn repeated_hits_reuse_output_storage_and_misses_leave_it_unchanged() {
        let meta = wire::parse_query_meta(&query(1)).unwrap();
        let cache = Cache::new(true, 2);
        cache.insert(&meta, &response(1, 60));
        let mut output = Vec::with_capacity(512);
        let allocation = output.as_ptr();
        for id in 0..100u16 {
            assert!(cache.get_into(&meta, id.to_be_bytes(), &mut output));
            assert_eq!(output.as_ptr(), allocation);
            assert_eq!(&output[..2], &id.to_be_bytes());
        }
        let before = output.clone();
        assert!(!Cache::new(false, 1).get_into(&meta, [0, 0], &mut output));
        assert_eq!(output, before);
    }

    #[test]
    fn disabled_cache_is_a_noop() {
        let cache = Cache::new(false, 2);
        let query = query(1);
        let meta = wire::parse_query_meta(&query).unwrap();
        cache.insert(&meta, &response(1, 60));
        assert!(cache.get(&meta, [0, 1]).is_none());
    }

    #[test]
    fn malformed_records_never_enter_the_cache() {
        let meta = wire::parse_query_meta(&query(1)).unwrap();
        let cache = Cache::new(true, 2);
        let complete = response(1, 120);
        for end in 0..complete.len() {
            cache.insert(&meta, &complete[..end]);
            assert!(cache.get(&meta, [0, 1]).is_none());
        }
    }

    #[test]
    fn expired_entries_are_removed() {
        let cache = Cache::new(true, 2);
        let query = query(1);
        let meta = wire::parse_query_meta(&query).unwrap();
        cache.insert(&meta, &response(1, 60));
        let mut entries = cache.entries.as_ref().unwrap().lock().unwrap();
        let entry = entries.get_mut(&meta.key).unwrap();
        entry.ttl = 1;
        entry.aged_at = Instant::now() - Duration::from_secs(2);
        drop(entries);
        assert!(cache.get(&meta, [0, 1]).is_none());
        assert!(cache.entries.as_ref().unwrap().lock().unwrap().is_empty());
    }

    #[test]
    fn separates_queries_that_can_produce_different_answers() {
        let query = edns_query(1, 4096);
        let meta = wire::parse_query_meta(&query).unwrap();
        let cache = Cache::new(true, 2);
        cache.insert(&meta, &response(1, 60));
        assert!(cache.get(&meta, [0, 1]).is_some());

        let cases = [
            ("QNAME", 13, b'b'),
            ("QTYPE", 16, 28),
            ("QCLASS", 18, 3),
            ("DO", 26, 0x80),
            ("AD", 3, 0x20),
            ("CD", 3, 0x10),
        ];
        for (field, offset, value) in cases {
            let mut different = query.clone();
            different[offset] = value;
            let meta = wire::parse_query_meta(&different).unwrap();
            assert!(cache.get(&meta, [0, 2]).is_none(), "different {field}");
        }
    }

    #[test]
    fn reuses_answers_across_udp_payload_sizes() {
        let large = wire::parse_query_meta(&edns_query(1, 4096)).unwrap();
        let small = wire::parse_query_meta(&edns_query(2, 512)).unwrap();
        assert_eq!(large.udp_size, 4096);
        assert_eq!(small.udp_size, 512);

        let cache = Cache::new(true, 2);
        cache.insert(&large, &response(1, 60));
        let got = cache.get(&small, [0, 2]).unwrap();
        assert_eq!(&got[..2], &[0, 2]);
    }

    #[test]
    fn edns_and_non_edns_clients_never_share_wire_responses() {
        let plain = wire::parse_query_meta(&query(1)).unwrap();
        let edns = wire::parse_query_meta(&edns_query(2, 1232)).unwrap();
        let mut with_opt = response(2, 60);
        with_opt[11] = 1;
        with_opt.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);

        for edns_first in [false, true] {
            let cache = Cache::new(true, 2);
            if edns_first {
                cache.insert(&edns, &with_opt);
                assert!(cache.get(&plain, [0, 3]).is_none());
            } else {
                cache.insert(&plain, &response(1, 60));
                assert!(cache.get(&edns, [0, 3]).is_none());
            }
            cache.insert(&plain, &response(1, 60));
            cache.insert(&edns, &with_opt);
            assert_eq!(cache.get(&plain, [0, 4]).unwrap()[11], 0);
            assert_eq!(cache.get(&edns, [0, 5]).unwrap()[11], 1);
        }
    }

    #[test]
    fn short_negative_answers_expire_and_zero_ttl_never_enters_cache() {
        let meta = wire::parse_query_meta(&query(1)).unwrap();
        for ttl in [0u32, 1] {
            let mut negative = query(1);
            negative[2] = 0x81;
            negative[3] = 0x83;
            negative[9] = 1;
            negative.extend_from_slice(&[0xc0, 0x0c, 0, 6, 0, 1]);
            negative.extend_from_slice(&ttl.to_be_bytes());
            negative.extend_from_slice(&[0, 24, 0xc0, 0x0c, 0xc0, 0x0c]);
            negative.extend_from_slice(&[0; 16]);
            negative.extend_from_slice(&ttl.to_be_bytes());
            let cache = Cache::new(true, 1);
            cache.insert(&meta, &negative);
            if ttl > 0 {
                assert!(cache.get(&meta, [0, 2]).is_some());
                cache
                    .entries
                    .as_ref()
                    .unwrap()
                    .lock()
                    .unwrap()
                    .get_mut(&meta.key)
                    .unwrap()
                    .aged_at = Instant::now() - Duration::from_secs(1);
            }
            assert!(cache.get(&meta, [0, 3]).is_none());
        }
    }

    #[test]
    fn ages_shared_ttls_once_without_sharing_client_mutations() {
        let meta = wire::parse_query_meta(&query(1)).unwrap();
        let mut original = response(1, 120);
        original[11] = 1;
        let opt = [0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0];
        original.extend_from_slice(&opt);
        let cache = Cache::new(true, 2);
        cache.insert(&meta, &original);

        for (id, ttl) in [([0x12, 0x34], 100), ([0xab, 0xcd], 80)] {
            let aged_at = Instant::now() - Duration::from_millis(20_500);
            cache
                .entries
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .get_mut(&meta.key)
                .unwrap()
                .aged_at = aged_at;
            let mut got = cache.get(&meta, id).unwrap();
            assert_eq!(&got[..2], &id);
            assert_eq!(wire::cache_ttl(&got, 1), Some(ttl));
            assert_eq!(&got[got.len() - opt.len()..], &opt);
            let again = cache.get(&meta, [0, 7]).unwrap();
            assert_eq!(&again[2..], &got[2..], "must not age twice in one second");
            got.fill(0);
            let mut entries = cache.entries.as_ref().unwrap().lock().unwrap();
            let entry = entries.get(&meta.key).unwrap();
            assert_eq!(&entry.response[..2], &[0, 0]);
            assert_eq!(&entry.response[2..], &again[2..]);
            assert_eq!(entry.aged_at, aged_at + Duration::from_secs(20));
        }
    }

    /// Run with `mbx test --release benchmark_cache_hits -- --ignored --nocapture`.
    #[test]
    #[ignore = "manual cache hot-path benchmark"]
    fn benchmark_cache_hits() {
        use std::hint::black_box;

        const ITERATIONS: usize = 100_000;
        const SAMPLES: usize = 7;
        println!(
            "cache entry metadata: {} bytes",
            std::mem::size_of::<Entry>()
        );
        let meta = wire::parse_query_meta(&query(1)).unwrap();
        for records in [1, 32] {
            for age in [0, 20] {
                let mut samples = [0.0; SAMPLES];
                for sample in &mut samples {
                    let cache = Cache::new(true, 1);
                    cache.insert(&meta, &response_with_records(1, 120, records));
                    cache
                        .entries
                        .as_ref()
                        .unwrap()
                        .lock()
                        .unwrap()
                        .get_mut(&meta.key)
                        .unwrap()
                        .aged_at = Instant::now() - Duration::from_secs(age);
                    let start = Instant::now();
                    for _ in 0..ITERATIONS {
                        black_box(
                            cache
                                .get(black_box(&meta), black_box([0xab, 0xcd]))
                                .unwrap(),
                        );
                    }
                    let elapsed = start.elapsed();
                    assert!(
                        elapsed < Duration::from_secs(1),
                        "sample crossed a TTL tick"
                    );
                    *sample = elapsed.as_nanos() as f64 / ITERATIONS as f64;
                }
                samples.sort_by(f64::total_cmp);
                println!(
                    "records={records} age={age}s median={:.1} ns/hit min={:.1} max={:.1}",
                    samples[SAMPLES / 2],
                    samples[0],
                    samples[SAMPLES - 1]
                );
            }
        }
    }
}
