use crate::wire::{self, QueryKey, QueryMeta};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Instant;

struct Entry {
    response: Box<[u8]>,
    stored_at: Instant,
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

    pub fn get(&self, meta: &QueryMeta, request_id: [u8; 2]) -> Option<Vec<u8>> {
        let entries = self.entries.as_ref()?;
        let mut entries = entries.lock().unwrap();
        let entry = entries.get(&meta.key)?;
        let elapsed = entry.stored_at.elapsed().as_secs();
        if elapsed >= u64::from(entry.ttl) {
            entries.pop(&meta.key);
            return None;
        }
        let mut response = entry.response.to_vec();
        drop(entries);

        // Insertion validates every record. Until a whole second has elapsed,
        // all TTLs are unchanged, so another full wire walk would do no work.
        if elapsed > 0 && !wire::adjust_ttls(&mut response, elapsed) {
            return None;
        }
        response[..2].copy_from_slice(&request_id);
        Some(response)
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
                stored_at: Instant::now(),
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
        entry.stored_at = Instant::now() - Duration::from_secs(2);
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
    fn keeps_cached_id_and_ttls_unchanged_between_clients() {
        let meta = wire::parse_query_meta(&query(1)).unwrap();
        let mut original = response(1, 120);
        original[11] = 1;
        let opt = [0, 0, 41, 0x10, 0, 0, 0, 0x80, 0, 0, 0];
        original.extend_from_slice(&opt);
        let cache = Cache::new(true, 2);
        cache.insert(&meta, &original);

        for (id, age) in [([0x12, 0x34], 20), ([0xab, 0xcd], 40)] {
            let stored_at = Instant::now() - Duration::from_secs(age);
            {
                let mut entries = cache.entries.as_ref().unwrap().lock().unwrap();
                entries.get_mut(&meta.key).unwrap().stored_at = stored_at;
            }
            let elapsed_before = stored_at.elapsed().as_secs().min(120) as u32;
            let mut got = cache.get(&meta, id).unwrap();
            let elapsed_after = stored_at.elapsed().as_secs().min(120) as u32;
            assert_eq!(&got[..2], &id);
            let ttl = wire::cache_ttl(&got, 1).unwrap();
            assert!((120 - elapsed_after..=120 - elapsed_before).contains(&ttl));
            assert_eq!(&got[got.len() - opt.len()..], &opt);

            // A client owns its response and can change it without changing the cache.
            got.fill(0);
            let mut entries = cache.entries.as_ref().unwrap().lock().unwrap();
            let entry = entries.get(&meta.key).unwrap();
            assert_eq!(&entry.response[..2], &[0, 0]);
            assert_eq!(&entry.response[2..], &original[2..]);
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
            let cache = Cache::new(true, 1);
            cache.insert(&meta, &response_with_records(1, 120, records));
            for age in [0, 20] {
                let mut samples = [0.0; SAMPLES];
                for sample in &mut samples {
                    cache
                        .entries
                        .as_ref()
                        .unwrap()
                        .lock()
                        .unwrap()
                        .get_mut(&meta.key)
                        .unwrap()
                        .stored_at = Instant::now() - Duration::from_secs(age);
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
