use crate::wire::{self, QueryMeta};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::time::Instant;

#[derive(Clone, Eq, Hash, PartialEq)]
struct Key {
    qname: Vec<u8>,
    qtype: u16,
    qclass: u16,
    do_bit: bool,
    dnssec_header_bits: u8,
}

impl From<&QueryMeta> for Key {
    fn from(meta: &QueryMeta) -> Self {
        Self {
            qname: meta.qname.clone(),
            qtype: meta.qtype,
            qclass: meta.qclass,
            do_bit: meta.do_bit,
            dnssec_header_bits: meta.dnssec_header_bits,
        }
    }
}

struct Entry {
    response: Vec<u8>,
    stored_at: Instant,
    ttl: u32,
}

pub struct Cache {
    entries: Option<Mutex<LruCache<Key, Entry>>>,
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
        let key = Key::from(meta);
        let mut entries = entries.lock().unwrap();
        let (mut response, elapsed, ttl) = {
            let entry = entries.get(&key)?;
            (
                entry.response.clone(),
                entry.stored_at.elapsed().as_secs(),
                entry.ttl,
            )
        };
        if elapsed >= u64::from(ttl) {
            entries.pop(&key);
            return None;
        }
        drop(entries);

        if !wire::adjust_ttls(&mut response, elapsed) {
            return None;
        }
        response[..2].copy_from_slice(&request_id);
        Some(response)
    }

    pub fn insert(&self, meta: &QueryMeta, response: &[u8]) {
        let Some(entries) = &self.entries else {
            return;
        };
        let Some(ttl) = wire::cache_ttl(response, meta.qtype) else {
            return;
        };
        let mut stored = response.to_vec();
        stored[..2].fill(0);
        entries.lock().unwrap().put(
            Key::from(meta),
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
        let mut message = query(id);
        message[2] = 0x81;
        message[3] = 0x80;
        message[6..8].copy_from_slice(&1u16.to_be_bytes());
        message.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1]);
        message.extend_from_slice(&ttl.to_be_bytes());
        message.extend_from_slice(&[0, 4, 1, 1, 1, 1]);
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
    fn disabled_cache_is_a_noop() {
        let cache = Cache::new(false, 2);
        let query = query(1);
        let meta = wire::parse_query_meta(&query).unwrap();
        cache.insert(&meta, &response(1, 60));
        assert!(cache.get(&meta, [0, 1]).is_none());
    }

    #[test]
    fn expired_entries_are_removed() {
        let cache = Cache::new(true, 2);
        let query = query(1);
        let meta = wire::parse_query_meta(&query).unwrap();
        cache.insert(&meta, &response(1, 60));
        let key = Key::from(&meta);
        let mut entries = cache.entries.as_ref().unwrap().lock().unwrap();
        let entry = entries.get_mut(&key).unwrap();
        entry.ttl = 1;
        entry.stored_at = Instant::now() - Duration::from_secs(2);
        drop(entries);
        assert!(cache.get(&meta, [0, 1]).is_none());
        assert!(cache.entries.as_ref().unwrap().lock().unwrap().is_empty());
    }
}
