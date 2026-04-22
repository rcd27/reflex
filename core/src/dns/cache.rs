//! In-memory DNS cache: maps IP addresses to domain names with TTL-based expiry.
//!
//! Used by Geneva for mapping destination IPs back to domain names.
//! Populated from DNS response packets observed on the bridge interface.
//!
//! # Eviction
//!
//! - Expired entries are removed by `cleanup()` (called periodically).
//! - When `max_entries` is exceeded on insert, the oldest entry (smallest
//!   `inserted_at`) is evicted to make room.

use std::collections::HashMap;
use std::net::Ipv4Addr;

/// A cached DNS entry (private — callers only see domain via `lookup`).
struct Entry {
    domain: String,
    expires_at: f64,
    inserted_at: f64,
}

/// IP -> domain cache with TTL expiry and bounded size.
pub struct DnsCache {
    entries: HashMap<Ipv4Addr, Entry>,
    max_entries: usize,
}

impl DnsCache {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
        }
    }

    /// Insert a DNS response: each IP in `ips` maps to `domain`.
    ///
    /// If the cache exceeds `max_entries` after insertion, the oldest entry
    /// (smallest `inserted_at`) is evicted.
    pub fn insert(&mut self, domain: &str, ips: &[Ipv4Addr], ttl_secs: f64, now: f64) {
        for &ip in ips {
            self.entries.insert(
                ip,
                Entry {
                    domain: domain.to_owned(),
                    expires_at: now + ttl_secs,
                    inserted_at: now,
                },
            );
        }

        while self.entries.len() > self.max_entries {
            self.evict_oldest();
        }
    }

    /// Look up the domain for `ip`, returning `None` if missing or expired.
    pub fn lookup(&self, ip: Ipv4Addr, now: f64) -> Option<&str> {
        let entry = self.entries.get(&ip)?;
        if now <= entry.expires_at {
            Some(entry.domain.as_str())
        } else {
            None
        }
    }

    /// Remove all expired entries.
    pub fn cleanup(&mut self, now: f64) {
        self.entries.retain(|_, entry| now <= entry.expires_at);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Evict the entry with the smallest `inserted_at`.
    fn evict_oldest(&mut self) {
        let oldest_ip = self
            .entries
            .iter()
            .min_by(|a, b| {
                a.1.inserted_at
                    .partial_cmp(&b.1.inserted_at)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(&ip, _)| ip);

        if let Some(ip) = oldest_ip {
            self.entries.remove(&ip);
        }
    }
}
