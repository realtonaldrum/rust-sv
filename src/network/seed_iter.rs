//! Iterates over Bitcoin SV DNS seeds to resolve IP addresses semi-randomly.
//!
//! The `SeedIter` struct provides an iterator over IP addresses resolved from a list
//! of DNS seeds, useful for establishing P2P connections to Bitcoin SV nodes.
//!
//! # Example
//!
//! ```rust
//! use sv::network::SeedIter;
//!
//! let seeds = vec!["seed.bitcoinsv.io".to_string(), "seed.satoshisvision.network".to_string()];
//! let mut iter = SeedIter::new(&seeds, 8333);
//! while let Some((ip, port)) = iter.next() {
//!     println!("Resolved: {}:{}", ip, port);
//! }
//! ```

use dns_lookup::lookup_host;
use log::{error, info};
use rand::{rngs::ThreadRng, rng, Rng}; // Updated: thread_rng -> rng, added rngs::ThreadRng
use std::net::IpAddr;

/// Iterates through DNS seeds semi-randomly to resolve Bitcoin SV node addresses.
#[derive(Clone, Debug)]
pub struct SeedIter<'a> {
    /// Common port for all resolved IP addresses (e.g., 8333 for mainnet).
    pub port: u16,
    /// List of DNS seeds to resolve.
    seeds: &'a [String],
    /// Resolved IP addresses from the current seed.
    nodes: Vec<IpAddr>,
    /// Current index into the seeds list.
    seed_index: usize,
    /// Current index into the nodes list.
    node_index: usize,
    /// Random offset for semi-random iteration.
    random_offset: usize,
}

impl<'a> SeedIter<'a> {
    /// Creates a new iterator over DNS seeds with a random starting offset.
    ///
    /// # Arguments
    ///
    /// * `seeds` - Slice of DNS seed hostnames (e.g., ["seed.bitcoinsv.io"]).
    /// * `port` - Port to pair with resolved IPs (e.g., 8333 for mainnet).
    pub fn new(seeds: &'a [String], port: u16) -> Self {
        let mut rng = rng(); // Updated: thread_rng() -> rng()
        let random_offset = rng.random_range(0..100); // Updated: gen_range -> random_range
        Self {
            port,
            seeds,
            nodes: Vec::new(),
            seed_index: 0,
            node_index: 0,
            random_offset,
        }
    }
}

impl<'a> Iterator for SeedIter<'a> {
    type Item = (IpAddr, u16);

    /// Returns the next resolved IP address and port, or None if exhausted.
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Check if all seeds are exhausted
            if self.seed_index >= self.seeds.len() {
                return None;
            }

            // Resolve new nodes if the current list is empty
            if self.nodes.is_empty() {
                let i = (self.seed_index + self.random_offset) % self.seeds.len();
                info!("Looking up DNS: {}", self.seeds[i]);
                match lookup_host(&self.seeds[i]) {
                    Ok(ip_list) => {
                        if ip_list.is_empty() {
                            error!("DNS lookup for {} returned no IPs", self.seeds[i]);
                            self.seed_index += 1;
                            continue;
                        }
                        self.nodes = ip_list;
                    }
                    Err(e) => {
                        error!("Failed to look up DNS {}: {}", self.seeds[i], e);
                        self.seed_index += 1;
                        continue;
                    }
                }
            }

            // Return the next node, or reset for the next seed
            let i = (self.node_index + self.random_offset) % self.nodes.len();
            self.node_index += 1;
            if self.node_index >= self.nodes.len() {
                self.node_index = 0;
                self.seed_index += 1;
                self.nodes.clear();
            }
            return Some((self.nodes[i], self.port));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seed_iter_empty_seeds() {
        let seeds: Vec<String> = vec![];
        let mut iter = SeedIter::new(&seeds, 8333);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_seed_iter_invalid_seed() {
        let seeds = vec!["invalid.dns.seed".to_string()];
        let mut iter = SeedIter::new(&seeds, 8333);
        // Should skip invalid seed and return None
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_seed_iter_random_offset() {
        let seeds = vec!["seed.bitcoinsv.io".to_string()];
        let iter1 = SeedIter::new(&seeds, 8333);
        let iter2 = SeedIter::new(&seeds, 8333);
        // Random offsets should differ with high probability
        assert_ne!(iter1.random_offset, iter2.random_offset);
    }
}
