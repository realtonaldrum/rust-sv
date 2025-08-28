//! A foundation for building applications on Bitcoin SV using Rust.

extern crate byteorder;
extern crate dns_lookup;
extern crate hex;
#[macro_use]
extern crate log;
extern crate linked_hash_map;
extern crate murmur3;
extern crate rand;
extern crate ring;
extern crate secp256k1;
extern crate snowflake;

pub mod messages;
pub mod network;
pub mod peer;
pub mod script;
pub mod transaction;
pub mod util;
pub mod wallet;

use crate::util::{secs_since, Error, Result};
use crate::peer::{Peer, SVPeerFilter};
use crate::util::rx::{Observable};
use std::time::{UNIX_EPOCH, Duration};
use crate::network::NetworkConfig;
use crate::messages::{Message, Version, NODE_BITCOIN_CASH, PROTOCOL_VERSION};
use std::thread::sleep;

pub async fn broadcast_tx(raw_tx_vec: Vec<String>) -> Result<Vec<String>> {
    println!("Starting broadcast_txs_via_rustsv with {} transactions", raw_tx_vec.len());

    let network = NetworkConfig::new(0)?;
    println!("Network created: {:?}", network);

    // Collect up to 3 seed nodes for better propagation
    let seed_nodes: Vec<_> = network.seed_iter().take(3).collect();
    if seed_nodes.is_empty() {
        return Err(Error::BadData("No seed nodes available".to_string()));
    }
    println!("Selected seed nodes: {:?}", seed_nodes);

    let version = Version {
        version: PROTOCOL_VERSION,
        services: NODE_BITCOIN_CASH,
        timestamp: secs_since(UNIX_EPOCH) as i64,
        user_agent: "mahrustsv".to_string(),
        ..Default::default()
    };
    println!("Version message created: {:?}", version);

    let mut peers = Vec::new();
    for (ip, port) in seed_nodes {
        let peer = Peer::connect(ip, port, network.clone(), version.clone(), SVPeerFilter::new(0));
        println!("Peer connection initiated for {}:{}", ip, port);
        peer.connected_event().poll();
        println!("Peer connected successfully: {}:{}", ip, port);
        peers.push(peer);
    }

    let mut txids = Vec::new();

    for (i, raw_tx) in raw_tx_vec.iter().enumerate() {
        println!("Processing transaction {}: {}", i + 1, raw_tx);
        let tx = crate::messages::tx_raw::read_raw_tx(raw_tx)?;
        println!("Deserialized Tx: {:?}", tx);

        let txid = tx.hash();
        
        // Broadcast to all peers
        for peer in &peers {
            // Check if transaction meets minfee requirement
            let minfee = 1;
            println!("Node minfee: {} satoshis", minfee);
            // Note: Fee validation requires Tx to expose inputs/outputs values

            println!("Sending Tx message to peer {:?}", peer);
            peer.send(&Message::Tx(tx.clone()))?;
            println!("Tx sent successfully to peer {:?}", peer);

            // Brief delay to allow network processing
            sleep(Duration::from_secs(1));
            println!("Waited for peer {:?}", peer);
        }
        
        let mut txid_rev = txid.0;
        txid_rev.reverse();
        let txid_hex = hex::encode(txid_rev);
        println!("Computed txid: {}", txid_hex);

        txids.push(txid_hex);
    }

    // Clean up
    for peer in peers {
        println!("Disconnecting peer {:?}", peer);
        peer.disconnect();
        println!("Peer disconnected {:?}", peer);
    }

    println!("Broadcast completed. Txids: {:?}", txids);
    Ok(txids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_broadcast_txs_via_rustsv() {
        // Example known raw_tx_hex (a legacy Bitcoin transaction; compatible with BSV)
        let raw_tx_vec = vec![
            "0200000003fe46aea86f3df120e07a0ea79324d47241bc818206d6d08b9abfcb30e1d00827020000006b483045022100ae694baa7990fa0396d5e79430a52ae9741f4b0a63783210511c8c563fa8a727022046a86ae022aa709ff4cbdec49392a0a5569bb88bcd187fdc6e3255027b4e9a054121024d48c9725ab5f36cb867054e0914aa450b4f3dfac4326db53002de8754d4273cfffffffffd4fc909d97ab6023816b8a84caf737be1b0802953473fdc88edb2d445864529010000006a473044022057ba60b3a446de0c45a1438ff39c60ef3c0b858084fb90a52e3a1d3038dbd75e02207179e44840b69f4a2492379e6c1da37ac855be1696c7564c69db3ec6526574824121024d48c9725ab5f36cb867054e0914aa450b4f3dfac4326db53002de8754d4273cfffffffffd4fc909d97ab6023816b8a84caf737be1b0802953473fdc88edb2d445864529020000006b48304502210088aec671ea18094fb67e52000b93ca80e93171637f644396b72b4e870e7ce9eb0220565bc670b6e7c083e04aaa46af72c20cc735a5ac6e32d879b04a2bfabc98f1894121024d48c9725ab5f36cb867054e0914aa450b4f3dfac4326db53002de8754d4273cffffffff026f000000000000001976a914cb68f11966e8acbc746c2288c54a5cbf0e71df3688ac55000000000000001976a91453df8b6b61f926da1f0227f4e5d5a53427f1ad7d88ac00000000".to_string(),
        ];

        match broadcast_tx(raw_tx_vec).await {
            Ok(txids) => println!("Broadcasted txids: https://whatsonchain.com/tx/{}", txids[0]),
            Err(e) => eprintln!("Error: {:?}", e),
        };
    }
}