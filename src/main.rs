use anyhow::{Context, Result};
use clap::Parser;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use protobuf::well_known_types::duration;
use protobuf::Message;
use reqwest::header::{self, HeaderMap, HeaderValue};
use reqwest::Method;
use std::fs::File;
use std::sync::Arc;

mod proto {
    include!(concat!(env!("OUT_DIR"), "/proto/mod.rs"));
}

#[derive(Parser)]
struct Cli {
    /// Playbook file in .pcap format, captured via `tcpdump -i any dst port 8002 -w playbook.pcap`
    playbook: String,

    /// The URL to send the request to
    /// Example: http://localhost:8002/route
    url: String,
}

struct Request {
    /// HTTP request type like `GET` or `POST`
    method: Method,
    /// HTTP request headers like `Content-Type` or `Accept-Encoding`
    headers: HeaderMap,
    /// HTTP request body
    body: Vec<u8>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 10)]
async fn main() {
    let cli = Cli::parse();

    let start = std::time::Instant::now();
    let requests: Arc<[Request]> = parse_tcpdump(cli.playbook)
        .expect("Failed to parse playbook")
        .into();
    println!(
        "Parsed {} requests in {}ms",
        requests.len(),
        start.elapsed().as_millis()
    );

    let client = reqwest::Client::new();

    for concurrency in [1, 4, 8, 16, 32, 64, 128] {
        let start = std::time::Instant::now();
        // Do concurrency via tasks to eleminate possible bottlenecks at the client side.
        let tasks: FuturesUnordered<_> = (0..concurrency)
            .map(|task_idx| {
                let client = client.clone();
                let url = cli.url.clone();
                let requests = requests.clone();

                tokio::spawn(async move {
                    let mut results = Vec::new();
                    for r in requests.iter().skip(task_idx).step_by(concurrency).take(50) {
                        let start = std::time::Instant::now();
                        let result = client
                            .request(r.method.clone(), &url)
                            .headers(r.headers.clone())
                            .body(r.body.clone())
                            .send()
                            .await;
                        let ok = result.is_ok_and(|r| r.status().is_success());
                        results.push((ok, start.elapsed()));
                    }
                    results
                })
            })
            .collect();

        let mut all_results = tasks
            .collect::<Vec<_>>()
            .await
            .into_iter()
            .flatten()
            .flatten()
            .collect::<Vec<_>>();

        // count p50, p90, p99 of the response times
        // count the number of successful requests
        // count the number of failed requests

        all_results.sort_by(|lha, rha| lha.1.cmp(&rha.1));
        let p50 = all_results[(all_results.len() as f64 * 0.50) as usize]
            .1
            .as_millis();
        let p95 = all_results[(all_results.len() as f64 * 0.95) as usize]
            .1
            .as_millis();
        let p99 = all_results[(all_results.len() as f64 * 0.99) as usize]
            .1
            .as_millis();
        let total = all_results.len();
        let successfull = all_results.iter().filter(|r| r.0).count();

        println!(
            "Concurrency {concurrency}: Sent {total} requests in {:.1}s. Success rate {:.2}, latency p50 {p50}ms, p95 {p95}ms, p99 {p99}ms",
            start.elapsed().as_secs_f64(),
            successfull as f64 / total as f64,
        );
    }
}

/// Parses the TCP header and extracts the HTTP request payload if present.
fn get_tcp_data(data: &[u8]) -> Option<&[u8]> {
    // Seems tcpdump adds 2 bytes of something to the Ethernet frame, this is why we check 14th and 15th bytes
    // instead of 12th and 13th bytes as per Ethernet standard.
    let tcp_packet = if u16::from_be_bytes([data[14], data[15]]) == 0x0800 {
        &data[16..]
    } else {
        println!("Not a Ethernet Type II frame start: {:02x?}.", &data[..16]);
        return None;
    };

    let ip_version_and_ihl = tcp_packet[0];
    let version = ip_version_and_ihl >> 4;
    if version != 4 {
        println!("Not an IPv4 packet (Version: {}).", version);
        return None;
    }
    let ip_protocol = tcp_packet[9];
    if ip_protocol != 6 {
        println!("Not a TCP packet (Protocol: {ip_protocol}).");
        return None;
    }

    let ihl = (ip_version_and_ihl & 0x0f) as usize * 4;
    let tcp_packet = &tcp_packet[ihl..];

    let data_offset = (tcp_packet[12] >> 4) as usize * 4;
    if tcp_packet.len() <= data_offset {
        return None;
    }
    Some(&tcp_packet[data_offset..])
}

fn parse_tcpdump(path: String) -> Result<Vec<Request>> {
    let file = File::open(path).context("Failed to open pcap file")?;
    let mut reader = LegacyPcapReader::new(65536, file).context("Failed to read pcap file")?;
    let mut requests = vec![];

    loop {
        match reader.next() {
            Ok((offset, data)) => {
                if let PcapBlockOwned::Legacy(block) = data {
                    if let Some(tcp_data) = get_tcp_data(block.data) {
                        if let Ok(api) = proto::api::Api::parse_from_bytes(tcp_data) {
                            if let proto::options::options::Action::route =
                                api.options.action.enum_value_or_default()
                            {
                                // todo: actually, parse headers from the previous tcp packet
                                requests.push(Request {
                                    method: Method::GET,
                                    headers: [
                                        (header::CONTENT_TYPE, "application/x-protobuf"),
                                        (header::ACCEPT_ENCODING, "gzip, deflate"),
                                    ]
                                    .into_iter()
                                    .map(|(k, v)| (k, HeaderValue::from_str(v).unwrap()))
                                    .collect(),
                                    body: api.write_to_bytes().unwrap(),
                                });

                                // if let Some(method) = tcp_data
                                //     .position(|b| b == b' ')
                                //     .and_then(|pos| Method::from_bytes(&tcp_data[..pos]).ok())
                                // {
                                //     // and then parse the headers and body
                                // }
                            }
                        }
                    }
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                reader.refill().unwrap();
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }

    Ok(requests)
}
