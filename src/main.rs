use anyhow::{Context, Result};
use clap::Parser;
use futures::stream::FuturesUnordered;
use futures::StreamExt;
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
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

    let requests: Arc<[Request]> = parse_tcpdump(cli.playbook)
        .expect("Failed to parse playbook")
        .into();

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
    let tcp_packet = if u16::from_be_bytes([data[14], data[15]]) == 0x0800 {
        // For `-i any` tcpdump adds 2 bytes of something to the Ethernet frame
        &data[16..]
    } else if u16::from_be_bytes([data[12], data[13]]) == 0x0800 {
        // In regular Ethernet frames the Ethernet header is 14 bytes long
        &data[14..]
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

    // Array of timestamps to calculate the requests per second
    let mut timestamps = vec![];

    loop {
        match reader.next() {
            Ok((offset, data)) => {
                if let PcapBlockOwned::Legacy(block) = data {
                    if let Some(tcp_data) = get_tcp_data(block.data) {
                        if let Ok(api) = proto::api::Api::parse_from_bytes(tcp_data) {
                            if let proto::options::options::Action::route =
                                api.options.action.enum_value_or_default()
                            {
                                // Convert the timestamp to microseconds
                                timestamps
                                    .push(block.ts_sec as u64 * 1_000_000 + block.ts_usec as u64);

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

    let duration_s =
        (timestamps.last().unwrap_or(&0) - timestamps.first().unwrap_or(&0)) as f64 / 1_000_000.0;
    let peak_rps = count_peak_rps(timestamps);
    println!(
        "Parsed {} requests ({duration_s:.1}s), average {:.2}rps, peak {peak_rps}rps",
        requests.len(),
        requests.len() as f64 / duration_s,
    );

    Ok(requests)
}

fn count_peak_rps(mut timestamps: Vec<u64>) -> usize {
    timestamps.sort();

    let mut max_rps = 0;
    let mut start = 0;

    for end in 0..timestamps.len() {
        // Move the start pointer to maintain a 1-second window
        while timestamps[end] - timestamps[start] > 1_000_000 {
            start += 1;
        }

        // Calculate the number of requests in the current window
        let current_rps = end - start + 1;
        if current_rps > max_rps {
            max_rps = current_rps;
        }
    }

    max_rps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_peak_rps_test() {
        assert_eq!(count_peak_rps(vec![]), 0);
    }
}
