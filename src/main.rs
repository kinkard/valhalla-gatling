use anyhow::{Context, Result};
use clap::Parser;
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

    /// The URL to send the request to.
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

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Test cli.url against `/status` endpoint to ensure the server is running
    let status = reqwest::get(format!("{}/status", cli.url)).await;
    assert!(
        status.is_ok_and(|r| r.status().is_success()),
        "HTTP request to '{}/status' failed",
        cli.url,
    );

    let requests: Arc<[Request]> = parse_tcpdump(cli.playbook)
        .expect("Failed to parse playbook")
        .into();

    let client = reqwest::Client::new();

    let concurrency_levels = [4, 6, 8, 12, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 128];
    let max_concurrency = concurrency_levels.last().cloned().unwrap();
    let mut tasks = Vec::new();

    let (results_tx, results_rx) = flume::unbounded::<Option<std::num::NonZeroU32>>();

    for concurrency in concurrency_levels {
        println!("Concurrency {}, warming up...", concurrency);
        // Gradually increase number of concurrent requests
        for tasl_idx in tasks.len()..concurrency {
            let client = client.clone();
            let url = cli.url.clone();
            let requests = requests.clone();
            let results_tx = results_tx.clone();

            tasks.push(tokio::spawn(async move {
                // Avoid duplicate requests by cycling through the requests array
                let requests = requests
                    .iter()
                    .cycle()
                    .skip(tasl_idx)
                    .step_by(max_concurrency);
                for r in requests {
                    let start = std::time::Instant::now();
                    let result = client
                        .request(r.method.clone(), &url)
                        .headers(r.headers.clone())
                        .body(r.body.clone())
                        .send()
                        .await;
                    let elapsed = start.elapsed().as_micros();
                    let latency = if result.is_ok_and(|r| r.status().is_success()) {
                        Some(std::num::NonZeroU32::new(elapsed as u32).unwrap())
                    } else {
                        None
                    };

                    // Channel has been closed, stop sending results and exit the task
                    if results_tx.send(latency).is_err() {
                        break;
                    }
                }
            }));
        }

        // First 15s read all results and throw them away
        let start = std::time::Instant::now();
        while let Ok(_latency) = results_rx.recv() {
            if start.elapsed().as_secs() >= 15 {
                break;
            }
        }

        // Then read the results for 15s and count the success rate, throughput and p50, p95, p99 latency
        let start = std::time::Instant::now();
        let mut successfull = 0;
        let mut total = 0;
        let mut latencies = Vec::new();
        while let Ok(latency) = results_rx.recv() {
            total += 1;
            if let Some(latency) = latency {
                successfull += 1;
                latencies.push(latency.get());
            }
            let elapsed = start.elapsed();
            if elapsed.as_secs() >= 15 {
                println!(
                    "- Throughput: {:.2}rps ({}/{:.2}s), success rate {:.2}",
                    total as f64 / elapsed.as_secs_f64(),
                    total,
                    elapsed.as_secs_f64(),
                    successfull as f64 / total as f64
                );
                break;
            }
        }
        latencies.sort_unstable();
        let p50 = latencies[(latencies.len() as f64 * 0.50) as usize] as f64 / 1000.0;
        let p95 = latencies[(latencies.len() as f64 * 0.95) as usize] as f64 / 1000.0;
        let p99 = latencies[(latencies.len() as f64 * 0.99) as usize] as f64 / 1000.0;
        println!("- Latency p50: {p50}ms, p95: {p95}ms, p99: {p99}ms");
    }

    // Close the channel to stop all tasks
    drop(results_tx);
    drop(results_rx);
    for t in tasks {
        t.await.expect("Task panicked");
    }
}

/// Parses the TCP header and extracts the HTTP request payload if present.
fn get_tcp_data(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 36 {
        return None;
    }

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

    #[test]
    fn get_tcp_data_test() {
        assert_eq!(get_tcp_data(&[]), None);
        assert_eq!(get_tcp_data(&[0; 36]), None);
    }
}
