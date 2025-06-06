use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use protobuf::Message;
use rand::{rng, seq::SliceRandom};
use reqwest::Method;
use reqwest::header::{self, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::str::FromStr;
use std::sync::Arc;

mod proto {
    include!(concat!(env!("OUT_DIR"), "/proto/mod.rs"));
}

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Extracts `/route` Valhalla or OSRM requests from the specified .pcap file.
    Extract {
        /// Path to the .pcap file to extract the requests from, usually captured via `tcpdump`.
        #[arg(required = true)]
        tcpdump: Vec<String>,
        /// Optional output file name. If not provided, the default name is equal to the input file name with the `.playbook` extension.
        #[arg(short, long)]
        output: Option<String>,
        /// Randomize the order of requests in the playbook.
        #[arg(long)]
        randomize: bool,
    },

    /// Sends the requests to the specified URL and measures the throughput, success rate and latency percentiles.
    Run {
        /// The URL to send the request to.
        /// Example: http://localhost:8002/route
        url: String,
        /// The playbook file in .playbook format, generated by the `extract` command.
        playbook: String,
        /// Maximum number of concurrent requests to send.
        #[arg(short, long, default_value = "128")]
        concurrency: u8,
        /// Additional HTTP headers to include with each request (format: "Name:Value").
        /// Useful if additional authentication is required.
        #[arg(short, long)]
        header: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
enum HttpMethod {
    Get,
    Post,
}

impl From<HttpMethod> for reqwest::Method {
    fn from(method: HttpMethod) -> Self {
        match method {
            HttpMethod::Get => Method::GET,
            HttpMethod::Post => Method::POST,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct Request {
    /// HTTP request type like `GET` or `POST`
    method: HttpMethod,
    /// Request endpoint with parameters like `/route` or `/route?json={...}`
    uri: Box<str>,
    /// HTTP request headers like `Content-Type` or `Accept-Encoding`
    headers: Box<[(Box<str>, Box<str>)]>,
    /// HTTP request body
    body: Box<[u8]>,
}

impl Request {
    async fn send(
        &self,
        client: &reqwest::Client,
        base_url: &str,
    ) -> Result<reqwest::Response, reqwest::Error> {
        client
            .request(self.method.into(), format!("{}{}", base_url, &self.uri))
            .headers(
                self.headers
                    .iter()
                    .map(|(k, v)| {
                        (
                            HeaderName::from_str(k).unwrap(),
                            HeaderValue::from_str(v).unwrap(),
                        )
                    })
                    .collect(),
            )
            .body(self.body.to_vec())
            .send()
            .await
    }
}

#[derive(Serialize, Deserialize)]
struct Playbook {
    /// List of requests to be sent to the server
    requests: Vec<Request>,
}

impl Playbook {
    fn save(&self, path: &str) -> Result<()> {
        let mut s = flexbuffers::FlexbufferSerializer::new();
        self.serialize(&mut s)
            .context("Failed to serialize requests")?;
        std::fs::write(path, s.view()).context("Failed to write serialized requests")
    }

    fn load(path: &str) -> Result<Self> {
        let data = std::fs::read(path).context("Failed to read playbook file")?;
        let r = flexbuffers::Reader::get_root(data.as_ref()).context("Failed to create reader")?;
        let playbook = Playbook::deserialize(r).context("Failed to deserialize playbook")?;
        Ok(playbook)
    }
}

#[derive(Default)]
struct Metric {
    concurrency: u16,
    throughput: f64,
    success_rate: f64,
    p50: f64,
    p95: f64,
    p99: f64,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Extract {
            tcpdump,
            output,
            randomize,
        } => extract(tcpdump, output, randomize),
        Commands::Run {
            url,
            playbook,
            concurrency,
            header,
        } => run(url, playbook, concurrency as usize, header),
    }
}

fn extract(tcpdumps: Vec<String>, output: Option<String>, randomize: bool) {
    let output = output.unwrap_or_else(|| format!("{}.playbook", tcpdumps[0]));
    let mut requests = Vec::new();

    for tcpdump in tcpdumps {
        println!("Parsing {tcpdump}...");
        let mut r = parse_tcpdump(tcpdump).expect("Failed to parse tcpdump");
        requests.append(&mut r);
    }

    println!("Total requests extracted: {}", requests.len());

    if randomize {
        println!("Randomizing request order...");
        requests.shuffle(&mut rng());
    }

    let playbook = Playbook { requests };
    playbook.save(&output).expect("Failed to save playbook");
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn run(
    url: String,
    playbook: String,
    max_concurrency: usize,
    additional_headers: Vec<String>,
) {
    let mut playbook = Playbook::load(&playbook).expect("Failed to load playbook");
    println!(
        "Loaded {} HTTP requests from the playbook",
        playbook.requests.len()
    );

    let additional_headers = additional_headers
        .iter()
        .filter_map(|header_str| {
            if let Some((key, value)) = header_str.split_once(':') {
                Some((key.trim().into(), value.trim().into()))
            } else {
                eprintln!(
                    "Warning: Invalid header format '{}', skipping. Expected format: 'Name:Value'",
                    header_str
                );
                None
            }
        })
        .collect::<Vec<(Box<str>, Box<str>)>>();
    if !additional_headers.is_empty() {
        for r in &mut playbook.requests {
            let mut new_headers = Vec::from(r.headers.as_ref());
            new_headers.extend(additional_headers.iter().cloned());
            r.headers = new_headers.into_boxed_slice();
        }
    }

    let requests: Arc<[Request]> = Arc::from(playbook.requests);

    let client = reqwest::Client::new();

    // Try to send a single request to check if the server is up
    let _ = requests[0]
        .send(&client, &url)
        .await
        .expect("Failed to send a test request");

    // Doing concurrent requests via spawning tasks allows us to
    // - gradually increase the number of concurrent requests without pauses, thus keeping the server warm
    // - utilize more than one thread/core to avoid bottlenecks with sending requests
    let concurrency_levels = [4, 6, 8, 12, 16, 20, 24, 28, 32, 40, 48, 56, 64, 80, 96, 128];
    let mut tasks = Vec::new();
    let (results_tx, results_rx) = flume::unbounded::<Option<std::num::NonZeroU32>>();
    let mut measure_cold_start = true;
    for concurrency in concurrency_levels
        .into_iter()
        .take_while(|c| *c <= max_concurrency)
    {
        // Gradually increase number of concurrent requests
        for task_idx in tasks.len()..concurrency {
            let client = client.clone();
            let url = url.clone();
            let requests = requests.clone();
            let results_tx = results_tx.clone();

            tasks.push(tokio::spawn(async move {
                // Avoid duplicate requests by cycling through the requests array
                let requests = requests
                    .iter()
                    .cycle()
                    .skip(task_idx)
                    .step_by(max_concurrency);
                for r in requests {
                    let start = std::time::Instant::now();
                    let result = r.send(&client, &url).await;

                    let elapsed_us = start.elapsed().as_micros();
                    let latency = if result.is_ok_and(|r| r.status().is_success()) {
                        Some(std::num::NonZeroU32::new(elapsed_us as u32).unwrap())
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

        // todo: remove copy&paste with logic below
        if measure_cold_start {
            measure_cold_start = false;

            let start = std::time::Instant::now();
            let mut successfull = 0;
            let mut total = 0;
            let mut latencies = Vec::new();
            let mut metric = Metric::default();
            while let Ok(latency) = results_rx.recv() {
                total += 1;
                if let Some(latency) = latency {
                    successfull += 1;
                    latencies.push(latency.get());
                }
                let elapsed = start.elapsed();
                if elapsed.as_secs() >= 5 {
                    metric.throughput = total as f64 / elapsed.as_secs_f64();
                    metric.success_rate = successfull as f64 / total as f64;
                    break;
                }
            }
            latencies.sort_unstable();
            metric.concurrency = concurrency as u16;
            metric.p50 = latencies[(latencies.len() as f64 * 0.50) as usize] as f64 / 1000.0;
            metric.p95 = latencies[(latencies.len() as f64 * 0.95) as usize] as f64 / 1000.0;
            metric.p99 = latencies[(latencies.len() as f64 * 0.99) as usize] as f64 / 1000.0;

            println!(
                "Cold start with concurrency {}: throughput {:.2}rps, success rate {:.2}, p50 {:.1}ms, p95 {:.1}ms, p99 {:.1}ms",
                metric.concurrency,
                metric.throughput,
                metric.success_rate,
                metric.p50,
                metric.p95,
                metric.p99
            );
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
        let mut metric = Metric::default();
        while let Ok(latency) = results_rx.recv() {
            total += 1;
            if let Some(latency) = latency {
                successfull += 1;
                latencies.push(latency.get());
            }
            let elapsed = start.elapsed();
            if elapsed.as_secs() >= 15 {
                metric.throughput = total as f64 / elapsed.as_secs_f64();
                metric.success_rate = successfull as f64 / total as f64;
                break;
            }
        }
        latencies.sort_unstable();
        metric.concurrency = concurrency as u16;
        metric.p50 = latencies[(latencies.len() as f64 * 0.50) as usize] as f64 / 1000.0;
        metric.p95 = latencies[(latencies.len() as f64 * 0.95) as usize] as f64 / 1000.0;
        metric.p99 = latencies[(latencies.len() as f64 * 0.99) as usize] as f64 / 1000.0;
        println!(
            "Concurrency {}: throughput {:.2}rps, success rate {:.2}, p50 {:.1}ms, p95 {:.1}ms, p99 {:.1}ms",
            metric.concurrency,
            metric.throughput,
            metric.success_rate,
            metric.p50,
            metric.p95,
            metric.p99
        );
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

/// Traverses the TCP dump file and extracts TCP data (payload) from the packets.
fn traverse_tcpdump(path: String, mut callback: impl FnMut(u64, &[u8])) -> Result<()> {
    let file = File::open(path).context("Failed to open pcap file")?;
    let mut reader = LegacyPcapReader::new(65536, file).context("Failed to read pcap file")?;

    loop {
        match reader.next() {
            Ok((offset, data)) => {
                if let PcapBlockOwned::Legacy(block) = data {
                    if let Some(tcp_data) = get_tcp_data(block.data) {
                        let ts_us = block.ts_sec as u64 * 1_000_000 + block.ts_usec as u64;
                        callback(ts_us, tcp_data);
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

    Ok(())
}

fn parse_tcpdump(path: String) -> Result<Vec<Request>> {
    // Array of timestamps to calculate the requests per second
    let mut timestamps = vec![];
    let mut requests = vec![];

    traverse_tcpdump(path, |ts_us, tcp_data| {
        if let Ok(http_request) = std::str::from_utf8(tcp_data) {
            if let Some(uri) = http_request.split(' ').nth(1) {
                if uri.starts_with("/route/v1") {
                    timestamps.push(ts_us);

                    requests.push(Request {
                        method: HttpMethod::Get,
                        uri: uri.into(),
                        headers: Default::default(),
                        body: Default::default(),
                    });
                }
            }
        }

        if let Ok(api) = proto::api::Api::parse_from_bytes(tcp_data) {
            if let proto::options::options::Action::route =
                api.options.action.enum_value_or_default()
            {
                timestamps.push(ts_us);

                requests.push(Request {
                    method: HttpMethod::Get,
                    uri: "/route".into(),
                    headers: [
                        (header::CONTENT_TYPE, "application/x-protobuf"),
                        (header::ACCEPT_ENCODING, "gzip, deflate"),
                    ]
                    .into_iter()
                    .map(|(k, v)| (k.to_string().into_boxed_str(), v.into()))
                    .collect::<Vec<_>>()
                    .into(),
                    body: api.write_to_bytes().unwrap().into(),
                });
            }
        }
    })?;

    let duration_s =
        (timestamps.last().unwrap_or(&0) - timestamps.first().unwrap_or(&0)) as f64 / 1_000_000.0;
    let peak_rps = count_peak_rps(timestamps);
    println!(
        "Parsed {} requests ({}), average {:.2}rps, peak {peak_rps}rps",
        requests.len(),
        nice_seconds_format(duration_s),
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

fn nice_seconds_format(seconds: f64) -> String {
    let minutes_sec = seconds % 3600.0;
    let hours = (seconds - minutes_sec) / 3600.0;

    let seconds = minutes_sec % 60.0;
    let minutes = (minutes_sec - seconds) / 60.0;

    if hours != 0.0 {
        format!("{:.0}h {:.0}m", hours, minutes)
    } else if minutes != 0.0 {
        format!("{:.0}m {:.0}s", minutes, seconds)
    } else {
        format!("{:.1}s", seconds)
    }
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

    #[test]
    fn save_load_playbook_test() {
        let playbook = Playbook {
            requests: vec![Request {
                method: HttpMethod::Get,
                uri: "/route".into(),
                headers: vec![("Content-Type".into(), "application/json".into())].into(),
                body: vec![1, 2, 3].into(),
            }],
        };
        let path = "/tmp/test.playbook";
        playbook.save(path).expect("Failed to save playbook");
        let loaded_playbook = Playbook::load(path).expect("Failed to load playbook");
        assert_eq!(playbook.requests.len(), loaded_playbook.requests.len());
        for (r1, r2) in playbook
            .requests
            .iter()
            .zip(loaded_playbook.requests.iter())
        {
            assert_eq!(r1.method, r2.method);
            assert_eq!(r1.uri, r2.uri);
            assert_eq!(r1.headers, r2.headers);
            assert_eq!(r1.body, r2.body);
        }
    }

    #[test]
    fn nice_seconds_format_test() {
        assert_eq!(nice_seconds_format(0.0), "0.0s");
        assert_eq!(nice_seconds_format(1.1), "1.1s");
        assert_eq!(nice_seconds_format(62.6), "1m 3s");
        assert_eq!(nice_seconds_format(3600.0), "1h 0m");
        assert_eq!(nice_seconds_format(3725.56), "1h 2m");
        assert_eq!(nice_seconds_format(39241.5), "10h 54m");

        // That's weird, but why not? It is defeniately better than panic.
        assert_eq!(nice_seconds_format(-1.33), "-1.3s");
        assert_eq!(nice_seconds_format(-1111.33), "-18m -31s");
        assert_eq!(nice_seconds_format(-39241.5), "-10h -54m");
    }
}
