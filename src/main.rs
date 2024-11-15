use clap::Parser;
use futures::{stream, StreamExt};

#[derive(Parser)]
struct Cli {
    /// The URL to send the request to
    /// Example: http://localhost:8002/route
    url: String,

    /// The number of requests to send in parallel
    #[arg(short, default_value_t = 1)]
    concurrency: u32,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // points in Germany
    let points: &[(f64, f64)] = &[
        (54.773757, 9.454516),
        (53.566530, 9.958475),
        (52.513193, 13.432262),
        (54.319199, 10.098249),
        (52.347264, 14.542465),
        (53.076539, 8.824777),
        (51.046489, 13.778721),
        (51.353396, 12.379302),
        (51.213349, 6.823608),
        (50.949610, 6.977544),
        (50.149349, 8.698830),
        (49.453874, 11.063848),
        (48.776063, 9.174632),
        (48.163703, 11.567639),
        (48.002704, 7.837777),
        (47.681602, 9.159130),
        (47.588680, 11.313302),
    ];

    // create an iter from each point to each other point
    let iter = points.iter().flat_map(|&from| {
        points
            .iter()
            .filter_map(move |&to| if from != to { Some((from, to)) } else { None })
    });

    let client = reqwest::Client::new();

    // create a stream of requests and send them in parallel
    let start = std::time::Instant::now();
    let results = stream::iter(iter.map(|(from, to)| {
        let url = cli.url.clone();
        let body = serde_json::json!({
            "locations": [
                {"lat": from.0, "lon": from.1, "type": "break"},
                {"lat": to.0, "lon": to.1, "type": "break"}
            ],
            "costing": "auto",
            "directions_options": {"units": "km"}
        });

        client.post(&url).json(&body).send()
    }))
    .buffer_unordered(cli.concurrency as usize)
    .collect::<Vec<_>>()
    .await;

    // count the number of successful requests
    let successful = results.iter().filter(|r| r.is_ok()).count();
    println!(
        "Sent {} requests in {} seconds with {} successful",
        points.len() * (points.len() - 1),
        start.elapsed().as_secs_f64(),
        successful
    );
}
