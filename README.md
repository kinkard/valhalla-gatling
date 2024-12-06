# About

This project is a simple tool to measure the latency and throughput of Valhalla routing engine.

## Build & Run

```sh
cargo run --release
```

## Playbook

If external IP address is `192.168.0.1` and port is `8002` (default Valhalla port), then

```sh
sudo tcpdump -i any dst host 192.168.0.1 and dst port 8002 -w valhalla.pcap
```

Note: Filtering by IP address can be skipped, but without it every packet will be captured 3 times if Valhalla is running in Docker:packet to the host, to the bridge and to the container.

## License

All code in this project is dual-licensed under either:

- [MIT license](https://opensource.org/licenses/MIT) ([`LICENSE-MIT`](LICENSE-MIT))
- [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([`LICENSE-APACHE`](LICENSE-APACHE))

at your option.
