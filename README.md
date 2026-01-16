# dns

Recursive DNS resolver in Rust. Starts from root servers, iteratively follows referrals, caches results with TTL.

## How it works

1. Receives DNS query on UDP port 8080
2. Starts at root nameserver (198.41.0.4)
3. Follows NS referrals down the hierarchy until answer found
4. Caches IPs with TTL, concurrent-safe via `DashMap`
5. Returns A record to client

## Usage

```bash
# start server
cargo r

# query (from another terminal)
dig @127.0.0.1 -p 8080 example.com
```

## Testing

```bash
cargo t                                        # unit tests
./bench/run_benchmark.sh                       # all benchmarks
./bench/run_benchmark.sh --tests cached,parallel  # specific benchmarks
```

## Dependencies

- `tokio` - async runtime
- `nom` - packet parsing
- `dashmap` - concurrent cache

## Resources

- [DNS packet structure primer](https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf)

## TODO

- [x] packet encode/decode
- [x] iterative resolution
- [x] TTL-based caching
- [ ] CNAME following
- [ ] cache persistence
- [ ] root server failover
- [ ] TCP fallback
- [ ] DNSSEC
