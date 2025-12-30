# i <3 dns.

going to try DIYing it!

## what i am using as resources

packet structure:
- https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf

to test:
- `cargo t` for my own tests
- `cargo r` and then in a separate tab running `dig @127.0.0.1 -p 8080 example.com`

to benchmark:
- `./bench/run_benchmark.sh` will run three types of workflows (random uncached queries, things that should benefit from caching, and parallel requests)
- to run just a subset of these, you can run `./bench/run_benchmark.sh --tests cached,parallel`

## todo list

### MAIN NEXT UP
- tidy what i have
- persist the cache?
- later [ benchmarking w criterion ]

### longer term TODO
- [x] message 8.8.8.8 with a query {decode and re-encode the packet}
- [x] support messaging 8.8.8.8 with norecurse on
- [x] add caching
- [ ] persist cache
- [ ] add retry logic / load balance between root servers
- [ ] move to tcp? 
- [ ] dnssec? 
- [ ] cname?
- [ ] performance?
