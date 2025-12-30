# i <3 dns.

going to try DIYing it!

## what i am using as resources

packet structure:
- https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf

to test:
- `cargo t` for my own tests
- `cargo r` and then in a separate tab running `dig @127.0.0.1 -p 8080 example.com`

## todo list

### MAIN NEXT UP
- tidy what i have
- add parallel processing
- add persistence + caching

### longer term TODO
- [x] message 8.8.8.8 with a query {decode and re-encode the packet}
- [x] support messaging 8.8.8.8 with norecurse on
- [ ] add caching
- [ ] persist cache
- [ ] add retry logic
- [ ] move to tcp? 
- [ ] edns
- [ ] dnssec? 
- [ ] cname?
- [ ] performance?
