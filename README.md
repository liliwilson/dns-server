# i <3 dns.

going to try DIYing it!

## what i am using as resources

packet structure:
- https://mislove.org/teaching/cs4700/spring11/handouts/project1-primer.pdf

to test:
doing `cargo r` and then in a separate tab running `dig @127.0.0.1 -p 8080 example.com`

## todo list

[ ] message 8.8.8.8 with a query {decode and re-encode the packet}
[ ] support messaging 8.8.8.8 with norecurse on
[ ] add caching
[ ] add retry logic (what if 8.8.8.8 doesn't know?)
[ ] move to tcp? 
[ ] add compression
[ ] edns
[ ] dnssec? 
[ ] cname?
[ ] performance?
