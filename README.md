# whoisit

An identd implementation for Linux, built as an excuse to play with async/await.
It cheats somewhat by relying on `lsof` to locate the user who owns a given
connection.

This is not a particularly useful thing.

On the bright side, it should be compliant with
[RFC 1413](https://tools.ietf.org/html/rfc1413) and it supports queries from both
IPv4 and IPv6 remote hosts.
