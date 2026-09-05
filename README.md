PcapQL is a pet project trying to create a database from where one can query information
about saved pcap files. Its purpose is twofold:
1. Learn Rust
2. Learn Network inspection.

It currently supports 2 [LinkTypes](https://www.tcpdump.org/linktypes.html)
- 1: LINKTYPE_ETHERNET
- 113: LINKTYPE_LINUX_SLL

It is also able to parse PCAP files having ARP packets in the data link layer,
IPv4, IPv6, ICMP, ICMPv6, IGMP in the network layer, and TCP, UDP in the
transport layer.

## Project Structure

```
pcapql
|
|---db/
|---parser/
      |----link/
      |----network/
      |----pcap/
      |----transport/
      |----layer.rs
      |----lib.rs
      |---tests/
            |---common/
            |---[test cases]
|---src/
|---tests/
      |---cases/
      |---accumulate.sh
      |---README.md
|---Design.md
|---README.md
```

### DB

Next module to be added. It will provide a DB-like functionality by storing the parsed data
and allowing functionalities like `insert`, `where`, `select`.

### Parser

Parses the PCAP files. Since recreating a Wireshark's parsing capabilities would not be
productive it panics each time it finds a missing Protocol to allow adding missing types of
fields on demand. Each protocol belongs to its corresponding OSI layer. 

It exports all the types inside a Frame.

### src

Simple driver to test functionalities and API usage. Will occasionally change.

### Desing.md

Contains architectural decisions justification as well as more detailed explanation of how the 
project works.

## Data References

The PCAPs used for testing the PcapQL are the following.

https://www.netresec.com/?page=PcapFiles
https://www.kaggle.com/datasets/olaidegabriel/attack-scenario-dataset-in-pcap-format

Data is not included due to its size.

## Benchmarking

I run 
```bash
hyperfine --warmup 3 --runs 10 './target/release/pcapql'
```

Resulting in 
```bash
Benchmark 1: ./target/release/pcapql
  Time (mean ± σ):      2.285 s ±  0.014 s    [User: 0.878 s, System: 0.981 s]
  Range (min … max):    2.261 s …  2.309 s    10 runs
```

With the downloaded data running
```bash
find data -type f \( -name "*.pcap" -o -name "snort.log*" \) -exec stat -f%z {} \; \
  | awk '{sum+=$1; n++} END {printf "%d files, %.2f MB (%.2f GB)\n", n, sum/1024/1024, sum/1024/1024/1024}'
```

Resulted in
```bash
85 files, 4385.26 MB (4.28 GB)
```
