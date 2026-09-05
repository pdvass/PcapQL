# Tests

Test fixtures here are generated with `tshark`, not written by hand. `tshark` acts as an
independent, field-accurate reference parser.

We will use `-T fields` with explicit `-e` field names over `-T json`:
One can follow the [reference](https://www.wireshark.org/docs/dfref/) here.

```bash
tshark -r <file> -T fields -E separator=/t \
  -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.flags ...
```

It also allows peeking into all the layers of the packet. 

```bash
tshark -r <file> -T fields -e sll.etype -e frame.protocols -c 1
# Let output: 0x0800 sll:ethertype:ip:tcp:ssh
# ethertype is pseudotype.
# Then:
tshark -r <file> -T fields -E separator=/t -e sll.etype -e ip.src -c 1
# SLL Layer 2 and IPv4 Layer 3
```

First we'll need to find all the PCAP files. They follow two main patterns.
  1. They have "pcap" extension.
  2. They are "snort" logs.

The two datasets are:
  - https://www.kaggle.com/datasets/olaidegabriel/attack-scenario-dataset-in-pcap-format
  - https://www.netresec.com/?page=PcapFiles (Hands-on Network Forensics - Training PCAP dataset from FIRST 2015)

After gathering all the files we want to look one that has data appropriate to test
the program. To do that, we follow the data flow a file would follow in our program
respecting the control flow. 

We start with `PCAP Header`.

The header is 24 bytes so we can just pick a file and

```bash
xxd -l 24 -p $filename
```

This is also going to be a test case. Does the parser extracts the right info from the file?

Then we have to follow the code. Let's start with SLL.
In `linux_sll.rs` we can see the only thing that matters for control flow is the protocol type.

So for a file having SLL we must create a test verifying the fields and then we can use 
`sll.etype` to see what other test can be derived from the file we're checking.
SLL passes control to either IPv4, or IPv6, or ARP packet. IPv4 passes control to TCP, UDP etc.
