# Design

## Parser

The parser leverages the way packets are encapsulated through different layers.

```
+----------------------------------------------------------------+
| Data Link Header | Network Header | Transport Header | Payload |
+----------------------------------------------------------------+
```

It uses a lightweight wrapper `Cursor` which encapsulates the byte array of the file. This way one
can read arbitrary bytes, and not resort to u8, u16, u32, u64 and later do bit manipulation.
Each sub-parser also exists in the appropriate folder corresponding to its Layer in OSI model.

`Cursor` implements Iterator pattern through the `PacketIter`, to iterate over each packet
separately.

It only exposes `parse_pcap`, `parse_packet`, and the struct and enums used to depict 
network protocols and their fields inside a frame.

Frame follows that encapsulation since `Frame` can have `Ethernet` or `SLL` frame which contain
a `NetworkPacket` ( IPv4, IPv6, ARP ), which contain a `TransportPacket` ( TCP, UDP ) ending
with a `Payload`.

After seeing all possible Protocols, EthTypes, PCAP Header types etc I decided that anything missing
should be added on demand. To make any need for another protocol support apparent and non-avoidable
I decided the parser should panic.

## Testing

Using `tshark`'s capabilities `accumulate.sh` reads the files from the dataset and finds files
that satisfy the filters. The filters are selected based on what the parser should parse. 

This way test cases can be generated independently from the dataset one has. 

Will be changed to lua or python script to be OS-agnostic.
