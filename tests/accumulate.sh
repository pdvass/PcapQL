#! /usr/bin/env bash

DATA_DIR="../data"
mapfile -d '' FILE_ARRAY < <(find "$DATA_DIR" -type f \( -name "*.pcap" -o -name "*snort*" \) -print0)

# TSV file containing File path and values that should be tested.
mkdir -p "./cases"
CASES_DIR="./cases"

echo "${#FILE_ARRAY[@]} files"

# Finds the first packet, across the whole corpus, matching a tshark display
# filter. Writes the matching file's path into $1 and the 0-based packet
# index (i.e. how many packets nth_frame must skip to reach it) into $2.
find_first () {
    # https://ss64.com/bash/local.html
    # "The option can be any of the options accepted by declare."
    # https://ss64.com/bash/declare.html
    # -n
    local -n file_ref="$1"
    local -n frame_ref="$2"
    # tshark can recieve any depth of filter. From "ip" to "ip.df".
    # We leverage that, to create different kind of test cases.
    local filter="$3"
    for file in "${FILE_ARRAY[@]}"; do
        local frame_num
        # -c 1: stop as soon as one match is found, since we only
        # need one packet to test the parser.
        frame_num=$(tshark -r "$file" -Y "$filter" -c 1 \
            -T fields -e frame.number 2>/dev/null | head -n1)
        if [ -n "$frame_num" ]; then
            file_ref="$file"
            frame_ref=$((frame_num - 1))
            return 0
        fi
    done
    return 1
}

# tshark fields can legitimately be empty (e.g. igmp.max_resp on a V3
# report).
# This is going to be used for Internal Field Separator ( IFS ).
FIELD_SEP=,


write_linktype_and_magic_number_test_case () {
    f="$CASES_DIR/linktype_and_magic_number_test_case.tsv"
    touch $f
    # Take 24 octets, fold per 2 chars (1 octet), reverse order, delete newlines.
    local header_string=$(xxd -l 24 -p $1 | fold -w2 | tail -r | tr -d "\n")

    # ${string:position:length}
    # We care about the magic number and linktype
    # HEX to INT
    # Deduced from here:
    # https://unix.stackexchange.com/questions/155085/fetching-individual-bytes-from-a-binary-file-into-a-variable-with-bash
    local linktype=$((16#${header_string:4:4}))
    local magic_number="${header_string:40:8}"
    # 0 indicates how many packets the test should skip.
    # In later tests, this is going to be named "found_frame".
    printf '%s\t%s\t%s\t0\n' "$1" "$linktype" "$magic_number" > $f
}

write_sll_packet_test_case () {
    local f="$CASES_DIR/sll_packet_test_case.tsv"
    local found_file found_frame
    if ! find_first found_file found_frame "sll"; then
        echo "sll_packet_test_case: no SLL packet found in corpus, skipping" >&2
        return 1
    fi
    IFS="$FIELD_SEP" read -r packet_type link_layer_addr_len protocol_type \
            < <(tshark -r "$found_file" -T fields -E "separator=$FIELD_SEP" \
                 -e sll.pkttype -e sll.halen -e sll.etype)
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$found_file" "$packet_type" "$link_layer_addr_len" "$protocol_type" "$found_frame" > $f
}

# Later I might add different option types, like F, DF etc.
# This applies to all protocols that have options.
write_ipv4_test_case () {
    local f="$CASES_DIR/ipv4_test_case.tsv"
    local found_file found_frame
    if ! find_first found_file found_frame "ip"; then
        echo "ipv4_test_case: no IPv4 packet found in corpus, skipping" >&2
        return 1
    fi
    IFS="$FIELD_SEP" read -r dscp ecn len flag offset ttl protocol checksum src_ip dst_ip \
    < <(tshark -r "$found_file" -T fields -E "separator=$FIELD_SEP" \
         -e ip.dsfield.dscp -e ip.dsfield.ecn\
         -e ip.len -e ip.flags -e ip.frag_offset -e ip.ttl -e ip.proto\
         -e ip.checksum -e ip.src -e ip.dst)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$found_file" "$dscp" "$ecn" "$len" "$flag" "$offset" "$ttl" "$protocol"\
        "$checksum" "$src_ip" "$dst_ip" "$found_frame" > $f
}

write_tcp_test_case () {
    local f="$CASES_DIR/tcp_test_case.tsv"
    local found_file found_frame
    if ! find_first found_file found_frame "tcp"; then
        echo "tcp_test_case: no TCP packet found in corpus, skipping" >&2
        return 1
    fi
    IFS="$FIELD_SEP" read -r srcport dstport seq ack flags window checksum urgptr \
    < <(tshark -r "$found_file" -T fields -E "separator=$FIELD_SEP" \
         -e tcp.srcport -e tcp.dstport -e tcp.seq_raw -e tcp.ack_raw \
         -e tcp.flags -e tcp.window_size_value -e tcp.checksum -e tcp.urgent_pointer)
    # tcp.flags is 12 bits: high nibble is reserved+NS (byte 12, low 4 bits —
    # separate from our Flags struct entirely, see TCPPacket.reserved in
    # tcp.rs), low byte is CWR..FIN (byte 13, exactly our Flags struct, one
    # bit each). Mask down to that low byte to compare against Flags.
    flags=$(printf '0x%02x' $((flags & 0xFF)))
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$found_file" "$srcport" "$dstport" "$seq" "$ack" "$flags" "$window" "$checksum" "$urgptr" "$found_frame" > $f
}

write_udp_test_case () {
    local f="$CASES_DIR/udp_test_case.tsv"
    local found_file found_frame
    if ! find_first found_file found_frame "udp"; then
        echo "udp_test_case: no UDP packet found in corpus, skipping" >&2
        return 1
    fi
    IFS="$FIELD_SEP" read -r srcport dstport length checksum \
    < <(tshark -r "$found_file" -T fields -E "separator=$FIELD_SEP" \
         -e udp.srcport -e udp.dstport -e udp.length -e udp.checksum)
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$found_file" "$srcport" "$dstport" "$length" "$checksum" "$found_frame" > $f
}

write_icmp_test_case () {
    local f="$CASES_DIR/icmp_test_case.tsv"
    local found_file found_frame
    if ! find_first found_file found_frame "icmp"; then
        echo "icmp_test_case: no ICMP packet found in corpus, skipping" >&2
        return 1
    fi
    IFS="$FIELD_SEP" read -r icmp_type code checksum \
    < <(tshark -r "$found_file" -T fields -E "separator=$FIELD_SEP" \
         -e icmp.type -e icmp.code -e icmp.checksum)
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$found_file" "$icmp_type" "$code" "$checksum" "$found_frame" > $f
}

write_icmpv6_test_case () {
    local f="$CASES_DIR/icmpv6_test_case.tsv"
    local found_file found_frame
    if ! find_first found_file found_frame "icmpv6"; then
        echo "icmpv6_test_case: no ICMPv6 packet found in corpus, skipping" >&2
        return 1
    fi
    IFS="$FIELD_SEP" read -r icmp_type code checksum \
    < <(tshark -r "$found_file" -T fields -E "separator=$FIELD_SEP" \
         -e icmpv6.type -e icmpv6.code -e icmpv6.checksum)
    printf '%s\t%s\t%s\t%s\t%s\n' \
        "$found_file" "$icmp_type" "$code" "$checksum" "$found_frame" > $f
}

write_igmp_test_case () {
    local f="$CASES_DIR/igmp_test_case.tsv"
    local found_file found_frame
    if ! find_first found_file found_frame "igmp"; then
        echo "igmp_test_case: no IGMP packet found in corpus, skipping" >&2
        return 1
    fi
    IFS="$FIELD_SEP" read -r igmp_type max_resp checksum group_address \
    < <(tshark -r "$found_file" -T fields -E "separator=$FIELD_SEP" \
         -e igmp.type -e igmp.max_resp -e igmp.checksum -e igmp.maddr)
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$found_file" "$igmp_type" "$max_resp" "$checksum" "$group_address" "$found_frame" > $f
}

write_ethernet_test_case () {
    local f="$CASES_DIR/ethernet_test_case.tsv"
    local found_file found_frame
    if ! find_first found_file found_frame "eth.src"; then
        echo "ethernet_test_case: no Ethernet-linktype packet found in corpus, skipping" >&2
        return 1
    fi
    IFS="$FIELD_SEP" read -r mac_dest mac_source \
    < <(tshark -r "$found_file" -T fields -E "separator=$FIELD_SEP" \
         -e eth.dst -e eth.src)
    printf '%s\t%s\t%s\t%s\n' \
        "$found_file" "$mac_dest" "$mac_source" "$found_frame" > $f
}

write_arp_test_case () {
    local f="$CASES_DIR/arp_test_case.tsv"
    local found_file found_frame
    if ! find_first found_file found_frame "arp"; then
        echo "arp_test_case: no ARP packet found in corpus, skipping" >&2
        return 1
    fi
    IFS="$FIELD_SEP" read -r hw_type proto_type hw_size proto_size opcode \
        src_mac src_ip dst_mac dst_ip \
    < <(tshark -r "$found_file" -T fields -E "separator=$FIELD_SEP" \
         -e arp.hw.type -e arp.proto.type -e arp.hw.size -e arp.proto.size \
         -e arp.opcode -e arp.src.hw_mac -e arp.src.proto_ipv4 \
         -e arp.dst.hw_mac -e arp.dst.proto_ipv4)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$found_file" "$hw_type" "$proto_type" "$hw_size" "$proto_size" "$opcode" \
        "$src_mac" "$src_ip" "$dst_mac" "$dst_ip" "$found_frame" > $f
}

write_ipv6_test_case () {
    local f="$CASES_DIR/ipv6_test_case.tsv"
    local found_file found_frame
    if ! find_first found_file found_frame "ipv6"; then
        echo "ipv6_test_case: no IPv6 packet found in corpus, skipping" >&2
        return 1
    fi
    IFS="$FIELD_SEP" read -r version tclass flow plen nxt hlim src dst \
    < <(tshark -r "$found_file" -T fields -E "separator=$FIELD_SEP" \
         -e ipv6.version -e ipv6.tclass -e ipv6.flow -e ipv6.plen \
         -e ipv6.nxt -e ipv6.hlim -e ipv6.src -e ipv6.dst)
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$found_file" "$version" "$tclass" "$flow" "$plen" "$nxt" "$hlim" "$src" "$dst" "$found_frame" > $f
}

write_linktype_and_magic_number_test_case ${FILE_ARRAY[0]}
write_sll_packet_test_case
write_ipv4_test_case
write_tcp_test_case
write_udp_test_case
write_icmp_test_case
write_icmpv6_test_case
write_igmp_test_case
write_ethernet_test_case
write_arp_test_case
write_ipv6_test_case
