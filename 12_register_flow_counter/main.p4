/* -*- P4_16 -*- */
/*
 * Case 12: Per-flow packet counter stored in a P4 register.
 *
 * Every IPv4/UDP packet:
 *   1. Hash (srcIP, dstIP, srcPort, dstPort) into a 10-bit slot.
 *   2. Read register[slot], add 1, write back.
 *   3. Cross-forward 1<->2 so scapy can observe flows on the peer.
 *
 * The controller reads back the register to demonstrate how user-
 * controlled state in P4 is accessible via P4Runtime RegisterEntry
 * (counter extern would be the conventional choice for this; the
 * point of this case is to show the register-as-user-state pattern).
 */

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<10> slot_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

struct metadata {}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    udp_t      udp;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default:   accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17:      parse_udp;
            default: accept;
        }
    }
    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply {} }

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // 1024-slot register array of 32-bit packet counters.
    register<bit<32>>(1024) flow_counter;

    apply {
        // Cross-forward like Case 02.
        if (standard_metadata.ingress_port == 1) {
            standard_metadata.egress_spec = 2;
        } else if (standard_metadata.ingress_port == 2) {
            standard_metadata.egress_spec = 1;
        } else {
            mark_to_drop(standard_metadata);
            return;
        }

        if (hdr.udp.isValid()) {
            slot_t slot;
            // `max` must use a type wider than slot_t (bit<10>) because
            // 1024 would wrap to 0 in a 10-bit value.
            hash(slot, HashAlgorithm.crc16, (bit<16>)0,
                 { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr,
                   hdr.udp.srcPort,  hdr.udp.dstPort },
                 (bit<16>)1024);

            bit<32> current;
            flow_counter.read(current, (bit<32>)slot);
            current = current + 1;
            flow_counter.write((bit<32>)slot, current);
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) { apply {} }

control MyComputeChecksum(inout headers hdr, inout metadata meta) { apply {} }

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
    }
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
