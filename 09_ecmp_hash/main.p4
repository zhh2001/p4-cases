/* -*- P4_16 -*- */
/*
 * Case 09: ECMP (equal-cost multi-path) via hash selection.
 *
 * The ingress pipeline does a per-flow 5-tuple hash and uses the
 * result to pick one of N next-hops installed by the controller. A
 * single flow (same src/dst IP + same ports) always lands on the same
 * next-hop; different flows spread across the ecmp group.
 *
 * Data-plane structure:
 *
 *   ipv4_lpm (dst IP)  --+-- ecmp_group(ecmp_base, ecmp_count) ----.
 *                        |        ^                                 |
 *                        |        | (hash ingress on 5-tuple)       v
 *                        |        |                        ecmp_nhop(idx)
 *                        +--- forward(port) ---> direct hop (non-ECMP)
 */

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

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

struct metadata {
    bit<14> ecmp_select;
}

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

    action drop() { mark_to_drop(standard_metadata); }

    action set_nhop(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    // Picks one of ecmp_count ECMP members. ecmp_base + hash % ecmp_count
    // is used as the key into ecmp_nhop.
    action set_ecmp_select(bit<14> ecmp_base, bit<14> ecmp_count) {
        hash(meta.ecmp_select,
             HashAlgorithm.crc16,
             ecmp_base,
             { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr,
               hdr.ipv4.protocol, hdr.udp.srcPort, hdr.udp.dstPort },
             ecmp_count);
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { set_ecmp_select; set_nhop; drop; NoAction; }
        size = 1024;
        default_action = drop;
    }

    table ecmp_nhop {
        key = { meta.ecmp_select: exact; }
        actions = { set_nhop; drop; }
        size = 256;
        default_action = drop;
    }

    apply {
        if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 0) {
            switch (ipv4_lpm.apply().action_run) {
                set_ecmp_select: { ecmp_nhop.apply(); }
            }
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) { apply {} }

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv,
              hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags,
              hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol,
              hdr.ipv4.srcAddr, hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

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
