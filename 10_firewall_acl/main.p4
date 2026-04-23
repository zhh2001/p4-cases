/* -*- P4_16 -*- */
/*
 * Case 10: Firewall ACL.
 *
 * Pipeline does a simple L2 forward (like Case 03) then applies a
 * TERNARY acl table keyed on (srcIP, dstIP, ipProto, dstPort). The
 * first matching entry wins; entries have a priority, so specific
 * rules can override generic ones (typical firewall semantics).
 *
 * An ACL entry's action is either `allow` (no-op) or `deny` (drop).
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

// We need dst port for both TCP and UDP. Both protocols start with
// (srcPort, dstPort), so we parse a single L4-common header.
header l4_ports_t {
    bit<16> srcPort;
    bit<16> dstPort;
}

struct metadata {}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    l4_ports_t l4;
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
            6:       parse_l4;   // TCP
            17:      parse_l4;   // UDP
            default: accept;
        }
    }
    state parse_l4 {
        packet.extract(hdr.l4);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply {} }

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() { mark_to_drop(standard_metadata); }

    action forward(egressSpec_t egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    table dmac {
        key     = { hdr.ethernet.dstAddr: exact; }
        actions = { forward; NoAction; }
        size    = 256;
        default_action = NoAction;
    }

    action allow() { /* no-op: leaves egress_spec as set by dmac */ }
    action deny()  { mark_to_drop(standard_metadata); }

    table acl {
        key = {
            hdr.ipv4.srcAddr:  ternary;
            hdr.ipv4.dstAddr:  ternary;
            hdr.ipv4.protocol: ternary;
            hdr.l4.dstPort:    ternary;
        }
        actions = { allow; deny; NoAction; }
        size    = 256;
        default_action = allow;   // default permit; controller installs deny rules
    }

    apply {
        if (hdr.ethernet.isValid()) {
            dmac.apply();
        }
        if (hdr.ipv4.isValid()) {
            acl.apply();
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
        packet.emit(hdr.l4);
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
