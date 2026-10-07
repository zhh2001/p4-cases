/* -*- P4_16 -*- */
/*
 * Case 14: IPv6 LPM routing.
 *
 * Match destination addresses by longest prefix, rewrite both MACs
 * and decrement hopLimit once. Drop parser errors, non-IPv6 frames,
 * expired packets and destinations without a route.
 *
 * The controller installs:
 *
 *     2001:db8:1::/64  -> port 1, h1
 *     2001:db8:2::/64  -> port 2, h2
 *     2001:db8:3::/64  -> port 3, h3
 *     2001:db8:3::42/128 -> port 2, h2
 *
 * The /128 uses a different next hop, so its precedence is observable.
 * Other destinations in 2001:db8:3::/64, including h3, use port 3.
 * Extension headers and transport data remain in the unparsed payload.
 */

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV6 = 0x86dd;

error {
    InvalidIPv6Version,
    InvalidIPv6Length
}

typedef bit<9>   egressSpec_t;
typedef bit<48>  macAddr_t;
typedef bit<128> ip6Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv6_t {
    bit<4>    version;
    bit<8>    trafficClass;
    bit<20>   flowLabel;
    bit<16>   payloadLen;
    bit<8>    nextHdr;
    bit<8>    hopLimit;
    ip6Addr_t srcAddr;
    ip6Addr_t dstAddr;
}

struct metadata {}

struct headers {
    ethernet_t ethernet;
    ipv6_t     ipv6;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV6: parse_ipv6;
            default:   accept;
        }
    }
    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        verify(hdr.ipv6.version == 6, error.InvalidIPv6Version);
        verify((bit<32>)hdr.ipv6.payloadLen <= standard_metadata.packet_length - 54,
               error.InvalidIPv6Length);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply {} }

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() { mark_to_drop(standard_metadata); }

    action ipv6_forward(macAddr_t dstMac, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        // The arriving dstAddr is the router's gateway MAC for that
        // ingress; reuse it as the src for the rewritten frame.
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstMac;
        hdr.ipv6.hopLimit    = hdr.ipv6.hopLimit - 1;
    }

    table ipv6_lpm {
        key     = { hdr.ipv6.dstAddr: lpm; }
        actions = { ipv6_forward; drop; NoAction; }
        size    = 1024;
        default_action = drop;
    }

    apply {
        if (standard_metadata.parser_error != error.NoError ||
            !hdr.ipv6.isValid()) {
            drop();
            return;
        }
        if (hdr.ipv6.hopLimit <= 1) {
            drop();
            return;
        }
        ipv6_lpm.apply();
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) { apply {} }

// IPv6 has no header checksum, so this is a no-op.
control MyComputeChecksum(inout headers hdr, inout metadata meta) { apply {} }

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
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
