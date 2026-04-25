/* -*- P4_16 -*- */
/*
 * Case 14: IPv6 LPM routing.
 *
 * Single-stage IPv6 router. The match-action table `ipv6_lpm` keys on
 * `hdr.ipv6.dstAddr` with LPM (longest-prefix-match) — the same kind
 * of lookup a real router does on the FIB. The matching action is
 * `ipv6_forward(dstMac, port)`, which:
 *
 *   - decrements hopLimit (with a runtime check: 0 -> drop)
 *   - rewrites ethernet.srcAddr with the previous dstAddr (the router
 *     "owns" that gateway MAC, so on the way out it becomes the src)
 *   - rewrites ethernet.dstAddr with the next-hop MAC the controller
 *     installed alongside the prefix
 *   - sets egress_spec to the egress port for that next hop
 *
 * Why LPM matters here: with IPv4 you most often see /24 or /32 in
 * teaching examples, so the "longest prefix wins" logic is easy to
 * mentally simulate. With IPv6 the prefix-match width balloons to 128
 * bits, which forces P4's match engine to be parametric in width —
 * the same `lpm` keyword works unchanged. The controller installs:
 *
 *     2001:db8:1::/64  -> port 1, h1
 *     2001:db8:2::/64  -> port 2, h2
 *     2001:db8:3::/64  -> port 3, h3
 *     2001:db8:3::1/128 -> port 3, h3   (same destination, longer prefix)
 *
 * The /128 is redundant in next-hop terms but exercises the "longer
 * prefix takes precedence" rule — a packet to 2001:db8:3::1 hits the
 * /128, packets to any other 2001:db8:3::/64 host hit the /64.
 */

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV6 = 0x86dd;

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
        if (hdr.ipv6.isValid() && hdr.ipv6.hopLimit > 1) {
            ipv6_lpm.apply();
        } else if (hdr.ipv6.isValid()) {
            // hopLimit == 0 or 1 -> would underflow on decrement. drop.
            drop();
        }
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
