/* -*- P4_16 -*- */
/*
 * Case 11: VXLAN encapsulation.
 *
 * Two hosts on one switch (h1 port 1, h2 port 2). h1 sends a plain
 * Ethernet frame addressed to an inner MAC 00:00:00:11:11:11. The
 * ingress vtep table matches on that inner MAC and wraps the whole
 * frame in Outer-Eth / Outer-IP / UDP / VXLAN(VNI=5000) headers
 * before forwarding it to h2's port. h2 receives the wrapped packet,
 * scapy confirms the VXLAN header, VNI, and inner destination MAC.
 */

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4  = 0x0800;
const bit<8>  PROTO_UDP  = 17;
const bit<16> VXLAN_PORT = 4789;

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

header vxlan_t {
    bit<8>  flags;
    bit<24> reserved;
    bit<24> vni;
    bit<8>  reserved2;
}

struct metadata {}

struct headers {
    // Outer stack is inserted on encap.
    ethernet_t outer_eth;
    ipv4_t     outer_ipv4;
    udp_t      outer_udp;
    vxlan_t    vxlan;
    // Inner Ethernet = what h1 sent.
    ethernet_t inner_eth;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.inner_eth);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply {} }

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() { mark_to_drop(standard_metadata); }

    action encap(bit<9> egress_port,
                 macAddr_t outer_dmac,
                 macAddr_t outer_smac,
                 ip4Addr_t outer_sip,
                 ip4Addr_t outer_dip,
                 bit<24>   vni) {
        standard_metadata.egress_spec = egress_port;

        hdr.outer_eth.setValid();
        hdr.outer_eth.dstAddr   = outer_dmac;
        hdr.outer_eth.srcAddr   = outer_smac;
        hdr.outer_eth.etherType = TYPE_IPV4;

        hdr.outer_ipv4.setValid();
        hdr.outer_ipv4.version        = 4;
        hdr.outer_ipv4.ihl            = 5;
        hdr.outer_ipv4.diffserv       = 0;
        hdr.outer_ipv4.totalLen       = 50;   // 20+8+8 + 14 inner eth
        hdr.outer_ipv4.identification = 0;
        hdr.outer_ipv4.flags          = 0;
        hdr.outer_ipv4.fragOffset     = 0;
        hdr.outer_ipv4.ttl            = 64;
        hdr.outer_ipv4.protocol       = PROTO_UDP;
        hdr.outer_ipv4.hdrChecksum    = 0;
        hdr.outer_ipv4.srcAddr        = outer_sip;
        hdr.outer_ipv4.dstAddr        = outer_dip;

        hdr.outer_udp.setValid();
        hdr.outer_udp.srcPort  = 12345;
        hdr.outer_udp.dstPort  = VXLAN_PORT;
        hdr.outer_udp.length_  = 30;  // 8+8 + 14 inner eth
        hdr.outer_udp.checksum = 0;

        hdr.vxlan.setValid();
        hdr.vxlan.flags     = 0x08;   // I flag
        hdr.vxlan.reserved  = 0;
        hdr.vxlan.vni       = vni;
        hdr.vxlan.reserved2 = 0;
    }

    action forward_plain(bit<9> egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    table vtep {
        key     = { hdr.inner_eth.dstAddr: exact; }
        actions = { encap; forward_plain; drop; NoAction; }
        size    = 256;
        default_action = NoAction;
    }

    apply {
        vtep.apply();
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) { apply {} }

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.outer_ipv4.isValid(),
            { hdr.outer_ipv4.version, hdr.outer_ipv4.ihl, hdr.outer_ipv4.diffserv,
              hdr.outer_ipv4.totalLen, hdr.outer_ipv4.identification, hdr.outer_ipv4.flags,
              hdr.outer_ipv4.fragOffset, hdr.outer_ipv4.ttl, hdr.outer_ipv4.protocol,
              hdr.outer_ipv4.srcAddr, hdr.outer_ipv4.dstAddr },
            hdr.outer_ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.outer_eth);
        packet.emit(hdr.outer_ipv4);
        packet.emit(hdr.outer_udp);
        packet.emit(hdr.vxlan);
        packet.emit(hdr.inner_eth);
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
