/* -*- P4_16 -*- */
/*
 * Case 09: ECMP (equal-cost multi-path) via hash selection.
 *
 * The ingress pipeline does a per-flow 5-tuple hash and uses the
 * result to pick one of N next-hops installed by the controller. A
 * single TCP or UDP flow always lands on the same next-hop. IPv4
 * fragments and other protocols use zero ports in the hash input.
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

error {
    InvalidIPv4Version,
    InvalidIPv4Length,
    InvalidTransportLength
}

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

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  reserved;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header ipv4_options_t {
    varbit<320> data;
}

struct metadata {
    bit<14> ecmp_select;
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> transport_length;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    ipv4_options_t options;
    udp_t      udp;
    tcp_t      tcp;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        meta.src_port = 0;
        meta.dst_port = 0;
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default:   accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        verify(hdr.ipv4.version == 4, error.InvalidIPv4Version);
        verify(hdr.ipv4.ihl >= 5, error.InvalidIPv4Length);
        verify(hdr.ipv4.totalLen >= (bit<16>)hdr.ipv4.ihl * 4,
               error.InvalidIPv4Length);
        verify((bit<32>)hdr.ipv4.totalLen <= standard_metadata.packet_length - 14,
               error.InvalidIPv4Length);
        meta.transport_length = hdr.ipv4.totalLen - (bit<16>)hdr.ipv4.ihl * 4;
        transition select(hdr.ipv4.ihl) {
            5:       parse_fragment;
            default: parse_options;
        }
    }
    state parse_options {
        packet.extract(hdr.options, ((bit<32>)hdr.ipv4.ihl - 5) * 32);
        transition parse_fragment;
    }
    state parse_fragment {
        // All fragments, including the first, keep zero transport ports.
        transition select(hdr.ipv4.flags[0:0], hdr.ipv4.fragOffset) {
            (0, 0):  parse_protocol;
            default: accept;
        }
    }
    state parse_protocol {
        transition select(hdr.ipv4.protocol) {
            6:       parse_tcp;
            17:      parse_udp;
            default: accept;
        }
    }
    state parse_udp {
        verify(meta.transport_length >= 8, error.InvalidTransportLength);
        packet.extract(hdr.udp);
        verify(hdr.udp.length_ >= 8 && hdr.udp.length_ <= meta.transport_length,
               error.InvalidTransportLength);
        meta.src_port = hdr.udp.srcPort;
        meta.dst_port = hdr.udp.dstPort;
        transition accept;
    }
    state parse_tcp {
        verify(meta.transport_length >= 20, error.InvalidTransportLength);
        packet.extract(hdr.tcp);
        verify(hdr.tcp.dataOffset >= 5 &&
               (bit<16>)hdr.tcp.dataOffset * 4 <= meta.transport_length,
               error.InvalidTransportLength);
        meta.src_port = hdr.tcp.srcPort;
        meta.dst_port = hdr.tcp.dstPort;
        transition accept;
    }
}

#define IPV4_FIELDS \
    hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.diffserv, \
    hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, \
    hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, \
    hdr.ipv4.srcAddr, hdr.ipv4.dstAddr

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(hdr.ipv4.isValid() && !hdr.options.isValid(),
                        { IPV4_FIELDS }, hdr.ipv4.hdrChecksum,
                        HashAlgorithm.csum16);
        verify_checksum(hdr.ipv4.isValid() && hdr.options.isValid(),
                        { IPV4_FIELDS, hdr.options.data }, hdr.ipv4.hdrChecksum,
                        HashAlgorithm.csum16);
    }
}

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
             {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                hdr.ipv4.protocol,
                meta.src_port,
                meta.dst_port
             },
             ecmp_count);
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            set_ecmp_select;
            set_nhop;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop;
    }

    table ecmp_nhop {
        key = {
            meta.ecmp_select: exact;
        }
        actions = {
            set_nhop;
            drop;
        }
        size = 256;
        default_action = drop;
    }

    apply {
        if (standard_metadata.parser_error != error.NoError ||
            standard_metadata.checksum_error == 1 ||
            !hdr.ipv4.isValid() || hdr.ipv4.ttl <= 1) {
            drop();
            return;
        }
        switch (ipv4_lpm.apply().action_run) {
            set_ecmp_select: { ecmp_nhop.apply(); }
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) { apply {} }

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(hdr.ipv4.isValid() && !hdr.options.isValid(),
                        { IPV4_FIELDS }, hdr.ipv4.hdrChecksum,
                        HashAlgorithm.csum16);
        update_checksum(hdr.ipv4.isValid() && hdr.options.isValid(),
                        { IPV4_FIELDS, hdr.options.data }, hdr.ipv4.hdrChecksum,
                        HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.options);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
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
