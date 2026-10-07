#include <core.p4>
#include <v1model.p4>

#define MAX_INT_HEADERS 9

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8> IPV4_OPTION_INT = 0x1f;

typedef bit<9> egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<13> switch_id_t;
typedef bit<13> queue_depth_t;
typedef bit<6> output_port_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header ipv4_option_t {
    bit<1> copyFlag;
    bit<2> optClass;
    bit<5> option;
    bit<8> optionLength;
}

header int_count_t {
    bit<16> num_switches;
}

header int_header_t {
    switch_id_t switch_id;
    queue_depth_t queue_depth;
    output_port_t output_port;
}

header ipv4_options_t {
    varbit<320> data;
}

struct metadata {
    bit<16> remaining;
    bit<8> option_type;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    ipv4_option_t ipv4_option;
    int_count_t int_count;
    int_header_t[MAX_INT_HEADERS] int_headers;
    ipv4_options_t options;
}

error {
    InvalidIPv4Version,
    InvalidIPv4Length,
    InvalidINTLength
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
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
        transition select(hdr.ipv4.ihl) {
            5: accept;
            default: parse_option_type;
        }
    }
    state parse_option_type {
        meta.option_type = packet.lookahead<bit<8>>() & 0x7f;
        transition select(meta.option_type) {
            IPV4_OPTION_INT: parse_int_option;
            default: parse_options;
        }
    }
    state parse_options {
        packet.extract(hdr.options, ((bit<32>)hdr.ipv4.ihl - 5) * 32);
        transition accept;
    }
    state parse_int_option {
        packet.extract(hdr.ipv4_option);
        packet.extract(hdr.int_count);
        verify(hdr.int_count.num_switches <= MAX_INT_HEADERS,
               error.InvalidINTLength);
        verify(hdr.ipv4_option.optionLength == 4 + (bit<8>)hdr.int_count.num_switches * 4,
               error.InvalidINTLength);
        verify((bit<16>)hdr.ipv4_option.optionLength == ((bit<16>)hdr.ipv4.ihl - 5) * 4,
               error.InvalidINTLength);
        meta.remaining = hdr.int_count.num_switches;
        transition select(meta.remaining) {
            0: accept;
            default: parse_int_headers;
        }
    }
    state parse_int_headers {
        packet.extract(hdr.int_headers.next);
        meta.remaining = meta.remaining - 1;
        transition select(meta.remaining) {
            0: accept;
            default: parse_int_headers;
        }
    }
}

// Only the trace headers present on the wire participate in the checksum.
#define IPV4_FIELDS \
    hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.dscp, hdr.ipv4.ecn, \
    hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, \
    hdr.ipv4.fragOffset, hdr.ipv4.ttl, hdr.ipv4.protocol, \
    hdr.ipv4.srcAddr, hdr.ipv4.dstAddr
#define TRACE_FIELDS(N) \
    hdr.int_headers[N].switch_id, hdr.int_headers[N].queue_depth, \
    hdr.int_headers[N].output_port
#define INT_FIELDS_0 \
    hdr.ipv4_option.copyFlag, hdr.ipv4_option.optClass, \
    hdr.ipv4_option.option, hdr.ipv4_option.optionLength, hdr.int_count.num_switches
#define INT_FIELDS_1 INT_FIELDS_0, TRACE_FIELDS(0)
#define INT_FIELDS_2 INT_FIELDS_1, TRACE_FIELDS(1)
#define INT_FIELDS_3 INT_FIELDS_2, TRACE_FIELDS(2)
#define INT_FIELDS_4 INT_FIELDS_3, TRACE_FIELDS(3)
#define INT_FIELDS_5 INT_FIELDS_4, TRACE_FIELDS(4)
#define INT_FIELDS_6 INT_FIELDS_5, TRACE_FIELDS(5)
#define INT_FIELDS_7 INT_FIELDS_6, TRACE_FIELDS(6)
#define INT_FIELDS_8 INT_FIELDS_7, TRACE_FIELDS(7)
#define INT_FIELDS_9 INT_FIELDS_8, TRACE_FIELDS(8)
#define VERIFY_INT(N) \
    verify_checksum(hdr.int_count.isValid() && hdr.int_count.num_switches == N, \
                    { IPV4_FIELDS, INT_FIELDS_##N }, \
                    hdr.ipv4.hdrChecksum, HashAlgorithm.csum16)
#define UPDATE_INT(N) \
    update_checksum(hdr.int_count.isValid() && hdr.int_count.num_switches == N, \
                    { IPV4_FIELDS, INT_FIELDS_##N }, \
                    hdr.ipv4.hdrChecksum, HashAlgorithm.csum16)

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(hdr.ipv4.isValid() && hdr.ipv4.ihl == 5,
                        { IPV4_FIELDS }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        verify_checksum(hdr.options.isValid(),
                        { IPV4_FIELDS, hdr.options.data },
                        hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        VERIFY_INT(0);
        VERIFY_INT(1);
        VERIFY_INT(2);
        VERIFY_INT(3);
        VERIFY_INT(4);
        VERIFY_INT(5);
        VERIFY_INT(6);
        VERIFY_INT(7);
        VERIFY_INT(8);
        VERIFY_INT(9);
    }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; drop; NoAction; }
        size = 1024;
        default_action = drop();
    }
    apply {
        if (standard_metadata.parser_error != error.NoError ||
            standard_metadata.checksum_error == 1 ||
            !hdr.ipv4.isValid() || hdr.ipv4.ttl <= 1) {
            drop();
            return;
        }
        ipv4_lpm.apply();
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action add_int_header(switch_id_t swid) {
        hdr.int_headers.push_front(1);
        hdr.int_headers[0].setValid();
        hdr.int_headers[0].switch_id = swid;
        hdr.int_headers[0].queue_depth = (queue_depth_t)standard_metadata.deq_qdepth;
        hdr.int_headers[0].output_port = (output_port_t)standard_metadata.egress_port;
        hdr.int_count.num_switches = hdr.int_count.num_switches + 1;
        hdr.ipv4.ihl = hdr.ipv4.ihl + 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
        hdr.ipv4_option.optionLength = hdr.ipv4_option.optionLength + 4;
    }
    table int_table {
        actions = { add_int_header; NoAction; }
        default_action = NoAction();
    }
    apply {
        if (hdr.int_count.isValid() && hdr.int_count.num_switches < MAX_INT_HEADERS &&
            hdr.ipv4.totalLen <= 65531) {
            int_table.apply();
        }
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(hdr.ipv4.isValid() && hdr.ipv4.ihl == 5,
                        { IPV4_FIELDS }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        update_checksum(hdr.options.isValid(),
                        { IPV4_FIELDS, hdr.options.data },
                        hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
        UPDATE_INT(0);
        UPDATE_INT(1);
        UPDATE_INT(2);
        UPDATE_INT(3);
        UPDATE_INT(4);
        UPDATE_INT(5);
        UPDATE_INT(6);
        UPDATE_INT(7);
        UPDATE_INT(8);
        UPDATE_INT(9);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv4_option);
        packet.emit(hdr.int_count);
        packet.emit(hdr.int_headers);
        packet.emit(hdr.options);
    }
}

V1Switch(MyParser(), MyVerifyChecksum(), MyIngress(), MyEgress(),
         MyComputeChecksum(), MyDeparser()) main;
