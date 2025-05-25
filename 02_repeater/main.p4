#include <core.p4>
#include <v1model.p4>

typedef bit<32> ipv4Addr_t;
typedef bit<48> macAddr_t;

header ipv4_t {
    bit<4>     version;
    bit<4>     internetHeaderLength;
    bit<8>     diffserv;
    bit<16>    totalLength;
    bit<16>    identification;
    bit<3>     flags;
    bit<13>    fragmentOffset;
    bit<8>     timeToLive;
    bit<8>     protocol;
    bit<16>    headerChecksum;
    ipv4Addr_t srcAddr;
    ipv4Addr_t dstAddr;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

struct metadata {}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition accept;
    }

}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    table my_table {
        actions = {
            NoAction;
        }
    }

    apply {
        my_table.apply();
        if (standard_metadata.ingress_port == 1) {
            standard_metadata.egress_spec = 2;
        }
        else if (standard_metadata.ingress_port == 2) {
            standard_metadata.egress_spec = 1;
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {}
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {}
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
