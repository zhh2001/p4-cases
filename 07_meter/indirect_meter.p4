/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<48> macAddr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

struct metadata {
    bit<32> meter_tag;
}

struct headers {
    ethernet_t ethernet;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr,
                         inout metadata meta) {
    apply {

    }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    meter(32w8192, MeterType.packets) my_meter;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action m_action(bit<32> meter_index) {
        my_meter.execute_meter<bit<32>>(meter_index, meta.meter_tag);
    }

    table m_read {
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        actions = {
            m_action;
            NoAction;
        }
        default_action = NoAction;
        size = 8192;
    }

    table m_filter {
        key = {
            meta.meter_tag: exact;
        }
        actions = {
            drop;
            NoAction;
        }
        default_action = drop;
        size = 128;
    }

    apply {
        standard_metadata.egress_spec = 2;
        m_read.apply();
        m_filter.apply();
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {

    }
}

control MyComputeChecksum(inout headers hdr,
                          inout metadata meta) {
    apply {

    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
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