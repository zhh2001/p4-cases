#include <core.p4>
#include <v1model.p4>

typedef bit<48> macAddr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

struct metadata {}

struct headers {
    ethernet_t ethernet;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start{
        packet.extract(hdr.ethernet);
        transition accept;
    }

}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action swap_mac() {
        // 交换目的 MAC 地址和源 MAC 地址
        macAddr_t tmpAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = tmpAddr;
    }

    action set_egress_spec() {
        // 设置转发端口为接收到数据包的端口
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    apply {
        swap_mac();
        set_egress_spec();
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // 已解析的报头必须再次添加到数据包中
        packet.emit(hdr.ethernet);
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
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
