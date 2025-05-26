#include <core.p4>
#include <v1model.p4>

const bit<16> L2_LEARN_ETHER_TYPE = 16w0x1234;

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_t {
    macAddr_t srcAddr;
    bit<16>   ingress_port;
}

struct metadata {
    @field_list(0)
    port_t ingress_port;
}

struct headers {
    ethernet_t ethernet;
    cpu_t      cpu;
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

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action mac_learn() {
        meta.ingress_port = standard_metadata.ingress_port;
        clone_preserving_field_list(CloneType.I2E, 100, 0);
    }

    table smac {
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        actions = {
            mac_learn;
            NoAction;
        }
        size = 256;
        default_action = mac_learn;
    }

    action forward(port_t egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    table dmac {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            forward;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    action set_mcast_grp(bit<16> mcast_grp) {
        standard_metadata.mcast_grp = mcast_grp;
    }

    table broadcast {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            set_mcast_grp;
            NoAction;
        }
        size = 256;
        default_action = NoAction;
    }

    apply {
        smac.apply();
        if (!dmac.apply().hit){
            broadcast.apply();
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        // 入口克隆
        if (standard_metadata.instance_type == 1){
            hdr.cpu.setValid();
            hdr.cpu.srcAddr = hdr.ethernet.srcAddr;
            hdr.cpu.ingress_port = (bit<16>)meta.ingress_port;
            hdr.ethernet.etherType = L2_LEARN_ETHER_TYPE;
            truncate((bit<32>)22); // ether + cpu 报头
        }
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // 已解析的标头必须再次添加到数据包中
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu);
    }
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
