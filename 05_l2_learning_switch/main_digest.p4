#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

struct learn_t {
    macAddr_t srcAddr;
    port_t    ingress_port;
}

struct metadata {
    learn_t learn;
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

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action mac_learn() {
        meta.learn.srcAddr = hdr.ethernet.srcAddr;
        meta.learn.ingress_port = standard_metadata.ingress_port;
        digest<learn_t>(1, meta.learn);
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

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // 已解析的标头必须再次添加到数据包中
        packet.emit(hdr.ethernet);
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {}
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
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