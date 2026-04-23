/* -*- P4_16 -*- */
/*
 * Case 13: Clone to CPU.
 *
 * The normal data-plane path cross-forwards h1 <-> h2 just like case
 * 02. In addition, every packet is cloned to a dedicated "CPU port"
 * that BMv2's simple_switch_grpc exposes as the P4Runtime PacketIn
 * channel. The egress pipeline recognises the clone (by checking
 * standard_metadata.instance_type) and rewrites the Ethernet header
 * into a trivial "CPU header" carrying the original ingress_port
 * before handing it to the controller.
 *
 * The controller subscribes via Client.OnPacketIn and receives every
 * packet that flies through.
 */

#include <core.p4>
#include <v1model.p4>

const bit<32> CPU_CLONE_SESSION_ID = 99;
const bit<16> ETHERTYPE_CPU = 0x1010;   // arbitrary, for easy recognition

typedef bit<48> macAddr_t;
typedef bit<9>  port_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_t {
    bit<16> ingress_port;   // padded up to 16 bits for alignment
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

control MyVerifyChecksum(inout headers hdr, inout metadata meta) { apply {} }

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    apply {
        // Remember ingress port in user-metadata so the egress stage
        // can rebuild the CPU header on the clone.
        meta.ingress_port = standard_metadata.ingress_port;

        // Plain 1 <-> 2 forward for inline traffic.
        if (standard_metadata.ingress_port == 1) {
            standard_metadata.egress_spec = 2;
        } else if (standard_metadata.ingress_port == 2) {
            standard_metadata.egress_spec = 1;
        } else {
            mark_to_drop(standard_metadata);
            return;
        }

        // Clone every packet to the CPU session. The controller
        // programmed this session via P4Runtime to land on BMv2's
        // --cpu-port (510), which becomes the PacketIn channel.
        clone_preserving_field_list(CloneType.I2E, CPU_CLONE_SESSION_ID, 0);
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {
        // instance_type == 1 -> this is a cloned copy produced by I2E.
        if (standard_metadata.instance_type == 1) {
            hdr.cpu.setValid();
            hdr.cpu.ingress_port   = (bit<16>)meta.ingress_port;
            hdr.ethernet.etherType = ETHERTYPE_CPU;
            // Keep payload as-is; controller will see:
            //   outer_eth (src/dst preserved, ethType=0x1010)
            //   cpu_t     (2 bytes: ingress_port)
            //   original payload
        }
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) { apply {} }

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu);
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
