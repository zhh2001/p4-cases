#include <core.p4>
#include <v1model.p4>

#define MAX_INT_HEADERS 9

const bit<16> TYPE_IPV4       = 16w0x0800;
const bit<5>  IPV4_OPTION_INT = 5w31;

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

typedef bit<13> switch_id_t;
typedef bit<13> queue_depth_t;
typedef bit<6>  output_port_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    dscp;
    bit<2>    ecn;
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
    switch_id_t   switch_id;
    queue_depth_t queue_depth;
    output_port_t output_port;
}

struct parser_metadata_t {
    bit<16> num_headers_remaining;
}

struct metadata {
    parser_metadata_t parser_metadata;
}

struct headers {
    ethernet_t    ethernet;
    ipv4_t        ipv4;
    ipv4_option_t ipv4_option;
    int_count_t   int_count;
    int_header_t[MAX_INT_HEADERS] int_headers;
}

error {
    IPHeaderWithoutOptions
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        // 检查 ihl 是否大于 5。没有 ip options 的数据包将 ihl 设置为 5
        verify(hdr.ipv4.ihl >= 5, error.IPHeaderWithoutOptions);
        transition select(hdr.ipv4.ihl) {
            5:       accept;
            default: parse_ipv4_option;
        }
    }

    state parse_ipv4_option {
        packet.extract(hdr.ipv4_option);
        transition select(hdr.ipv4_option.option){
            IPV4_OPTION_INT: parse_int;
            default:         accept;
        }
     }

    state parse_int {
        packet.extract(hdr.int_count);
        meta.parser_metadata.num_headers_remaining = hdr.int_count.num_switches;
        transition select(meta.parser_metadata.num_headers_remaining){
            0: accept;
            default: parse_int_headers;
        }
    }

    state parse_int_headers {
        packet.extract(hdr.int_headers.next);
        meta.parser_metadata.num_headers_remaining = meta.parser_metadata.num_headers_remaining -1 ;
        transition select(meta.parser_metadata.num_headers_remaining){
            0: accept;
            default: parse_int_headers;
        }
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
        hdr.ipv4.ttl = hdr.ipv4.ttl -1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        // 仅当 IPV4 时，该规则才会应用。因此其他数据包将不会被转发。
        if (hdr.ipv4.isValid()){
            ipv4_lpm.apply();
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    action add_int_header(switch_id_t swid){
        // 将 INT 堆栈计数器增加 1
        hdr.int_count.num_switches = hdr.int_count.num_switches + 1;

        hdr.int_headers.push_front(1);
        // This was not needed in older specs. Now by default pushed
        // invalid elements are
        hdr.int_headers[0].setValid();
        hdr.int_headers[0].switch_id = (bit<13>)swid;
        hdr.int_headers[0].queue_depth = (bit<13>)standard_metadata.deq_qdepth;
        hdr.int_headers[0].output_port = (bit<6>)standard_metadata.egress_port;

        // 更新 IP 报头长度
        hdr.ipv4.ihl = hdr.ipv4.ihl + 1;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 4;
        hdr.ipv4_option.optionLength = hdr.ipv4_option.optionLength + 4;
    }

    table int_table {
        actions = {
            add_int_header;
            NoAction;
        }
        default_action = NoAction();
    }

    apply {
        if (hdr.int_count.isValid()){
            int_table.apply();
        }
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        // 已解析的标头必须再次添加到数据包中
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv4_option);
        packet.emit(hdr.int_count);
        packet.emit(hdr.int_headers);
    }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.dscp,
                hdr.ipv4.ecn,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
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
