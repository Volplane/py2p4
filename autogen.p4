//This is an auto_generated p4 file, do not modify it manually
#include <core.p4>
#include <v1model.p4>

typedef bit<48>  EthernetAddress;
typedef bit<32>  IPv4Address;

header ethernet_t {
    EthernetAddress dstAddr;
    EthernetAddress srcAddr;
    bit<16>         etherType;
}

header ipv4_t {
    bit<4>       version;
    bit<4>       ihl;
    bit<8>       diffserv;
    bit<16>      packet_length;
    bit<16>      identification;
    bit<3>       flags;
    bit<13>      fragOffset;
    bit<8>       ttl;
    bit<8>       protocol;
    bit<16>      hdrChecksum;
    IPv4Address  srcAddr;
    IPv4Address  dstAddr;
}

header tcp_t {
    bit<16> srcport;
    bit<16> dstport;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

// Parser section

struct Headers {
    ethernet_t ethernet;
    ipv4_t     ip;
    tcp_t      tcp;
}

struct pipeline_stage1_metadata_t{
    bit<10> dstip_match;
}

struct pipeline_stage2_metadata_t{
    bit<10> ethtype_match;
}

struct pipeline_stage3_metadata_t{
    bit<10> dstip_ethtype_match;
}

struct pipeline_stage4_metadata_t{
    bit<9> dstip_ethtype_modify_port;
}

struct CommonMetadata {
    bit<32> switchId;
    bit<32> payload_length;
    bit<32> egress_timestamp;
    bit<32> pktpath;
    bit<32> srcport;
    bit<32> dstport;
}

struct Metadata {
    CommonMetadata common_meta;
    pipeline_stage1_metadata_t pipeline_stage1_metadata;
    pipeline_stage2_metadata_t pipeline_stage2_metadata;
    pipeline_stage3_metadata_t pipeline_stage3_metadata;
    pipeline_stage4_metadata_t pipeline_stage4_metadata;
}

parser P(packet_in b,
         out Headers p,
         inout Metadata meta,
         inout standard_metadata_t standard_meta) {
    state start {
        b.extract(p.ethernet);
        transition select(p.ethernet.etherType) {
            0x0800 : parse_ipv4;
            default : reject;
        }
    }

    state parse_ipv4 {
        b.extract(p.ip);
        transition select(p.ip.fragOffset, p.ip.ihl, p.ip.protocol) {
            (13w0x0 &&& 13w0x0, 4w0x5 &&& 4w0xf, 8w0x6 &&& 8w0xff): parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        b.extract(p.tcp);
        transition accept;
    }
}

control Ing(inout Headers hdr,
            inout Metadata meta,
            inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop();
    }
    action pipeline_stage1_action(bit<10> dstip_match){
        meta.pipeline_stage1_metadata.dstip_match = dstip_match;
    }

    table pipeline_stage1{
        key = {
            hdr.ip.dstAddr: lpm;
        }
        actions = {
            pipeline_stage1_action;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action pipeline_stage2_action(bit<10> ethtype_match){
        meta.pipeline_stage2_metadata.ethtype_match = ethtype_match;
    }

    table pipeline_stage2{
        key = {
            hdr.ethernet.etherType: exact;
        }
        actions = {
            pipeline_stage2_action;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action pipeline_stage3_action(bit<10> dstip_ethtype_match){
        meta.pipeline_stage3_metadata.dstip_ethtype_match = dstip_ethtype_match;
    }

    table pipeline_stage3{
        key = {
            meta.pipeline_stage1_metadata.dstip_match: exact;
            meta.pipeline_stage2_metadata.ethtype_match: exact;
        }
        actions = {
            pipeline_stage3_action;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action pipeline_stage4_action(bit<9> dstip_ethtype_modify_port){
        standard_metadata.egress_spec = dstip_ethtype_modify_port;
    }

    table pipeline_stage4{
        key = {
            meta.pipeline_stage3_metadata.dstip_ethtype_match: exact;
        }
        actions = {
            pipeline_stage4_action;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ip.isValid()) {
            pipeline_stage1.apply();
            pipeline_stage2.apply();
            pipeline_stage3.apply();
            pipeline_stage4.apply();
       }
    }
}

control MyEgress(inout Headers hdr,
                 inout Metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control DP(packet_out b, in Headers p) {
    apply {
        b.emit(p.ethernet);
        b.emit(p.ip);
        b.emit(p.tcp);
    }
}

control Verify(inout Headers hdr, inout Metadata meta) {
    apply {}
}

control Compute(inout Headers hdr, inout Metadata meta) {
    apply {}
}

V1Switch(P(),
         Verify(),
         Ing(),
         MyEgress(),
         Compute(),
         DP()) main;
