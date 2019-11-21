from pyretic.core.language import *
from pyretic.core.packet import *

from pyretic.modules.pipeGen import *

import copy
import sys

def p4_file_gen(nodelist):
    hdrs_bit_dict = {}
    hdrs_bit_dict['srcmac'] = 'bit<48>'
    hdrs_bit_dict['dstmac'] = 'bit<48>'
    hdrs_bit_dict['srcip'] = 'bit<32>'
    hdrs_bit_dict['dstip'] = 'bit<32>'
    hdrs_bit_dict['srcport'] = 'bit<9>'
    hdrs_bit_dict['dstport'] = 'bit<9>'
    hdrs_bit_dict['ethtype'] = 'bit<16>'
    hdrs_bit_dict['protocol'] = 'bit<8>'
    hdrs_bit_dict['port'] = 'bit<9>'
    hdrs_bit_dict['tcpflag'] = 'bit<8>'

    hdrs_py2p4_dict = {}
    hdrs_py2p4_dict['srcmac'] = 'hdr.ethernet.srcAddr'
    hdrs_py2p4_dict['dstmac'] = 'hdr.ethernet.dstAddr'
    hdrs_py2p4_dict['ethtype'] = 'hdr.ethernet.etherType'
    hdrs_py2p4_dict['srcip'] = 'hdr.ip.srcAddr'
    hdrs_py2p4_dict['dstip'] = 'hdr.ip.dstAddr'
    hdrs_py2p4_dict['srcport'] = 'hdr.tcp.srcport'
    hdrs_py2p4_dict['dstport'] = 'hdr.tcp.dstport'
    hdrs_py2p4_dict['protocol'] = 'hdr.ip.protocol'
    hdrs_py2p4_dict['tcpflag'] = 'hdr.tcp.flags'
    hdrs_py2p4_dict['port'] = 'standard_metadata.ingress_port'

    lw = []

    stages = []
    curr = 1
    stage = []
    #Seperate nodes into differnet stages
    for node in nodelist:
        if node.stage>curr:
            stages.append(stage)
            stage = []
            curr+=1
        stage.append(node)
    stages.append(stage)
    #print(stages)

    f = open(r"./autogen.p4","w")
    lw.append('//This is an auto_generated p4 file, do not modify it manually\n')
    lw.append('#include <core.p4>\n')
    lw.append('#include <v1model.p4>\n')
    lw.append('\n')
    lw.append('typedef bit<48>  EthernetAddress;\n')
    lw.append('typedef bit<32>  IPv4Address;\n')
    lw.append('\n')
    lw.append('header ethernet_t {\n')
    lw.append('    EthernetAddress dstAddr;\n')
    lw.append('    EthernetAddress srcAddr;\n')
    lw.append('    bit<16>         etherType;\n')
    lw.append('}\n')
    lw.append('\n')
    lw.append('header ipv4_t {\n')
    lw.append('    bit<4>       version;\n')
    lw.append('    bit<4>       ihl;\n')
    lw.append('    bit<8>       diffserv;\n')
    lw.append('    bit<16>      packet_length;\n')
    lw.append('    bit<16>      identification;\n')
    lw.append('    bit<3>       flags;\n')
    lw.append('    bit<13>      fragOffset;\n')
    lw.append('    bit<8>       ttl;\n')
    lw.append('    bit<8>       protocol;\n')
    lw.append('    bit<16>      hdrChecksum;\n')
    lw.append('    IPv4Address  srcAddr;\n')
    lw.append('    IPv4Address  dstAddr;\n')
    lw.append('}\n')
    lw.append('\n')
    lw.append('header tcp_t {\n')
    lw.append('    bit<16> srcport;\n')
    lw.append('    bit<16> dstport;\n')
    lw.append('    bit<32> seqNo;\n')
    lw.append('    bit<32> ackNo;\n')
    lw.append('    bit<4>  dataOffset;\n')
    lw.append('    bit<4>  res;\n')
    lw.append('    bit<8>  flags;\n')
    lw.append('    bit<16> window;\n')
    lw.append('    bit<16> checksum;\n')
    lw.append('    bit<16> urgentPtr;\n')
    lw.append('}\n')
    lw.append('\n')
    lw.append('header udp_t {\n')
    lw.append('    bit<16> srcPort;\n')
    lw.append('    bit<16> dstPort;\n')
    lw.append('    bit<16> length;\n')
    lw.append('    bit<16> checksum;\n')
    lw.append('}\n')
    lw.append('\n')
    lw.append('// Parser section\n')
    lw.append('\n')
    lw.append('struct Headers {\n')
    lw.append('    ethernet_t ethernet;\n')
    lw.append('    ipv4_t     ip;\n')
    lw.append('    tcp_t      tcp;\n')
    lw.append('}\n')
    lw.append('\n')

    curr = 1
    metadatas = []
    for stage in stages:
        hds = set()
        meta = []
        lw.append('struct pipeline_stage'+str(curr)+'_metadata_t{\n')
        for node in stage:
            if (node.nodeType == 'match' or node.nodeType == 'negate_match'):
                node.md_Name = node.right1
                if (node.right1 not in hds):
                    lw.append('    bit<10> '+node.right1+'_match;\n')
                    meta.append('bit<10> '+node.right1+'_match')
                    hds.add(node.right1)
            if (node.nodeType == 'intersect' or node.nodeType == 'union'):
                if (node.parent[0].nodeType == 'match' and node.parent[1].nodeType == 'match'):
                    node.md_Name = node.parent[0].right1+'_'+node.parent[1].right1
                    if (node.md_Name not in hds):
                        lw.append('    bit<10> '+node.md_Name+'_match;\n')
                        meta.append('bit<10> '+node.md_Name+'_match')
                        hds.add(node.md_Name)
                if (node.parent[0].nodeType == 'match' and (node.parent[1].nodeType == 'union' or node.parent[1].nodeType == 'intersect')):
                    node.md_Name = node.parent[0].right1+'_'+node.parent[1].md_Name
                    if (node.md_Name not in hds):
                        lw.append('    bit<10> '+node.md_Name+'_match;\n')
                        meta.append('bit<10> '+node.md_Name+'_match')
                        hds.add(node.md_Name)
                if ((node.parent[0].nodeType == 'union' or node.parent[0].nodeType == 'intersect') and node.parent[1].nodeType == 'match'):
                    node.md_Name = node.parent[0].md_Name+'_'+node.parent[1].right1
                    if (node.md_Name not in hds):
                        lw.append('    bit<10> '+node.md_Name+'_match;\n')
                        meta.append('bit<10> '+node.md_Name+'_match')
                        hds.add(node.md_Name)
                if ((node.parent[0].nodeType == 'union' or node.parent[0].nodeType == 'intersect') and (node.parent[1].nodeType == 'union' or node.parent[1].nodeType == 'intersect')):
                    node.md_Name = node.parent[0].md_Name+'_'+node.parent[1].md_Name
                    if (node.md_Name not in hds):
                        lw.append('    bit<10> '+node.md_Name+'_match:\n')
                        meta.append('bit<10> '+node.md_Name+'_match')
                        hds.add(node.md_Name)
            if (node.nodeType == 'modify'):
                for parent_node in node.parent:
                    if (parent_node.left == node.right2):
                        node.md_Name = parent_node.md_Name+'_modify_'+node.left
                if (node.md_Name not in hds):
                    lw.append('    '+hdrs_bit_dict[node.left]+' '+node.md_Name+';\n')
                    meta.append(hdrs_bit_dict[node.left]+' ' +node.md_Name)
                    hds.add(node.md_Name)
        metadatas.append(meta)
        print(hds)
        lw.append('}\n')
        lw.append('\n')
        curr += 1

    lw.append('struct CommonMetadata {\n')
    lw.append('    bit<32> switchId;\n')
    lw.append('    bit<32> payload_length;\n')
    lw.append('    bit<32> egress_timestamp;\n')
    lw.append('    bit<32> pktpath;\n')
    lw.append('    bit<32> srcport;\n')
    lw.append('    bit<32> dstport;\n')
    lw.append('}\n')
    lw.append('\n')
    lw.append('struct Metadata {\n')
    lw.append('    CommonMetadata common_meta;\n')

    countStage = 1
    for stage in stages:
        lw.append('    pipeline_stage'+str(countStage)+'_metadata_t pipeline_stage'+str(countStage)+'_metadata;\n')
        countStage += 1

    lw.append('}\n')
    lw.append('\n')
    lw.append('parser P(packet_in b,\n')
    lw.append('         out Headers p,\n')
    lw.append('         inout Metadata meta,\n')
    lw.append('         inout standard_metadata_t standard_meta) {\n')
    lw.append('    state start {\n')
    lw.append('        b.extract(p.ethernet);\n')
    lw.append('        transition select(p.ethernet.etherType) {\n')
    lw.append('            0x0800 : parse_ipv4;\n')
    lw.append('            default : reject;\n')
    lw.append('        }\n')
    lw.append('    }\n')
    lw.append('\n')
    lw.append('    state parse_ipv4 {\n')
    lw.append('        b.extract(p.ip);\n')
    lw.append('        transition select(p.ip.fragOffset, p.ip.ihl, p.ip.protocol) {\n')
    lw.append('            (13w0x0 &&& 13w0x0, 4w0x5 &&& 4w0xf, 8w0x6 &&& 8w0xff): parse_tcp;\n')
    lw.append('            default: accept;\n')
    lw.append('        }\n')
    lw.append('    }\n')
    lw.append('\n')
    lw.append('    state parse_tcp {\n')
    lw.append('        b.extract(p.tcp);\n')
    lw.append('        transition accept;\n')
    lw.append('    }\n')
    lw.append('}\n')
    lw.append('\n')
    #Ingress part should be implemented here
    lw.append('control Ing(inout Headers hdr,\n')
    lw.append('            inout Metadata meta,\n')
    lw.append('            inout standard_metadata_t standard_metadata) {\n')
    lw.append('    action drop() {\n')
    lw.append('        mark_to_drop();\n')
    lw.append('    }\n')

    countStage = 1
    for stage in stages:
        actionArgs = ''
        for m in metadatas[countStage-1]:
            actionArgs += (m+', ')
        actionArgs = actionArgs[:-2]
        lw.append('    action pipeline_stage'+str(countStage)+'_action('+actionArgs+'){\n')
        for m in metadatas[countStage-1]:
            ms1 = m.split(' ')[1]
            ms2 = ms1.split('_')
            if ('modify' not in ms2):
                lw.append('        meta.pipeline_stage'+str(countStage)+'_metadata.'+ms1+' = '+ms1+';\n')
            else:
                if(ms2[-1] != 'port'):
                    lw.append('        '+hdrs_py2p4_dict[ms2[-1]]+' = '+ms2[-1]+';\n')
                else:
                    lw.append('        standard_metadata.egress_spec = '+ms1+';\n')
        lw.append('    }\n')
        lw.append('\n')


        lw.append('    table pipeline_stage'+str(countStage)+'{\n')
        lw.append('        key = {\n')
        keys = set()
        for node in stage:
            if (node.nodeType == 'match' or node.nodeType == 'negate_match'):
                if (node.right1 not in keys):
                    keys.add(node.right1)
                    if (node.right1 == 'dstip' or node.right1 == 'srcip'):
                        lw.append('            '+hdrs_py2p4_dict[node.right1]+': lpm;\n')
                    else:
                        lw.append('            '+hdrs_py2p4_dict[node.right1]+': exact;\n')
            if (node.nodeType == 'union' or node.nodeType == 'intersect' or node.nodeType == 'modify'):
                for p in node.parent:
                    if (p.nodeType == 'match' or p.nodeType == 'negate_match'):
                        ps = 'meta.pipeline_stage'+str(p.stage)+'_metadata.'+p.right1+'_match'
                        if (ps not in keys):
                            keys.add(ps)
                            lw.append('            '+ps+': exact;\n')
                    if (p.nodeType == 'intersect' or p.nodeType == 'union'):
                        ps = 'meta.pipeline_stage'+str(p.stage)+'_metadata.'+p.md_Name+'_match'
                        if (ps not in keys):
                            keys.add(ps)
                            lw.append('            '+ps+': exact;\n')
        lw.append('        }\n')
        lw.append('        actions = {\n')
        lw.append('            pipeline_stage'+str(countStage)+'_action;\n')
        lw.append('            drop;\n')
        lw.append('            NoAction;\n')
        lw.append('        }\n')
        lw.append('        size = 1024;\n')
        lw.append('        default_action = drop();\n')
        lw.append('    }\n')
        lw.append('\n')

        countStage += 1

    lw.append('    apply {\n')
    lw.append('        if (hdr.ip.isValid()) {\n')
    countStage = 1
    for stage in stages:
        lw.append('            pipeline_stage'+str(countStage)+'.apply();\n')
        countStage += 1
    lw.append('       }\n')
    lw.append('    }\n')

    lw.append('}\n')
    lw.append('\n')

    lw.append('control MyEgress(inout Headers hdr,\n')
    lw.append('                 inout Metadata meta,\n')
    lw.append('                 inout standard_metadata_t standard_metadata) {\n')
    lw.append('    apply { }\n')
    lw.append('}\n')
    lw.append('\n')
    lw.append('control DP(packet_out b, in Headers p) {\n')
    lw.append('    apply {\n')
    lw.append('        b.emit(p.ethernet);\n')
    lw.append('        b.emit(p.ip);\n')
    lw.append('        b.emit(p.tcp);\n')
    lw.append('    }\n')
    lw.append('}\n')
    lw.append('\n')
    lw.append('control Verify(inout Headers hdr, inout Metadata meta) {\n')
    lw.append('    apply {}\n')
    lw.append('}\n')
    lw.append('\n')
    lw.append('control Compute(inout Headers hdr, inout Metadata meta) {\n')
    lw.append('    apply {}\n')
    lw.append('}\n')
    lw.append('\n')
    lw.append('V1Switch(P(),\n')
    lw.append('         Verify(),\n')
    lw.append('         Ing(),\n')
    lw.append('         MyEgress(),\n')
    lw.append('         Compute(),\n')
    lw.append('         DP()) main;\n')
    lw.append('')
    lw.append('')
    lw.append('')
    lw.append('')
    lw.append('')
    lw.append('')
    lw.append('')
    lw.append('')


    lw.append('')
    f.writelines(lw)
    f.close()
    #for node in nodelist:
