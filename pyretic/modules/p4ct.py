import argparse
import os
import sys
from time import sleep

from pyretic.core.language import *
from pyretic.core.packet import *

from pyretic.modules.pipeGen import *

sys.path.append('/home/p4/tutorials/utils')
import p4runtime_lib.bmv2
import p4runtime_lib.helper

def build_connection_to_switch(nodelist):
    p4info_helper = p4runtime_lib.helper.P4InfoHelper('/home/p4/Desktop/autogenbeta/exercises/p4runtime/build/autogen.p4info')
    s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
        name='s1',
        address='127.0.0.1:50051',
        device_id=0,
        proto_dump_file='/home/p4/Desktop/autogenbeta/exercises/p4runtime/logs/s1-p4runtime-requests.txt')
    s1.MasterArbitrationUpdate()
    s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,
                                   bmv2_json_file_path='/home/p4/Desktop/autogenbeta/exercises/p4runtime/build/autogen.json')
    print('successfully connected to p4 switch')
    try:
        write_table_entry(nodeList, s1)
    except:
        print('when writing rules problems')
    else:
        print('All set')

def write_table_entry(nodelist, p4switch):

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
    tableNamePre = 'Ing.pipeline_stage'
    actionNamePre = 'Ing.pipeline_stage'
    actionNamePost = '_action'
    currStage = 1

    for stage in stages:
        for node in stage:
            if (node.nodeType == 'match' or node.nodeType == 'negate_match'):
                node.md_Name = node.right1
            if (node.nodeType == 'union' or node.nodeType == 'intersect'):
                node.md_Name = node.parent[0].md_Name + '_' + node.parent[1].md_Name
            if (node.nodeType == 'modify'):
                for parent_node in node.parents:
                    if (parent_node.left == node.right2):
                        node.md_Name = parent_node.md_Name+'_modify_'+node.left

    for stage in stages:
        for node in stage:
            if (node.nodeType == 'match' or node.nodeType == 'negate_match'):
                match_content = None
                if(node.right1 == 'dstip' or node.right1 == 'srcip'):
                    match_content = [node.right2,32]
                else:
                    match_content = int(node.right2)
                table_entry = p4info_helper.buildTableEntry(
                    table_name = tableNamePre+str(currStage),
                    match_fields = {hdrs_py2p4_dict[node.right1]:match_content},
                    action_name = actionNamePre+str(currStage)+actionNamePost,
                    action_params = {node.md_Name+"_match":node.left[3:]}
                )
            if (node.nodeType == 'intersect' or node.nodeType == 'union'):
                table_entry = p4info_helper.buildTableEntry(
                    table_name = tableNamePre+str(currStage),
                    match_fields = {
                    "metadata.pipeline_stage"+str(node.parents[0].stage)+"_metadata."+node.parents[0].md_Name+"_match" : int(node.parent[0].left[3:]),
                    "metadata.pipeline_stage"+str(node.parents[1].stage)+"_metadata."+node.parents[1].md_Name+"_match" : int(node.parent[1].left[3:])
                    },
                    action_name = actionNamePre+str(currStage)+actionNamePost,
                    action_params = {
                    node.md_Name+"_match" : int(node.left[3:])
                    }
                )
            if (node.nodeType == 'modify'):
                for parent_node in node.parents:
                    if (parent_node.left == node.right2):
                        table_entry = p4info_helper.buildTableEntry(
                            table_name = tableNamePre+str(currStage),
                            match_fields = {
                            "metadata.pipeline_stage"+str(parent_node.stage)+"_matadata."+parent_node.md_Name+"_match" : int(node.right2[3:])
                            },
                            action_name = actionNamePre+str(currStage)+actionNamePost,
                            action_params = {
                            node.md_Name : int(node.right1)
                            }
                        )
            p4switch.WriteTableEntry(table_entry)
        currStage += 1
