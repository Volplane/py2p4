from pyretic.core.language import *
from pyretic.core.packet import *
from pyretic.core import packet

import pyretic.lib.query as query

import copy

def dynamic_handler(nodeList):
    headers = {}
    headers['srcmac'] = 'ff:ff:ff:ff:ff:ff'
    headers['dstmac'] = 'ff:ff:ff:ff:ff:ff'
    headers['srcip'] = '10.0.0.4'
    headers['dstip'] = '10.0.0.1'
    headers['tos'] = '0'
    headers['srcport'] = 0
    headers['dstport'] = 0
    headers['ethtype'] = 0
    headers['protocol'] = 0
    headers['tcpflag'] = 0
    headers['payload_len'] = 0
    headers['port'] = 0

    pfs = FwdBucket_packetfield_handler(nodeList)
    for pf in pfs:
        for f in pf:
            headers[f[0]] = f[1]
    pkt = Packet()
    pkt = pkt.modifymany(headers)
    for item in nodeList[4]:
        item(pkt)

def mt_printer(node):
    print(node.content)
    if node.children:
        for child in node.children:
            mt_printer(child)

def domino_printer(nodeList):
    for node in nodeList:
        if(isinstance(node, domino_Node)):
            print(node.nodeContent, node.stage, node.nodeType)

def domino_graph_gen(nodeList):
    tempList = []
    for node in nodeList:
        if(isinstance(node,domino_Node)):
            for nodecomp in nodeList:
                if(isinstance(nodecomp,domino_Node)):
                    if(node.right1==nodecomp.left or node.right2==nodecomp.left):
                        node.parent.append(nodecomp)
                    if(node.left==nodecomp.right1 or node.left==nodecomp.right2):
                        node.children.append(nodecomp)
            tempList.append(node)
    return tempList

def FwdBucket_packetfield_handler(nodeList):
    packetfields = []
    for fbs in nodeList[3]:
        if(fbs==0):
            packetfields.append([])
        else:
            pf = []
            pf = pf_search('tmp'+str(fbs), pf, nodeList)
            packetfields.append(pf)
    return packetfields

def pf_search(fbs, pf, nodeList):
    for node in nodeList:
        if(isinstance(node,domino_Node)):
            if(node.left == fbs):
                if(node.right1[0:3] == 'tmp'):
                    pf_search(node.right1, pf, nodeList)
                    pf_search(node.right2, pf, nodeList)
                else:
                    pf.append([node.right1, node.right2])
    return pf

def domino_stage_gen_v2(nodeList):
    reList = []
    stage = 0
    while(len(reList)<len(nodeList)):
        stage = stage+1
        flagNode = None
        for node in nodeList:
            if not node.parent:
                if(node.stage==0):
                    if not flagNode:
                        flagNode = node
                        node.stage = stage
                        reList.append(node)
                    else:
                        if(node.nodeType == flagNode.nodeType):
                            if(node.nodeType == 'match' or node.nodeType == 'negate_match'):
                                if(node.right1 == flagNode.right1):
                                    node.stage = stage
                                    reList.append(node)
                            if(node.nodeType == 'modify'):
                                if(node.left == flagNode.left):
                                    node.stage = stage
                                    reList.append(node)
                            if(node.nodeType == 'FwdBucket'):
                                print('FwdBucket found in stage generating')
            else:
                if(node.stage==0):
                    if not flagNode:
                        flagNode = node
                        node.stage = stage
                        reList.append(node)
                    else:
                        if(node.nodeType == flagNode.nodeType):
                            if(node.nodeType == 'match' or node.nodeType == 'negate_match'):
                                if(node.right1 == flagNode.right1):
                                    node.stage = stage
                                    reList.append(node)
                            if(node.nodeType == 'intersect' or node.nodeType == 'union'):
                                if(node.parent[0].stage == flagNode.parent[0].stage and node.parent[1].stage == flagNode.parent[1].stage):
                                    node.stage = stage
                                    reList.append(node)
                            if(node.nodeType == 'modify'):
                                if(node.left == flagNode.left):
                                    node.stage = stage
                                    reList.append(node)
                            if(node.nodeType == 'FwdBucket'):
                                print('FwdBucket found in stage generating')
    return reList



def domino_stage_gen(nodeList):
    reList = []
    compList = []
    stage = 0
    while(len(reList)<len(nodeList)):
        stage = stage+1
        #print(stage)
        tmpList = []
        for node in nodeList:
            if(node.nodeContent not in compList):
                if not node.parent:
                    node.stage = stage
                    reList.append(node)
                    tmpList.append(node.nodeContent)
                else:
                    flag = true
                    for p in node.parent:
                        if (p.nodeContent not in compList):
                            flag = false
                    if (flag == true):
                        node.stage = stage
                        reList.append(node)
                        tmpList.append(node.nodeContent)
        for s in tmpList:
            compList.append(s)
        #print(tmpList)

    return reList

def domino_trans(node, nodeList):
    if(node.nodeType == 'sequential'):
        for child in node.children:
            nodeList = domino_trans(child, nodeList)
        return nodeList
    elif(node.nodeType == 'identity'):

        dnode = domino_Node('identity')
        #nodeList.append(dnode)
        return nodeList
    elif(node.nodeType == 'match'):
        if(nodeList[2] == 0):
            for key in node.content.map:
                dnode = domino_Node('match')
                tmpStr = 'tmp'+str(nodeList[0])
                nodeList[0] = nodeList[0]+1
                dnode.left = tmpStr
                dnode.right1 = str(key)
                dnode.right2 = str(node.content.map[key])
                dnode.nodeContent = dnode.left+'='+dnode.right1+'=='+dnode.right2
                nodeList.append(dnode)
                if (nodeList[1]!=0):
                    dnode = domino_Node('intersect')
                    tmpStr1 = 'tmp'+str(nodeList[0])
                    nodeList[0] = nodeList[0]+1
                    tmpStr2 = 'tmp'+str(nodeList[1])
                    dnode.left = tmpStr1
                    dnode.right1 = tmpStr
                    dnode.right2 = tmpStr2
                    dnode.nodeContent = dnode.left+'='+dnode.right1+'&&'+dnode.right2
                    nodeList.append(dnode)
                nodeList[1] = nodeList[0]-1
        else:
            currentLogic = nodeList[1]
            counter = 0
            for key in node.content.map:
                dnode = domino_Node('nagate_match')
                tmpStr = 'tmp'+str(nodeList[0])
                nodeList[0] = nodeList[0]+1
                dnode.left = tmpStr
                dnode.right1 = str(key)
                dnode.right2 = str(node.content.map[key])
                dnode.nodeContent = dnode.left+'='+dnode.right1+'!='+dnode.right2
                nodeList.append(dnode)
                if (counter!=0):
                    dnode = domino_Node('union')
                    tmpStr1 = 'tmp'+str(nodeList[0])
                    nodeList[0] = nodeList[0]+1
                    tmpStr2 = 'tmp'+str(counter)
                    dnode.left = tmpStr1
                    dnode.right1 = tmpStr
                    dnode.right2 = tmpStr2
                    dnode.nodeContent = dnode.left+'='+dnode.right1+'||'+dnode.right2
                    nodeList.append(dnode)
                counter = nodeList[0]-1
            if (currentLogic != 0):
                dnode = domino_Node('intersect')
                tmpStr = 'tmp'+str(nodeList[0]-1)
                tmpStr1 = 'tmp'+str(nodeList[0])
                nodeList[0] = nodeList[0]+1
                tmpStr2 = 'tmp'+str(currentLogic)
                dnode.left = tmpStr1
                dnode.right1 = tmpStr
                dnode.right2 = tmpStr2
                dnode.nodeContent = dnode.left+'='+dnode.right1+'&&'+dnode.right2
                nodeList.append(dnode)
            nodeList[1] = nodeList[0]-1
        nodeList[2] = 0
        return nodeList
    elif(node.nodeType == 'drop'):
        dnode = domino_Node('drop')
        dnode.left = 'port'
        dnode.right1 = '10000'
        if(nodeList[1]!=0):
            tmpStr = 'tmp'+str(nodeList[1])
            dnode.right2 = tmpStr
            dnode.nodeContent = dnode.left+'='+dnode.right1+':'+dnode.right2+'?'+dnode.right2
        else:
            dnode.right2 = None
            dnode.nodeContent = dnode.left+'='+dnode.right1
        nodeList.append(dnode)
        return nodeList
    elif(node.nodeType == 'modify'):
        for key in node.content.map:
            dnode = domino_Node('modify')
            dnode.left = str(key)
            dnode.right1 = str(node.content.map[key])
            if(nodeList[1]!=0):
                tmpStr = 'tmp'+str(nodeList[1])
                dnode.right2 = tmpStr
                dnode.nodeContent = dnode.left+'='+dnode.right2+'?'+dnode.right1+':'+dnode.left
            else:
                dnode.right2 = None
                dnode.nodeContent = dnode.left+'='+dnode.right1
            nodeList.append(dnode)
        return nodeList
    elif(node.nodeType == 'FwdBucket'):
        dnode = domino_Node('FwdBucket')
        dnode.left = 'FwdBucket'
        if(nodeList[1]!=0):
            tmpStr = 'tmp'+str(nodeList[1])
            dnode.right1 = tmpStr
            dnode.nodeContent = dnode.left + 'while' + dnode.right1
        #tmp_pkt = Packet()
        #tmp_pkt = tmp_pkt.modifymany({'srcmac':'ff:ff:ff:ff:ff:ff','dstmac':'ff:ff:ff:ff:ff:ff','srcip':'10.0.0.4','dstip':'10.0.0.1','tos':'0','srcport':'0','dstport':'0','ethtype':'0','protocol':'0','tcpflag':1})
        for item in node.content.callbacks:
            nodeList[4].append(item)
        nodeList[3].append(nodeList[1])
        nodeList.append(dnode)
        return nodeList
    elif(node.nodeType == 'Query'):
        dnode = domino_Node('Query')
        #nodeList.append(dnode)
        return nodeList
    elif(node.nodeType == 'parallel'):
        currentLogic = nodeList[1]
        for child in node.children:
            nodeList = domino_trans(child, nodeList)
            nodeList[1] = currentLogic
        return nodeList
    elif(node.nodeType == 'negate'):
        nodeList[2] = 1
        currentLogic = nodeList[1]
        for child in node.children:
            nodeList = domino_trans(child, nodeList)
            nodeList[1] = currentLogic
        return nodeList
    else:
        currentLogic = nodeList[1]
        for child in node.children:
            nodeList = domino_trans(child, nodeList)
            nodeList[1] = currentLogic
        return nodeList

def mt_Generator(policy):
    if(policy == identity):
        node = mt_Node('identity')
        node.content = policy
        return node
    elif(isinstance(policy,DynamicPolicy)):
        node = mt_Node('DynamicPolicy')
        node.children.append(mt_Generator(policy.policy))
        return node
    elif(isinstance(policy,if_)):
        node = mt_Node('if_')
        node.children.append(mt_Generator(policy.policy))
        return node
    elif(isinstance(policy,fwd)):
        node = mt_Node('fwd')
        node.children.append(mt_Generator(policy.policy))
        return node
    elif(isinstance(policy,xfwd)):
        node = mt_Node('xfwd')
        node.childrenn.append(mt_Generator(policy.policy))
        return node
    elif(isinstance(policy,difference)):
        node = mt_Node('difference')
        node.children.append(mt_Generator(policy.policy))
        return node
    elif(isinstance(policy,query.packets)):
        node = mt_Node('querypackets')
        node.children.append(mt_Generator(policy.policy))
        return node
    elif(isinstance(policy,parallel)):
        node = mt_Node('parallel')
        for subp in policy.policies:
            node.children.append(mt_Generator(subp))
        return node
    elif(isinstance(policy,sequential)):
        node = mt_Node('sequential')
        for subp in policy.policies:
            node.children.append(mt_Generator(subp))
        return node
    elif(isinstance(policy,negate)):
        node = mt_Node('negate')
        for subp in policy.policies:
            node.children.append(mt_Generator(subp))
        return node
    elif(isinstance(policy,union)):
        node = mt_Node('union')
        for subp in policy.policies:
            node.children.append(mt_Generator(subp))
        return node
    elif(isinstance(policy,intersection)):
        node = mt_Node('intersection')
        for subp in policy.policies:
            node.children.append(mt_Generator(subp))
        return node
    elif(policy == drop):
        node = mt_Node('drop')
        node.content = policy
        return node
    elif(isinstance(policy,FwdBucket)):
        node = mt_Node('FwdBucket')
        #policy.compile()
        #print('FwdBucket detected!!!!!')
        #print(policy._classifier)
        #for item in policy.callbacks:
        #   print item
        node.content = policy
        return node
    elif(isinstance(policy,Query)):
        node = mt_Node('Qurey')
        node.content = policy
        return node
    elif(isinstance(policy,match)):
        node = mt_Node('match')
        node.content = policy
        return node
    elif(isinstance(policy,modify)):
        node = mt_Node('modify')
        node.content = policy
        return node
    else:
        node = mt_Node('NOT_IMPLEMENTED')
        node.content = policy
        return node


def pipe_Generator(nodes, policy, name_dict):
    if(policy == identity):
        nodes = nodes
        return nodes
    elif(isinstance(policy,DynamicPolicy)):
        nodes = pipe_Generator(nodes, policy.policy, name_dict)
        return nodes
    elif(isinstance(policy,if_)):
        print('if:')
        print(policy.policy)
        nodes = pipe_Generator(nodes, policy.policy, name_dict)
        return nodes
    elif(isinstance(policy,difference)):
        nodes = pipe_Generator(nodes, policy.policy, name_dict)
        return nodes
    elif(isinstance(policy,query.packets)):
        nodes = pipe_Generator(nodes, policy.policy, name_dict)
        return nodes
    elif(isinstance(policy,parallel)):
        for subp in policy.policies:
            nodes = pipe_Generator(nodes, subp, name_dict)
        return nodes
    elif(isinstance(policy,sequential)):
        for subp in policy.policies:
            nodes = pipe_Generator(nodes, subp, name_dict)
        return nodes
    elif(isinstance(policy,negate)):
        for subp in policy.policies:
            nodes = pipe_Generator(nodes, subp, name_dict)
        return nodes
    elif(isinstance(policy,union)):
        for subp in policy.policies:
            nodes = pipe_Generator(nodes, subp, name_dict)
        return nodes
    elif(isinstance(policy,intersection)):
        for subp in policy.policies:
            nodes = pipe_Generator(nodes, subp, name_dict)
        return nodes
    elif(policy == drop):
        node = pg_Node('drop')
        nodes.append(node)
        return nodes
    elif(isinstance(policy,Query)):
        node = pg_Node('Query')
        nodes.append(node)
        return nodes
    elif(isinstance(policy,match)):
        for key in policy.map:
            if 'tmp' in name_dict:
                name_dict['tmp'] += 1
            else:
                name_dict['tmp'] = 0
            node = pg_Node('match')
            tempStr = 'tmp'+str(name_dict['tmp'])
            node.left = tempStr
            node.right1 = str(key)
            node.right2 = str(policy.map[key])
            node.nodeContent = node.left+'='+node.right1+'=='+node.right2
            nodes.append(node)
        return nodes
    elif(isinstance(policy,fwd)):
        nodes = pipe_Generator(nodes, policy.policy, name_dict)
        return nodes
    elif(isinstance(policy,xfwd)):
        nodes = pipe_Generator(nodes, policy.policy, name_dict)
        return nodes
    elif(isinstance(policy,modify)):
        for key in policy.map:
            node = pg_Node('modify')
            node.left = key
            node.right1 = policy.map[key]
            nodes.append(node)
        return nodes
    else:
        print('NOT YET IMPLEMENTED')
        print(policy)
        return nodes

def pt_Gen(policy, start_node):
    if(isinstance(policy,DynamicPolicy)):
        node = pt_Gen(policy.policy, start_node)
        return node
    elif(isinstance(policy, if_)):
        parent = t_Node(policy.policy.polices[0].policies[0])
        parent.leftChild = pt_Gen(policy.policy.policies[0].policies[1], t_Node(None))
        parent.rightChild = pt_Gen(policy.policy.policies[1].policies[1], t_Node(None))
        return parent
    elif(policy == identity):
        node = t_Node(policy)
        return node
    elif(isinstance(policy, difference)):
        node = pt_Gen(policy.policy, start_node)
        return node
    elif(isinstance(policy, query.packets)):
        node = pt_Gen(policy.policy, start_node)
        return node
    elif(isinstance(policy, parallel)):
        node_list=[]
        for subp in policy.policies:
            node = pt_Gen(subp, start_node)
            node_list.append(node)

        re_node = t_node(None)
        first_node = node_list[0]

    elif(isinstance(policy, negate)):
        node = pt_Gen(policy.policy, start_node)
        return node
    elif(isinstance(policy, fwd)):
        node = pt_Gen(policy.policy, start_node)
        return node
    elif(isinstance(policy, xfwd)):
        node = pt_Gen(policy.policy, start_node)
    elif(policy == drop):
        node = t_Node(policy)
        return node
    elif(isinstance(policy, Query)):
        node = t_Node(policy)
        return node
    elif(isinstance(policy, modify)):
        node = t_Node(policy)
        return node
    else:
        print('Tree NOT IMPLEMENTED ERROR')
        print(policy)
        return start_node

class mt_Node(object):
    def __init__(self,nodeType):
        self.nodeType = nodeType
        self.children = []
        self.content = nodeType


class t_Node(object):
    def __init__(self,nodePolicy):
        self.nodePolicy = nodePolicy
        self.leftChild = None
        self.rightChild = None

class pg_Node(object):
    def __init__(self,nodeType):
        self.nodeType = nodeType
        self.left = None
        self.right1 = None
        self.right2 = None
        self.nodeContent = None

class domino_Node(object):
    def __init__(self,nodeType):
        self.left = None
        self.right1 = None
        self.right2 = None
        self.nodeType = nodeType
        self.nodeContent = nodeType
        self.parent = []
        self.children = []
        self.md_Name = None
        self.stage = 0

class pg_Graph(object):
    def __init__(self,nodes):
        vnum = len(nodes)
        self._mat = [nodes[i][:] for i in nodes]
        self._unconn = 0
        self._vnum = vnum

    def vertex_num(self):
        return self._vnum

    def add_edge(self,vi,vj):
        if self._invalid(vi) or self._invalid(vj):
            raise ValueError(str(vi)+' or '+str(vj)+' is not valid')
        self._mat[vi][vj] = 1

    def get_edge(self,vi,vj):
        if self._invalid(vi) or self._invalid(vj):
            raise ValueError(str(vi)+' or '+str(vj)+' is not valid')
        return self._mat[vi][vj]

    def _invalid(self,vi):
        return v<0 or v>self._vnum

    def out_edges(self,vi):
        if self._invalid(vi):
            raise ValueError(str(vi)+' is not valid')
        edges = []
        for i in range(len(self._mat[vi])):
            if self._mat[vi] != 0:
                edges.append(self._mat[vi][i])
        return edges
