
################################################################################
# The Pyretic Project                                                          #
# frenetic-lang.org/pyretic                                                    #
# author: Srinivas Narayana (narayana@cs.princeton.edu)                        #
# author: Mina Tahmasbi (arashloo@cs.princeton.edu)                            #
################################################################################
# Licensed to the Pyretic Project by one or more contributors. See the         #
# NOTICES file distributed with this work for additional information           #
# regarding copyright and ownership. The Pyretic Project licenses this         #
# file to you under the following license.                                     #
#                                                                              #
# Redistribution and use in source and binary forms, with or without           #
# modification, are permitted provided the following conditions are met:       #
# - Redistributions of source code must retain the above copyright             #
#   notice, this list of conditions and the following disclaimer.              #
# - Redistributions in binary form must reproduce the above copyright          #
#   notice, this list of conditions and the following disclaimer in            #
#   the documentation or other materials provided with the distribution.       #
# - The names of the copyright holds and contributors may not be used to       #
#   endorse or promote products derived from this work without specific        #
#   prior written permission.                                                  #
#                                                                              #
# Unless required by applicable law or agreed to in writing, software          #
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT    #
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the     #
# LICENSE file distributed with this work for specific language governing      #
# permissions and limitations under the License.                               #
################################################################################

import sys
import logging
import httplib
from ipaddr import IPv4Network

NETKAT_PORT = 9000
NETKAT_DOM  = "/compile"
NETKAT_TIME_HDR = "x-compile-time"
TEMP_INPUT = "/tmp/temp.in.json"
TEMP_HEADERS = "/tmp/temp.headers.txt"
TEMP_OUTPUT = "/tmp/temp.out.json"

class netkat_backend(object):
    """
    Backend component to communicate with the NetKAT compiler server through
    HTTP. This module does not actually do any compilation; it just communicates
    the policy to the NetKAT HTTP compiler server and receives the classifier in
    response. (Note that the Pyretic policy compilation routines are in
    pyretic/core/classifier.py.)
    """
    @classmethod
    def generate_classifier(cls, pol, switch_cnt, outport = False,
                            print_json=False):
        def use_explicit_switches(pol):
            """ Ensure every switch in the network gets reflected in the policy
            sent to netkat. This is because netkat generates a separate copy of
            the policy per switch, and it is necessary for it to know that a switch
            appears in the policy through the policy itself."""
            from pyretic.core.language import match, identity
            pred_policy = None
            for i in range(1, switch_cnt + 1):
                if pred_policy is None:
                    pred_policy = match(switch = i)
                else:
                    pred_policy |= match(switch = i)

            if pred_policy is None:
                pred_policy = identity
            return pred_policy >> pol

        def curl_channel_compilation(pol):
            """ Communicate with the netKAT compile server through curl. """
            import subprocess

            f = open('/tmp/in.json', 'w')
            if print_json:
                self.log.error("The policy being compiled to netkat is:")
                self.log.error(str(pol))
            f.write(compile_to_netkat(pol))
            f.close()

            try:
                output = subprocess.check_output(['curl', '-X', 'POST', 'localhost:9000/compile', '--data-binary', '@/tmp/in.json', '-D', '/tmp/header.txt'])
                f = open('/tmp/out.json', 'w')
                f.write(output)
                f.close()
            except subprocess.CalledProcessError:
                print "error in calling frenetic"

            cls = json_to_classifier(output, outport)
            if print_json:
                self.log.error("This is the json output:")
                self.log.error(str(output))
            f = open('/tmp/header.txt')
            time = 0
            for line in f.readlines():
                if line.startswith('x-compile-time:'):
                    time = float(line[line.index(":") + 1:-1])
                    break

            return (cls, time)

        def httplib_channel_compilation(pol):
            json_input = compile_to_netkat(pol)
            write_to_file(json_input, TEMP_INPUT)
            headers = {"Content-Type": "application/x-www-form-urlencoded",
                       "Accept": "*/*"}
            ctime = 0
            try:
                conn = httplib.HTTPConnection("localhost", NETKAT_PORT)
                conn.request("POST", NETKAT_DOM, json_input, headers)
                resp = conn.getresponse()
                ctime = resp.getheader(NETKAT_TIME_HDR, "-1")
                netkat_out = resp.read()
                write_to_file(ctime, TEMP_HEADERS)
                write_to_file(netkat_out, TEMP_OUTPUT)
            except Exception as e:
                print "Failed!!"
                print e
                sys.exit(0)
            cls = json_to_classifier(netkat_out, outport)
            return (cls, ctime)

        pol = use_explicit_switches(pol)
        # return curl_channel_compilation(pol)
        return httplib_channel_compilation(pol)

##################### Helper functions #################

import json

def write_to_file(val, fname):
    f = open(fname, 'w')
    f.write(val)
    f.close()

def mk_filter(pred):
  return { "type": "filter", "pred": pred }

def mk_test(hv):
  return { "type": "test", "header": hv["header"], "value": hv["value"] }

def mk_mod(hv):

  return { "type": "mod", "header": hv["header"], "value": hv["value"] }

def mk_header(h, v):
  return { "header": h, "value": v }

def to_int(bytes):
  n = 0
  for b in bytes:
    n = (n << 8) + ord(b)
  # print "Ethernet: %s -> %s" % (bytes, n)
  return n

def unip(v):
  # if isinstance(v, IPAddr):
  #   bytes = v.bits
  #   n = 0
  #   for b in bytes:
  #     n = (n << 8) + ord(b)
  #   print "IPAddr: %s -> %s (len = %s) -> %s" % (v, bytes, len(bytes), n)
  #   return { "addr": n, "mask": 32 }
  if isinstance(v, IPv4Network):
    return { "addr": str(v.ip), "mask": v.prefixlen }   
  elif isinstance(v, str):
    return { "addr" : v, "mask" : 32}
  else:
    raise TypeError(type(v))

def unethaddr(v):
  return repr(v)

def physical(n):
  return { "type": "physical", "port": n }

def header_val(h, v):
  if h == "switch":
    return mk_header("switch", v)
  elif h == "inport" or h == "outport":
    return mk_header("location", physical(v))
  elif h == "srcmac":
    return mk_header("ethsrc", unethaddr(v))
  elif h == "dstmac":
    return mk_header("ethdst", unethaddr(v))
  elif h == "vlan_id":
    return mk_header("vlan", v)
  elif h == "vlan_pcp":
    return mk_header("vlanpcp", v)
  elif h == "ethtype":
    return mk_header("ethtype", v)
  elif h == "protocol":
    return mk_header("inproto", v)
  elif h == "srcip":
    return mk_header("ip4src", unip(v))
  elif h == "dstip":
    return mk_header("ip4dst", unip(v))
  elif h == "srcport":
    return mk_header("tcpsrcport", v)
  elif h == "dstport":
    return mk_header("tcpdstport", v)
  else:
    raise TypeError("bad header %s" % h)

def match_to_pred(m):
  lst = [mk_test(header_val(h, m[h])) for h in m]
  return mk_and(lst)

def mod_to_pred(m):
  lst = [ mk_mod(header_val(h, m[h])) for h in m ]
  return mk_seq(lst)


def to_pred(p):
  from pyretic.core.language import (match, identity, drop, negate, union,
                                     parallel, intersection, ingress_network,
                                     egress_network, _match)
  if isinstance(p, match):
    return match_to_pred(_match(**p.map).map)
  elif p == identity:
    return { "type": "true" }
  elif p == drop:
    return { "type": "false" }
  elif isinstance(p, negate):
    # Only policies[0] is used in Pyretic
    return { "type": "neg", "pred": to_pred(p.policies[0]) }
  elif isinstance(p, union) or isinstance(p, parallel):
    return mk_or(map(to_pred, p.policies))
  elif isinstance(p, intersection):
    return mk_and(map(to_pred, p.policies))
  elif isinstance(p, ingress_network) or isinstance(p, egress_network):
    return to_pred(p.policy)
  else:
    raise TypeError(p)

# TODO(arjun): Consider using aspects to inject methods into each class. That
# would be better object-oriented style.
def to_pol(p):
  from pyretic.core.language import (match, modify, identity, drop, negate, union,
                                     parallel, intersection, ingress_network,
                                     egress_network, sequential, fwd, if_,
                                     FwdBucket, DynamicPolicy, DerivedPolicy,
                                     Controller, _modify)
  if isinstance(p, match):
    return mk_filter(to_pred(p))
  elif p == identity:
    return mk_filter({ "type": "true" })
  elif p == drop:
    return mk_filter({ "type": "false" })
  elif isinstance(p, modify):
    return mod_to_pred(_modify(**p.map).map)
  elif isinstance(p, negate):
    return mk_filter(to_pred(p))
  elif isinstance(p, union):
    return mk_filter(to_pred(p))
  elif isinstance(p, parallel):
    return mk_union(map(to_pol, p.policies))
  #elif isinstance(p, disjoint):
    #return mk_disjoint(map(to_pol, p.policies))
  elif isinstance(p, intersection):
    return mk_filter(to_pred(p))
  elif isinstance(p, sequential):
    return mk_seq(map(to_pol, p.policies))
  elif isinstance(p, fwd):
    return mk_mod(mk_header("location", physical(p.outport)))
  elif isinstance(p, if_):
    c = to_pred(p.pred)
    return mk_union([mk_seq([mk_filter(c), to_pol(p.t_branch)]),
                     mk_seq([mk_filter({ "type": "neg", "pred": c }), to_pol(p.f_branch)])])    
  elif isinstance(p, FwdBucket):
      return {"type" : "mod", "header" : "location", "value": {"type" : "pipe", "name" : str(id(p))}}
  elif isinstance(p, ingress_network) or isinstance(p, egress_network) or isinstance(p, DynamicPolicy):
      return to_pol(p.policy)
  elif isinstance(p, DerivedPolicy):
      return to_pol(p.policy)
  else:
    raise TypeError("unknown policy %s" % type(p))

def mk_union(pols):
  return { "type": "union", "pols": pols }

def mk_disjoint(pols):
  return { "type": "disjoint", "pols": pols }

def mk_seq(pols):
  return { "type": "seq", "pols": pols }

def mk_and(preds):
  return { "type": "and", "preds": preds }

def mk_or(preds):
  return { "type": "or", "preds": preds }

# Converts a Pyretic policy into NetKAT, represented
# as a JSON string.
def compile_to_netkat(pyretic_pol):
  return json.dumps(to_pol(pyretic_pol))


############## json to policy ###################

field_map = {'dlSrc' : 'srcmac', 'dlDst': 'dstmac', 'dlTyp': 'ethtype', 
                'dlVlan' : 'vlan_id', 'dlVlanPcp' : 'vlan_pcp',
                'nwSrc' : 'srcip', 'nwDst' : 'dstip', 'nwProto' : 'protocol',
                'tpSrc' : 'srcport', 'tpDst' : 'dstport', 'inPort' : 'inport'}

def create_match(pattern, switch_id):
    from pyretic.core.language import match
    def __reverse_mac__(m):
        return ':'.join(m.split(':')[::-1])
    if switch_id > 0:
        match_map = {'switch' : switch_id}
    else:
        match_map = {}
    for k,v in pattern.items():
        # HACKETY HACK: remove nwProto from netkat generated classifier
        if v is not None and k != "dlTyp" and k != "nwProto":
            if k == 'dlSrc' or k == 'dlDst':
                """ TODO: NetKat returns MAC addresses reversed. """
                match_map[field_map[k]] = __reverse_mac__(v)
            else:
                match_map[field_map[k]] = v

    # HACK! NetKat doesn't return vlan_pcp with vlan_id sometimes.
    if 'vlan_id' in match_map and not 'vlan_pcp' in match_map:
        match_map['vlan_pcp'] = 0
    return match(**match_map)

def create_action(action, inport):
    from pyretic.core.language import (modify, Controller, identity)
    if len(action) == 0:
        return set()
    else:
        res = set()

        for act_list in action:
            mod_dict = {}
            for act in act_list:
                if act[0] == "Modify":
                    hdr_field = act[1][0][3:]
                    if hdr_field == "Vlan" or hdr_field == "VlanPcp":
                        hdr_field = 'dl' + hdr_field
                    else:
                        hdr_field = hdr_field[0].lower() + hdr_field[1:]
                    hdr_field = field_map[hdr_field]
                    value = act[1][1]
                    if hdr_field == 'srcmac' or hdr_field == 'dstmac':
                        value = MAC(value)
                    mod_dict[hdr_field] = value
                elif act[0] == "Output":
                    outout_seen = True
                    out_info = act[1]
                    if out_info['type'] == 'physical':
                        mod_dict['outport'] = out_info['port']
                    elif out_info['type'] == 'controller':
                        res.add(Controller)
                    #elif out_info['type'] == 'inport' and inport is not None:
                        #mod_dict['outport'] = inport 
            
            if len(mod_dict) > 0:
                res.add(modify(**mod_dict))
        if len(res) == 0:
            res.add(identity)
    return res
        
def json_to_classifier(fname, outport = False):
    from pyretic.core.classifier import Rule, Classifier
    if outport:
        field_map['inPort'] = 'outport'
    data = json.loads(fname)
    rules = []
    for sw_tbl in data:
        switch_id = sw_tbl['switch_id']
        for rule in sw_tbl['tbl']:
            prio = rule['priority']
            m = create_match(rule['pattern'], switch_id)
            inport = None
            if 'inport' in m.map:
                inport = m.map['inport']
            action = create_action(rule['action'], inport)
            rules.append( (prio, Rule(m, action, [None], "netkat")))
    #rules.sort()
    rules = [v for (k,v) in rules]
    return Classifier(rules)