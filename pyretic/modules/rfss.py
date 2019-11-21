from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *

class rfss(DynamicPolicy):
    def __init__(self):
        super(rfss,self).__init__()
        self.ports = [1,2,3,4]
        self.r = None
        self.routing()
        self.spread = {}
        self.super_spreader = []
        self.stateful_firewall = []
        self.set_initial_state()
        self.trigger_stateful_firewall()
        

    def set_initial_state(self):
        chosen_ip = '10.0.0.%d' % self.ports[-1]
        self.query = packets() 
        self.tcpdetect = match(ethtype=0x0800, protocol=6)>>self.query
        self.query.register_callback(self.super_spread)

    def trigger_stateful_firewall(self):
        chosen_ip = '10.0.0.%d' % self.ports[-1]
        print ('chosen_ip %s' % chosen_ip)
        self.firewall_query = packets(limit=1, group_by=['dstip','srcip'])
        self.fwt = (match(dstip=IPAddr(chosen_ip))|match(srcip=IPAddr(chosen_ip)))>>self.firewall_query
        self.firewall_query.register_callback(self.stateful_fw)
        self.update_policy()

    def routing(self):
        for port in self.ports:
            if port != self.ports[-1]:
                addr = '10.0.0.%d' % port 
                r_part = if_(match(dstip=IPAddr(addr)),fwd(port),identity)
                if self.r is None:
                    print('Routing rule %s added' % addr)
                    self.r = r_part
                else:
                    print('Routing rule %s added' % addr)
                    self.r += r_part

    def stateful_fw(self,pkt):
        #print (pkt['tcpflag'])
        chosen_ip = '10.0.0.%d' % self.ports[-1]
        print ('chosen_ip %s' % chosen_ip)
        print (pkt['srcip'])
        
        if(str(pkt['srcip']) == chosen_ip):
            print('srcip = %s matched' % chosen_ip)
            self.stateful_firewall.append([pkt['srcip'],pkt['dstip']])
            self.r = if_(match(dstip=pkt['srcip'],srcip=pkt['dstip']),fwd(self.ports[-1]),self.r)
        else: 
            if(str(pkt['dstip']) == chosen_ip):
                print('Trying to reach chosen_ip')
                if([pkt['dstip'],pkt['srcip']] in self.stateful_firewall):
                    print('Access allowed')
                    self.r = if_(match(dstip=pkt['dstip'],srcip=pkt['srcip']),fwd(self.ports[-1]),self.r)
                else:
                    print('Access denied')
                    self.r = if_(match(dstip=pkt['dstip'],srcip=pkt['srcip']),drop,self.r)

        self.update_policy()

    def super_spread(self,pkt):
        #print('super spread triggered.')
        SYN = 0
        FIN = 1
        THRESHOLD = 5
        src = pkt['srcip']
        #print('src %s' % src)
        print('tcpflag is %d' % pkt['tcpflag'])
        if(pkt['tcpflag']==2):
            print('super spread triggered')
            if self.spread.has_key(src):
                self.spread[src] += 1
                print('src %s +1' % src)
                print('src now is %d' % self.spread[src])
                if self.spread[src] == THRESHOLD:
                    self.super_spreader.append(src)
                    print('src %s is in super_spreader list' % src)
            else:
                self.spread[src] = 1
        else:
             if(pkt['tcpflag']==1):
                 if self.spread.has_key(src):
                     print('src %s -1' % src)
                     self.spread[src] -= 1    

    def update_policy(self):
        self.policy = self.r+self.firewall_query+self.tcpdetect
        #print(self.policy)

def main():
    return rfss()
