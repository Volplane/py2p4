from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import *
from pyretic.core import packet

class routing(DynamicPolicy):
    def __init__(self):
        super(routing,self).__init__()
        self.ports = [1,2,3,4]
        self.r = None
        self.route()
        self.policy = self.r
        print(self.policy) 

    def route(self):
        for port in self.ports:
            addr = '10.0.0.%d' % port
            r_part = match(dstip=addr, ethtype=packet.IPV4) >> fwd(port)
            if self.r is None:
                self.r = r_part
                print('Rule %d added' % port)
            else:
                self.r += r_part
                print('Rule %d added' % port)

def main():
     return routing()
