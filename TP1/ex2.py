from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller, RemoteController
from topologia import Topologia
from mininet.log import setLogLevel
from mininet.cli import CLI
import threading
import time

def adicionar_link(net):
    time.sleep(1)
    print("cenas\n")
    net.configLinkStatus('s1','h3','down')
    time.sleep(3)
    net.configLinkStatus('s4', 'h10', 'up')
    #net.addLink('s1','h10')


    
    
setLogLevel( 'info' )

c0 = RemoteController( 'c0', ip='127.0.0.1',port=6653, protocols="OpenFlow13")
c1 = RemoteController( 'c1', ip='127.0.0.1',port=6654, protocols="OpenFlow13")

cmap = { 's1': c0, 's2': c0, 's3': c0 , 's4': c1}

class MultiSwitch( OVSSwitch ):
    def start( self, controllers ):
        return OVSSwitch.start( self, [ cmap[ self.name ] ] )

topo = Topologia()
net = Mininet( topo=topo, switch=MultiSwitch, build=False, waitConnected=True )
for c in [ c0, c1 ]:
    net.addController(c)

net.build()
threading.Thread(target=adicionar_link, args=(net,)).start()
net.configLinkStatus('s1','h10','down') 
net.start()


CLI( net )
net.stop()

