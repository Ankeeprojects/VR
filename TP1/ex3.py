from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller, RemoteController
from topologia import Topologia
from mininet.log import setLogLevel
from mininet.cli import CLI
import threading
import time
    

def alterar_link(net):
    time.sleep(65)
    net.configLinkStatus('s4','s7','down')


setLogLevel( 'info' )

c0 = RemoteController( 'c0', ip='127.0.0.1',port=6653, protocols="OpenFlow13")
c1 = RemoteController( 'c1', ip='127.0.0.1',port=6654, protocols="OpenFlow13")

cmap = { 's1': c0, 's2': c0, 's3': c0 , 's4': c1, 's5' : c1, 's6' : c0, 's7' : c1, 's8' : c0, 's9' : c0}

class MultiSwitch( OVSSwitch ):
    def start( self, controllers ):
        return OVSSwitch.start( self, [ cmap[ self.name ] ] )

topo = Topologia()
net = Mininet( topo=topo, switch=MultiSwitch, build=False, waitConnected=True )

threading.Thread(target=alterar_link, args=(net,)).start()

for c in [ c0, c1 ]:
    net.addController(c)

net.build() 
net.start()


CLI( net )
net.stop()

