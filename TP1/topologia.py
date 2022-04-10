from mininet.node import CPULimitedHost
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel, info
from mininet.node import RemoteController
from mininet.cli import CLI
from mininet.link import TCLink 

class Topologia(Topo):
    """Simple topology example."""

    def __init__(self, **opts):
        """Create custom topo."""

        # Initialize topology
        # It uses the constructor for the Topo cloass
        super(Topologia, self).__init__(**opts)

        # Add hosts and switches
        h1 = self.addHost('h1', ip="10.0.1.1/24", defaultRoute = "via 10.0.1.254")
        h2 = self.addHost('h2', ip="10.0.1.2/24", defaultRoute = "via 10.0.1.254")
        h3 = self.addHost('h3', ip="10.0.1.3/24", defaultRoute = "via 10.0.1.254")
        h4 = self.addHost('h4', ip="10.0.2.1/24", defaultRoute = "via 10.0.2.254")
        h5 = self.addHost('h5', ip="10.0.2.2/24", defaultRoute = "via 10.0.2.254")
        h6 = self.addHost('h6', ip="10.0.2.3/24", defaultRoute = "via 10.0.2.254")
        h7 = self.addHost('h7', ip="10.0.3.1/24", defaultRoute = "via 10.0.3.254")
        h8 = self.addHost('h8', ip="10.0.3.2/24", defaultRoute = "via 10.0.3.254")
        h9 = self.addHost('h9', ip="10.0.3.3/24", defaultRoute = "via 10.0.3.254")
        
        h10 = self.addHost('h10', ip="10.0.5.1/24", defaultRoute = "via 10.0.5.254")
        
        #self.h10 = self.addHost('h10', ip="10.0.1.69/24", defaultRoute = "via 10.0.1.254")

        # Adding switches
        s1 = self.addSwitch('s1', dpid="0000000000000001", protocols="OpenFlow13")
        s2 = self.addSwitch('s2', dpid="0000000000000002", protocols="OpenFlow13")
        s3 = self.addSwitch('s3', dpid="0000000000000003", protocols="OpenFlow13")
        s4 = self.addSwitch('s4', dpid="0000000000000004", protocols="OpenFlow13")
        s5 = self.addSwitch('s5', dpid="0000000000000005", protocols="OpenFlow13")
        
        #def 	addLink (self, node1, node2, port1=None, port2=None, cls=None, **params)


        # Add links
        self.addLink(h1, s1)
        self.addLink(h2, s1)
        self.addLink(h3, s1)

       
        self.addLink(h4, s2)
        self.addLink(h5, s2)
        self.addLink(h6, s2, cls=TCLink, delay='5ms')

        self.addLink(h7, s3)
        self.addLink(h8, s3)
        self.addLink(h9, s3, cls=TCLink, loss=10)

        self.addLink(s1, s4, cls=TCLink, delay='5ms')
        self.addLink(s2, s4)
        self.addLink(s3, s4)

        self.addLink(s4, s5)

        self.addLink(s5, h10)