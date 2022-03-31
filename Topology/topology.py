#!/usr/bin/python


from import_topology import *

def topology():
    'Create a network and controller'
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch)
    protocolName = "OpenFlow13"

    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    
    
    info("*** Creating the nodes\n")
     
    h1 = net.addHost('h1', ip='10.0.0.1/24', position='10,10,0')
    h2 = net.addHost('h2', ip='10.0.0.2/24', position='20,10,0')
	h3 = net.addHost('h3', ip='10.0.0.3/24', position='30,10,0')
    h4 = net.addHost('h4', ip='10.0.0.4/24', position='40,10,0')
	h5 = net.addHost('h5', ip='10.0.0.5/24', position='50,10,0')
    h6 = net.addHost('h6', ip='10.0.0.6/24', position='60,10,0')
    
    switch1 = net.addSwitch('switch1', protocols=protocolName, position='12,10,0')
    

    
    info("*** Adding the Link\n")
    net.addLink(h1, switch1)
	net.addLink(h2, switch1)
	net.addLink(h3, switch1)
	net.addLink(h4, switch1)
	net.addLink(h5, switch1)
	net.addLink(h6, switch1)
	
  

    info("*** Starting the network\n")
    net.build()
    c0.start()
    switch1.start([c0])
   
    

    net.pingFull()
    
    info("*** Running the CLI\n")
    CLI( net )

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()