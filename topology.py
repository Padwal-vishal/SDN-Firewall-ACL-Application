#!/usr/bin/python


from import_topology import *

def topology():
    '*** Create a network and controller\n'
    net = Mininet(controller=RemoteController, switch=OVSKernelSwitch)
    protocolName = "OpenFlow13"

    info("*** Creating the controller\n\n")
    c0 = net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    info("*** Added Controller:c0\n\n")

    
    info("*** Creating the nodes\n\n")
     
    h1 = net.addHost('h1', ip='10.1.1.1/24', position='10,10,0')
    h2 = net.addHost('h2', ip='10.1.1.2/24', position='20,10,0')
    h3 = net.addHost('h3', ip='10.1.1.3/24', position='30,10,0')
    h4 = net.addHost('h4', ip='10.1.1.4/24', position='40,10,0')
    h5 = net.addHost('h5', ip='10.1.1.5/24', position='50,10,0')
    h6 = net.addHost('h6', ip='10.1.1.6/24', position='60,10,0')
    info("*** Nodes Created:h1,h2,h3,h4,h5,h6\n\n")
    
    info("*** Creating the switch\n\n")
    switch1 = net.addSwitch('switch1', protocols=protocolName, position='12,10,0')
    info("*** Switch1 created\n\n")
    

    
    info("*** Adding the Link\n\n")
    net.addLink(h1, switch1)
    net.addLink(h2, switch1)
    net.addLink(h3, switch1)
    net.addLink(h4, switch1)
    net.addLink(h5, switch1)
    net.addLink(h6, switch1)
    info("*** Links Added:(h1, switch1),(h2, switch1),(h3, switch1),(h4, switch1),(h5, switch1),(h6, switch1)\n\n")
  

    info("*** Starting the network\n\n")
    net.build()
    c0.start()
    switch1.start([c0])
   
    
    info("*** Running the CLI \n\n")
    CLI( net )

    info("*** Stopping network \n\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
