# SDN-Firewall-ACL-Application

## Installation guide:
> Install mininet  : http://mininet.org/download/
>
> Use:  mininer/install/install.sh -a <br>
  The option -a install all required packages, such as Openflow, Wireshark as part of the mininet installation
  
> Install  python 3


## Application Test:
> Terminal 1 run topology:   ``Sudo python topology.py``

> Terminal 2 run controller:  ``ryu-manager –observe-links app.py``

> Terminal 3 run wireshark: ``sudo wireshark``

> Terminal 1 in mininet CLI run: ``pingall``
