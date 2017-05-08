#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller
from mininet.util import dumpNodeConnections
from mininet.node import OVSSwitch
from mininet.node import RemoteController
from mininet.cli import CLI
import requests
import json

class SingleSwitchTopo(Topo):
    "Single switch connected to n hosts."
    def __init__(self, n=2, **opts):
        # Initialize topology and default options
        Topo.__init__(self, **opts)
        switch = self.addSwitch('s1')
        # Python's range(N) generates 0..N-1
        for h in range(n):
            host = self.addHost('h%s' % (h + 1))
            self.addLink(host, switch)

def setHosts(net):
    h1 = net.get('h1')
    h2 = net.get('h2')
    h1.setIP('10.0.0.1',8)
    h2.setIP('10.0.0.2',8)
    

def rest(tcp1,tcp2,tcp3,tcp4,tcp5):
    url = 'http://localhost:8080/stats/flowentry/add'
    payload = { "dpid": 1, "priority":10, "match": { "in_port": 1}, "actions": [{ "type": "OUTPUT", "port": 2} ] }
    r=requests.post(url, json.dumps(payload))

    payload = { "dpid": 1, "priority":10, "match": { "in_port": 2}, "actions": [{ "type": "OUTPUT", "port": 1} ] }
    r=requests.post(url, json.dumps(payload))
       
    payload = { "dpid": 1, "priority":100, "match": { "ipv4_dst": "10.0.0.2", "ip_proto": 6, "eth_type": 2048, "tcp_dst": tcp1, "in_port": 1}, "actions": [ { "type": "SET_FIELD", "field": "tcp_dst", "value": tcp2, "port":1}, { "type": "OUTPUT", "port": 2} ] }
    r=requests.post(url, json.dumps(payload))
    
   
    payload = { "dpid": 1, "priority":100, "match": { "ipv4_src": "10.0.0.2", "ip_proto": 6, "eth_type": 2048, "tcp_src": tcp2, "in_port": 2}, "actions": [ { "type": "SET_FIELD", "field": "tcp_src", "value": tcp1, "port":1}, { "type": "OUTPUT", "port": 1} ] }
    r=requests.post(url, json.dumps(payload))

    payload = { "dpid": 1, "priority":100, "match": { "ipv4_src": "10.0.0.2", "ip_proto": 6, "eth_type": 2048, "tcp_src": tcp3, "in_port": 2}, "actions": [ { "type": "SET_FIELD", "field": "tcp_src", "value": tcp1, "port":1}, { "type": "OUTPUT", "port": 1} ] }
    r=requests.post(url, json.dumps(payload))

    payload = { "dpid": 1, "priority":100, "match": { "ipv4_src": "10.0.0.2", "ip_proto": 6, "eth_type": 2048, "tcp_src": tcp4, "in_port": 2}, "actions": [ { "type": "SET_FIELD", "field": "tcp_src", "value": tcp1, "port":1}, { "type": "OUTPUT", "port": 1} ] }
    r=requests.post(url, json.dumps(payload))

    payload = { "dpid": 1, "priority":100, "match": { "ipv4_src": "10.0.0.2", "ip_proto": 6, "eth_type": 2048, "tcp_src": tcp5, "in_port": 2}, "actions": [ { "type": "SET_FIELD", "field": "tcp_src", "value": tcp1, "port":1}, { "type": "OUTPUT", "port": 1} ] }
    r=requests.post(url, json.dumps(payload))
       
def genericTest(topo):
    c0=RemoteController( 'c0', ip='127.0.0.1', port=6633 )
    net = Mininet(topo=topo, switch=OVSSwitch,
                  controller=c0)
    net.start()
    setHosts(net)
    dumpNodeConnections(net.hosts)
    x=input("Enter port1: ")
    y=input("Enter port2: ")
    z=input("Enter port3: ")
    a=input("Enter port4: ")
    b=input("Enter port5: ")
         
    rest(x,y,z,a,b)
    CLI(net)

    net.stop()
   
def main():
    topo = SingleSwitchTopo()
    genericTest(topo)


if __name__ == '__main__':
    main()

