"""
Zero Trust Network Topology for Mininet.

Simulates an enterprise network with:
- 1 OVS switch (OpenFlow 1.3)
- 4 hosts: 2 employees (h1, h2), 1 server (h3), 1 attacker (h4)
- Remote Ryu SDN controller

Architecture:
    h1 (Employee 1)  ──┐
    h2 (Employee 2)  ──┤
    h3 (Server)      ──┼── s1 (OVS Switch) ──── Ryu Controller (c0)
    h4 (Attacker)    ──┘
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import sys
import os


class ZeroTrustTopo(Topo):
    """Custom topology for Zero Trust Network simulation."""

    def build(self):
        info('*** Creating Zero Trust Network Topology\n')

        # Add the central OVS switch
        s1 = self.addSwitch('s1', cls=OVSKernelSwitch, protocols='OpenFlow13')

        # Add hosts with distinct MAC and IP addresses
        # Employees (normal users)
        h1 = self.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
        h2 = self.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')

        # Server (target resource)
        h3 = self.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')

        # Attacker (will generate anomalous traffic)
        h4 = self.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

        # Add links with bandwidth constraints (simulating real network)
        # TCLink allows traffic control (bandwidth, delay, loss)
        self.addLink(h1, s1, cls=TCLink, bw=100, delay='2ms')
        self.addLink(h2, s1, cls=TCLink, bw=100, delay='2ms')
        self.addLink(h3, s1, cls=TCLink, bw=1000, delay='1ms')  # Server has faster link
        self.addLink(h4, s1, cls=TCLink, bw=100, delay='2ms')


def start_network(controller_ip='127.0.0.1', controller_port=6633):
    """Start the Mininet network with remote Ryu controller."""
    setLogLevel('info')

    info('*** Starting Zero Trust SDN Network\n')
    info(f'*** Connecting to Ryu controller at {controller_ip}:{controller_port}\n')

    topo = ZeroTrustTopo()

    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(
            name,
            ip=controller_ip,
            port=controller_port
        ),
        switch=OVSKernelSwitch,
        link=TCLink,
        autoSetMacs=False,  # We set MACs explicitly
        autoStaticArp=False,
    )

    net.start()

    info('\n*** Network started successfully!\n')
    info('*** Host information:\n')
    for host in net.hosts:
        info(f'    {host.name}: IP={host.IP()}, MAC={host.MAC()}\n')

    info('\n*** Switch information:\n')
    for switch in net.switches:
        info(f'    {switch.name}: dpid={switch.dpid}\n')

    return net


def run_interactive(controller_ip='127.0.0.1', controller_port=6633):
    """Run the network with an interactive CLI."""
    net = start_network(controller_ip, controller_port)

    info('\n*** Running CLI (type "help" for commands, "exit" to quit)\n')
    CLI(net)

    info('*** Stopping network\n')
    net.stop()


if __name__ == '__main__':
    controller_ip = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    controller_port = int(sys.argv[2]) if len(sys.argv) > 2 else 6633
    run_interactive(controller_ip, controller_port)
