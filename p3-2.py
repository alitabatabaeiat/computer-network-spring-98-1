from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


def myNet():
    "Create an empty network and add nodes to it."

    net = Mininet(controller=Controller, link=TCLink)

    info('# Adding controller\n')
    net.addController('c0')

    info("# Add hosts and switches\n")
    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    h3 = net.addHost('h3')
    h4 = net.addHost('h4')
    s1 = net.addSwitch('s1')
    s2 = net.addSwitch('s2')

    info("# Add links\n")
    net.addLink(h1, s1, delay='20ms')
    net.addLink(h2, s1, delay='20ms')
    net.addLink(h3, s2, delay='15ms')
    net.addLink(h4, s2, delay='1s')
    net.addLink(s1, s2, delay='50ms')

    info('# Starting network\n')
    net.start()

    info('# Running CLI\n')
    CLI(net)

    info('# Stopping network')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    myNet()