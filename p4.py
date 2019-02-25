from mininet.net import Mininet
from mininet.node import Controller
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

delay = '90ms'
bandwidth = 15
queue = 15
switch_num = 7


def myNet():
    "Create an empty network and add nodes to it."
    linkopts = dict(bw=bandwidth, delay=delay, max_queue_size=queue)
    net = Mininet(controller=Controller, link=TCLink)

    info('# Adding controller\n')
    net.addController('c0')

    info("# Add hosts and switches\n")
    h1 = net.addHost('h1')
    h2 = net.addHost('h2')
    for i in range(switch_num):
        switch = net.addSwitch('s%s' % (i + 1))
        if i > 0:
            previous_switch = net.getNodeByName('s%s' % i)
            net.addLink(switch, previous_switch, **linkopts)

    s1 = net.getNodeByName('s1')
    sn = net.getNodeByName('s%s' % (switch_num))
    net.addLink(h1, s1, **linkopts)
    net.addLink(h2, sn, **linkopts)

    info('# Starting network\n')
    net.start()

    info('# Running CLI\n')
    CLI(net)

    info('# Stopping network')
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    myNet()
