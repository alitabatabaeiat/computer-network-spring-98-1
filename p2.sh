#!/bin/bash
ip -all netns delete
ovs-vsctl del-br s1
ovs-vsctl del-br s2
ip link delete s1-eth0
ip netns add h1
ip netns add h2
ip netns add h3
ovs-vsctl add-br s1
ovs-vsctl add-br s2
ip link add h1-eth0 type veth peer name s1-eth1
ip link add h2-eth0 type veth peer name s1-eth2
ip link add h3-eth0 type veth peer name s2-eth1
ip link add s1-eth0 type veth peer name s2-eth0
ip link set h1-eth0 netns h1
ip link set h2-eth0 netns h2
ip link set h3-eth0 netns h3
ovs-vsctl add-port s1 s1-eth0
ovs-vsctl add-port s1 s1-eth1
ovs-vsctl add-port s1 s1-eth2
ovs-vsctl add-port s2 s2-eth0
ovs-vsctl add-port s2 s2-eth1
ip link set s1-eth0 up
ip link set s1-eth1 up
ip link set s1-eth2 up
ip link set s2-eth0 up
ip link set s2-eth1 up
ip netns exec h1 ip link set h1-eth0 up
ip netns exec h2 ip link set h2-eth0 up
ip netns exec h3 ip link set h3-eth0 up
ip netns exec h1 ifconfig h1-eth0 10.0.0.1/24
ip netns exec h2 ifconfig h2-eth0 10.0.0.2/24
ip netns exec h3 ifconfig h3-eth0 10.0.0.3/24
ip netns exec h1 ping -c1 10.0.0.3
