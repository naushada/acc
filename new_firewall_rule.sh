#!/bin/sh

PTABLES=/sbin/iptables

WANIF='eth0'
LANIF='tun0'

# enable ip forwarding in the kernel
echo 'Enabling Kernel IP forwarding...'
/bin/echo 1 > /proc/sys/net/ipv4/ip_forward

# flush rules and delete chains
echo 'Flushing rules and deleting existing chains...'
iptables -F
iptables -X

# enable masquerading to allow LAN internet access
echo 'Enabling IP Masquerading and other rules...'
iptables -t nat -A POSTROUTING -o $LANIF -j MASQUERADE
iptables -A FORWARD -i $LANIF -o $WANIF -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $WANIF -o $LANIF -j ACCEPT

iptables -t nat -A POSTROUTING -o $WANIF -j MASQUERADE
iptables -A FORWARD -i $WANIF -o $LANIF -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i $LANIF -o $WANIF -j ACCEPT
