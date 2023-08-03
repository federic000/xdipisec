#!/bin/sh

cd /home/shscripts
ip link set eth1 address aa:bb:cc:00:00:03
ip address add 192.0.0.2/24 dev eth1
##
ip address add 10.2.2.2/32 dev lo
# add strongswan config 
cat ipsec.conf.template > /etc/ipsec.conf
ip neigh add 192.0.0.1 lladdr aa:00:00:00:00:01 dev eth1 nud permanent
ip neigh change 192.0.0.1 lladdr aa:00:00:00:00:01 dev eth1 nud permanent
# route back to client
ip route add 192.0.0.0/8 via 192.0.0.1 
# start strongswan 
ipsec start


