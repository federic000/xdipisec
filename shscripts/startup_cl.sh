#!/bin/sh
# setup client IP addresses and config
cd /home/
ip link set eth1 address aa:00:00:00:00:01
ip address add 192.0.0.1/24 dev eth1
ip address add 192.0.1.1/24 dev eth1
ip address add 192.0.2.1/24 dev eth1
ip address add 192.0.3.1/24 dev eth1
ip address add 192.0.4.1/24 dev eth1
ip address add 192.0.5.1/24 dev eth1
ip address add 192.0.6.1/24 dev eth1
ip address add 192.0.7.1/24 dev eth1
ip address add 192.0.8.1/24 dev eth1
ip address add 192.0.9.1/24 dev eth1
ip address add 192.0.10.1/24 dev eth1

##
ip address add 10.1.0.1/32 dev lo
ip address add 10.1.0.2/32 dev lo
ip address add 10.1.0.3/32 dev lo
ip address add 10.1.0.4/32 dev lo
ip address add 10.1.0.5/32 dev lo
ip address add 10.1.0.6/32 dev lo
ip address add 10.1.0.7/32 dev lo
ip address add 10.1.0.8/32 dev lo
ip address add 10.1.0.9/32 dev lo
ip address add 10.1.0.10/32 dev lo

## push strongswan configuration 
cat ipsec.conf.template.client > /etc/ipsec.conf
# start strongswan/charon daemon
ipsec start



