#!/bin/sh

cd /home/
ip link set eth9 address aa:00:00:00:00:01
ip address add 192.0.0.1/24 dev eth9
##
ip address add 192.0.1.1/24 dev eth1
ip address add 192.0.2.1/24 dev eth2
ip address add 192.0.3.1/24 dev eth3
ip address add 192.0.4.1/24 dev eth4
ip address add 192.0.5.1/24 dev eth5
ip address add 192.0.6.1/24 dev eth6
ip address add 192.0.7.1/24 dev eth7
ip address add 192.0.8.1/24 dev eth8
##
ip neigh add 192.0.0.2 lladdr aa:bb:cc:00:00:01 dev eth9 nud permanent
ip neigh change 192.0.0.2 lladdr aa:bb:cc:00:00:01 dev eth9 nud permanent

