#!/bin/bash

# unload the xdp object from interfaces 

ip link set dev eth1 xdpgeneric off 
ip link set dev eth2 xdpgeneric off 
ip link set dev eth3 xdpgeneric off 
ip link set dev eth4 xdpgeneric off 
ip link set dev eth5 xdpgeneric off

