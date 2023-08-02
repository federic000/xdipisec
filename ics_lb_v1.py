#!/usr/bin/python3
#
from bcc import BPF
import pyroute2
import datetime
import time 
import sys
import ctypes as ct 
from ctypes import *

flags = 0

def usage():
    print("redirect packets from int1 to int2-3-4... as a round-robin scheduler") 
    print("Usage: {0} <ifdev1> <ifdev2.../dev3/dev4/dev5> ".format(sys.argv[0]))
    print("e.g.: {0} eth1 eth2 eth3 eth4 eth5\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) != 6:
    usage()

# populate device index map
in_if = sys.argv[1]
out_if_1 = sys.argv[2]
out_if_2 = sys.argv[3]
out_if_3 = sys.argv[4]
out_if_4 = sys.argv[5]
ip = pyroute2.IPRoute()
index_1 = ip.link_lookup(ifname=in_if)[0]
index_2 = ip.link_lookup(ifname=out_if_1)[0]
index_3 = ip.link_lookup(ifname=out_if_2)[0]
index_4 = ip.link_lookup(ifname=out_if_3)[0]
index_5 = ip.link_lookup(ifname=out_if_4)[0]

# load BPF program by source file 
b = BPF(src_file="ics_lb_v1.c", cflags=["-w"])


print("populating interface index map...")
devmap = b["intfmap"]
devmap[c_uint32(0)] = c_int(index_1)
devmap[c_uint32(1)] = c_int(index_2) 
devmap[c_uint32(2)] = c_int(index_3)
devmap[c_uint32(3)] = c_int(index_4)
devmap[c_uint32(4)] = c_int(index_5)
print("interface indexing done...\n")

print("now attaching xdp to interfaces...\n")
b.attach_xdp(in_if, fn=b.load_func("xdp_redirect_ingr",BPF.XDP), flags=BPF.XDP_FLAGS_SKB_MODE)
b.attach_xdp(out_if_1, fn=b.load_func("xdp_redirect_egr",BPF.XDP), flags=BPF.XDP_FLAGS_SKB_MODE)
b.attach_xdp(out_if_2, fn=b.load_func("xdp_redirect_egr",BPF.XDP), flags=BPF.XDP_FLAGS_SKB_MODE)
b.attach_xdp(out_if_3, fn=b.load_func("xdp_redirect_egr",BPF.XDP), flags=BPF.XDP_FLAGS_SKB_MODE)
b.attach_xdp(out_if_4, fn=b.load_func("xdp_redirect_egr",BPF.XDP), flags=BPF.XDP_FLAGS_SKB_MODE)

print("something is going on..... hit CTRL+C to stop")
packetcounter = b["pktcnt"]
prev = [0] * 256
while 1:
    try:
        for k in packetcounter.keys():
            current_time = datetime.datetime.now()
            val = packetcounter.sum(k).value
            tot = packetcounter.sum(k)
            i = k.value
            if val:
               delta = val - prev[i]
               prev[i] = val
               print("{} total pkts - {} pkts-per-sec @ {}".format(tot, delta, current_time), end = '\r')
               print("# ", end = '\r') 
        time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n") 
        print("Removing filter from device --> please run ./unload_xdp.sh")
        break 



