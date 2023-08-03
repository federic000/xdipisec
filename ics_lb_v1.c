// ebpf/xdp kernel space 
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/bpf.h>
#include <linux/if_arp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <linux/udp.h>
#define BPF_LICENSE GPL

// this project has a constant number of IPSec termination IP's 
#define TEIP_N 4

// interface index map used to redirect packets out
BPF_DEVMAP(intfmap, 8);

// hash map to keep track of source IP and their destination 
struct src_ip {
     __be32 ipAddr;
};
BPF_HASH(teip_map, struct src_ip, int, 256);

// array counter used to distribute new tunnels across available interfaces 
BPF_ARRAY(rr_count, int, 1);

// array counter to keep track of processed packets 
BPF_PERCPU_ARRAY(pktcnt, long, 1);


static __always_inline int packetforwarder(struct xdp_md *ctx, __u64 nhoff, __u64 intf_idx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    __u16 h_proto;

    if (data + sizeof(struct ethhdr) > data_end)
       return XDP_DROP;

    h_proto = eth->h_proto;
    // push proper mac_dest on the out_interface to TEIPs 
    if (h_proto == htons(ETH_P_IP)) {
       
	if (intf_idx == 1) {
        eth->h_dest[0] = 0xaa;
        eth->h_dest[1] = 0xbb;
        eth->h_dest[2] = 0xcc;
        eth->h_dest[3] = 0x00;
        eth->h_dest[4] = 0x00;
        eth->h_dest[5] = 0x01;
        } 

        if (intf_idx == 2) {
        eth->h_dest[0] = 0xaa;
        eth->h_dest[1] = 0xbb;
        eth->h_dest[2] = 0xcc;
        eth->h_dest[3] = 0x00;
        eth->h_dest[4] = 0x00;
        eth->h_dest[5] = 0x02;
        }

        if (intf_idx == 3) {
        eth->h_dest[0] = 0xaa;
        eth->h_dest[1] = 0xbb;
        eth->h_dest[2] = 0xcc;
        eth->h_dest[3] = 0x00;
        eth->h_dest[4] = 0x00;
        eth->h_dest[5] = 0x03;
        }

        if (intf_idx == 4) {
        eth->h_dest[0] = 0xaa;
	eth->h_dest[1] = 0xbb;
	eth->h_dest[2] = 0xcc;
	eth->h_dest[3] = 0x00;
        eth->h_dest[4] = 0x00;
	eth->h_dest[5] = 0x04;
	}
    } 

   // update packet counter and send packet out to selected interface index  
   pktcnt.increment(0); 
   return intfmap.redirect_map(intf_idx, 0); 
   }

int xdp_redirect_ingr(struct xdp_md *ctx)
{
   void* data_end = (void*)(long)ctx->data_end;
   void* data = (void*)(long)ctx->data;
   struct ethhdr *eth = data;
   int *ptr1; 
   int tkey = 0;
   int zero = 0;
   uint64_t nh_off;
   long *value; 
   nh_off = sizeof(*eth);
   if (data + nh_off  > data_end)
        return XDP_DROP;
   struct iphdr *ip = data + sizeof(struct ethhdr);
   if ((void *)(ip + 1) > data_end) {
       return XDP_DROP; 
       }
   uint16_t layer3_t = ip->protocol;
   __u32 ip_src = ip->saddr; 

   if (eth->h_proto == htons(ETH_P_ARP)) {
        // ARP always goes through interface with index 1   
        struct arphdr *arp = data + sizeof(struct ethhdr);
        if ((void *)(arp + 1) > data_end)
             return XDP_DROP;
        else 
           return packetforwarder(ctx, nh_off, 1);
	   
   } 
  
   if (layer3_t == IPPROTO_ICMP) {
        // allows ICMP - echo request type only 
        struct icmphdr *icmp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
             if ((void *)(icmp + 1) > data_end)
                 return XDP_DROP;
             else {
               if (icmp->type == ICMP_ECHO) {
                 int *ipval = teip_map.lookup(&ip_src);
                 if (ipval != NULL) {
                    return packetforwarder(ctx, nh_off, *ipval);
                    }
                    else {
                       ptr1 = rr_count.lookup(&zero);
                       if (ptr1){
                          *ptr1 += 1;
                          tkey = *ptr1;
                          if (tkey > TEIP_N) {
                          tkey = 1; 
                          rr_count.update(&zero, &tkey);
                          }
                          teip_map.insert(&ip_src, &tkey);
                          return packetforwarder(ctx, nh_off, &tkey);
                       }
                    }
               }
             }
   }        

   if (layer3_t == IPPROTO_ESP) {
       // allows ESP packets - no need to check for new IPs  
       struct ip_esp_hdr *esp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
             if ((void *)(esp + 1) > data_end)
                 return XDP_DROP;
             else {
                 int *ipval = teip_map.lookup(&ip_src);
                 if (ipval != NULL) {
                     return packetforwarder(ctx, nh_off, *ipval);
                 }
             }
    }

   struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
   if ((layer3_t == IPPROTO_UDP) && ((ntohs(udp->dest) == 500) )) { 
       // allows UDP:500 ISAKMP port 
             if ((void *)(udp + 1) > data_end)
                 return XDP_DROP;
             else {
                int *ipval = teip_map.lookup(&ip_src);
                if (ipval != NULL) {
                    return packetforwarder(ctx, nh_off, *ipval);
                } 
                else {
                   ptr1 = rr_count.lookup(&zero);
                   if (ptr1){
                       *ptr1 += 1;
                        tkey = *ptr1;
                        if (tkey > TEIP_N) {
                        tkey = 1; 
                        rr_count.update(&zero, &tkey);
                        }
                        teip_map.insert(&ip_src, &tkey);
                        return packetforwarder(ctx, nh_off, &tkey);
                   }
                }
              } 
     }      


   // EVENTUALLY DROP ANYTHING ELSE other than ICMP-echo|UDP:500|ESP
   return XDP_DROP; 
}

int xdp_redirect_egr(struct xdp_md *ctx)
{
   // on the way back to tunnel initatior...
   void* data_end = (void*)(long)ctx->data_end;
   void* data = (void*)(long)ctx->data;
   struct ethhdr *eth = data;
   uint32_t key = 0;
   uint64_t nh_off;

   nh_off = sizeof(*eth);
   if (data + nh_off  > data_end)
        return XDP_DROP;
   struct iphdr *ip = data + sizeof(struct ethhdr);
   if ((void *)(ip + 1) > data_end) {
       return XDP_DROP; }

   return intfmap.redirect_map(0, 0);

}



