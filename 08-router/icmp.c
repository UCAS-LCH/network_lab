#include "icmp.h"
#include "ip.h"
#include "rtable.h"
#include "arp.h"
#include "base.h"

#include <stdio.h>
#include <stdlib.h>

// send icmp packet
void icmp_send_packet(const char *in_pkt, int len, u8 type, u8 code)
{
	//fprintf(stderr, "TODO: malloc and send icmp packet.\n");
    
    //extrac orignal packet  	
    struct iphdr *ori_ip_hdr = packet_to_ip_hdr(in_pkt);
	u32 dst = ntohl(ori_ip_hdr->saddr);
	u32 src = ntohl(ori_ip_hdr->daddr);
	
	long size;	
    if (type != ICMP_ECHOREPLY) {//send packet error
        size = ETHER_HDR_SIZE + IP_BASE_HDR_SIZE + ICMP_HDR_SIZE + IP_HDR_SIZE(ori_ip_hdr) + 8;
    } else {
        size = len - IP_HDR_SIZE(ori_ip_hdr) + IP_BASE_HDR_SIZE;
    }

    char *packet = (char*) malloc(size);

	//encapsulate ether header
    struct ether_header *eh = (struct ether_header *)packet;
	eh->ether_type = htons(ETH_P_IP);

	//encapsulate ip header
	struct iphdr *cur_ip_hdr = packet_to_ip_hdr(packet);
	ip_init_hdr(cur_ip_hdr,src,dst,size - ETHER_HDR_SIZE,IPPROTO_ICMP);
	
	//icmp
	struct icmphdr *icmp = (struct icmphdr *)IP_DATA(ori_ip_hdr);
	memset(icmp,0,ICMP_HDR_SIZE);
    icmp->code = code;
    icmp->type = type;
	if(type != ICMP_ECHOREPLY)
	    memcpy((char *)icmp+8,ori_ip_hdr,IP_HDR_SIZE(ori_ip_hdr)+8);
	else
		memcpy((char *)icmp+4,in_pkt + ETHER_HDR_SIZE + IP_HDR_SIZE(ori_ip_hdr)+4,size - ETHER_HDR_SIZE - IP_BASE_HDR_SIZE-4);
    icmp->checksum = icmp_checksum(icmp,size- ETHER_HDR_SIZE - IP_BASE_HDR_SIZE);
	
	ip_send_packet(packet,size);
	
}
