#include "arp.h"
#include "base.h"
#include "types.h"
#include "packet.h"
#include "ether.h"
#include "arpcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// #include "log.h"

// send an arp request: encapsulate an arp request packet, send it out through
// iface_send_packet
void arp_send_request(iface_info_t *iface, u32 dst_ip)
{
	fprintf(stderr, "TODO: send arp request when lookup failed in arpcache.\n");
		
    struct ether_header *eh =(ether_header*) malloc(ETHER_HDR_SIZE);
	eh->ether_type = htons(ETH_P_ARP);
    memset(eh->ether_dhost, 0xff, ETH_ALEN);
    memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	
	struct ether_arp *arp_info=(ether_arp*) malloc(sizeof(struct ether_arp));
	memset(arp_info,0,sizeof(struct ether_arp));
	
	arp_info->arp_hrd = htons(0x01);
	arp_info->arp_pro = htons(ETH_P_IP);
	arp_info->arp_hln = 6;
	arp_info->arp_pln = 4;
	arp_info->arp_op = htons(ARPOP_REQUEST);
	memcpy(arp_info->arp_sha, iface->mac, ETH_ALEN);
	arp_info->arp_spa = htonl(iface->ip);
	arp_info->arp_tpa = htonl(dst_ip);
	
	int len=ETHER_HDR_SIZE + sizeof(struct ether_arp);
	
	char *packet = malloc(len);
	memcpy(packet, eh, ETHER_HDR_SIZE);
	memcpy(packet + ETHER_HDR_SIZE, arp_info, sizeof(struct ether_arp));
	
	iface_send_packet(iface, packet, len);
	
}

// send an arp reply packet: encapsulate an arp reply packet, send it out
// through iface_send_packet
void arp_send_reply(iface_info_t *iface, struct ether_arp *req_hdr)
{
	fprintf(stderr, "TODO: send arp reply when receiving arp request.\n");
	
	struct ether_header *eh =(ether_header*) malloc(ETHER_HDR_SIZE);
	eh->ether_type = htons(ETH_P_ARP);
    memcpy(eh->ether_dhost,req_hdr->sha, ETH_ALEN);
    memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	
	struct ether_arp *arp_info=(ether_arp*) malloc(sizeof(struct ether_arp));
	memset(arp_info,0,sizeof(struct ether_arp));
	
	arp_info->arp_hrd = htons(0x01);
	arp_info->arp_pro = htons(ETH_P_IP);
	arp_info->arp_hln = 6;
	arp_info->arp_pln = 4;
	arp_info->arp_op = htons(ARPOP_REPLY);
	memcpy(arp_info->arp_sha, iface->mac, ETH_ALEN);
	arp_info->arp_spa = htonl(iface->ip);
	memcpy(arp_info->arp_tha, req_hdr->sha, ETH_ALEN);
	arp_info->arp_tpa = req_hdr->spa;
	
	int len=ETHER_HDR_SIZE + sizeof(struct ether_arp);
	
	char *packet = malloc(len);
	memcpy(packet, eh, ETHER_HDR_SIZE);
	memcpy(packet + ETHER_HDR_SIZE, arp_info, sizeof(struct ether_arp));
	
	iface_send_packet(iface, packet, len);
}

void handle_arp_packet(iface_info_t *iface, char *packet, int len)
{
	fprintf(stderr, "TODO: process arp packet: arp request & arp reply.\n");
		
    struct ether_arp *arp = (struct ether_arp *)(packet + ETHER_HDR_SIZE);
    u32 src_ip = ntohl(arp->arp_spa);
    u32 dst_ip = ntohl(arp->arp_tpa);
    u16 op = ntohs(arp->arp_op);
	
	if(op==ARPOP_REPLY)
		arpcache_insert(src_ip,arp->arp_sha);
	else if(op==ARPOP_REQUEST && dst_ip==iface->ip){
		arp_send_reply(iface,arp);
		arpcache_insert(src_ip,arp->arp_sha);
	}
		
}

// send (IP) packet through arpcache lookup 
//
// Lookup the mac address of dst_ip in arpcache. If it is found, fill the
// ethernet header and emit the packet by iface_send_packet, otherwise, pending 
// this packet into arpcache, and send arp request.
void iface_send_packet_by_arp(iface_info_t *iface, u32 dst_ip, char *packet, int len)
{
	struct ether_header *eh = (struct ether_header *)packet;
	memcpy(eh->ether_shost, iface->mac, ETH_ALEN);
	eh->ether_type = htons(ETH_P_IP);

	u8 dst_mac[ETH_ALEN];
	int found = arpcache_lookup(dst_ip, dst_mac);
	if (found) {
		// log(DEBUG, "found the mac of %x, send this packet", dst_ip);
		memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
		iface_send_packet(iface, packet, len);
	}
	else {
		// log(DEBUG, "lookup %x failed, pend this packet", dst_ip);
		arpcache_append_packet(iface, dst_ip, packet, len);
	}
}
