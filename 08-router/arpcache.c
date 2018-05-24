#include "arpcache.h"
#include "arp.h"
#include "ether.h"
#include "packet.h"
#include "icmp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

static arpcache_t arpcache;

// initialize IP->mac mapping, request list, lock and sweeping thread
void arpcache_init()
{
	bzero(&arpcache, sizeof(arpcache_t));

	init_list_head(&(arpcache.req_list));

	pthread_mutex_init(&arpcache.lock, NULL);

	pthread_create(&arpcache.thread, NULL, arpcache_sweep, NULL);
}

// release all the resources when exiting
void arpcache_destroy()
{
	pthread_mutex_lock(&arpcache.lock);

	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		struct cached_pkt *pkt_entry = NULL, *pkt_q;
		list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
			list_delete_entry(&(pkt_entry->list));
			free(pkt_entry->packet);
			free(pkt_entry);
		}

		list_delete_entry(&(req_entry->list));
		free(req_entry);
	}

	pthread_kill(arpcache.thread, SIGTERM);

	pthread_mutex_unlock(&arpcache.lock);
}

// lookup the IP->mac mapping
//
// traverse the hash table to find whether there is an entry with the same IP
// and mac address with the given arguments
int arpcache_lookup(u32 ip4, u8 mac[ETH_ALEN])
{
	fprintf(stderr, "TODO: lookup ip address in arp cache.\n");
    for(int i=0;i<32;i++){
		if(arpcache.entries[i].ip4==ip4){
			memcpy(mac,arpcache.entries[i].mac,ETH_ALEN);
			return 1;
		}
	}
	
	return 0;
}

// append the packet to arpcache
//
// Lookup in the hash table which stores pending packets, if there is already an
// entry with the same IP address and iface (which means the corresponding arp
// request has been sent out), just append this packet at the tail of that entry
// (the entry may contain more than one packet); otherwise, malloc a new entry
// with the given IP address and iface, append the packet, and send arp request.
void arpcache_append_packet(iface_info_t *iface, u32 ip4, char *packet, int len)
{
	fprintf(stderr, "TODO: append the ip address if lookup failed, and send arp request if necessary.\n");
	pthread_mutex_lock(&arpcache.lock);
	struct arp_req *req_entry = NULL, *req_q;
	struct cached_pkt *pkt_entry = malloc(sizeof(struct cached_pkt));
	pkt_entry->packet=packet;
	pkt_entry->len=len;
	
	int found=0;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		if(req_entry->ip4==ip4 && req_entry->iface==iface){
			list_add_tail(&(pkt_entry->list), &(req_entry->cached_packets));
			found=1;
		}
		
		if(found==0){
			struct arp_req *req_new=malloc(sizeof(struct aqr_req));
	        init_list_head(&(req_new->list));
	        req_new->iface=iface;
	        req_new->ip4=ip4;
	        req_new->sent=time(NULL);
	        req_new->retries=1;
	        init_list_head(&(req_new->cached_packets));
			list_add_tail(&(pkt_entry->list), &(req_new->cached_packets));
			list_add_tail(&(req_new->list),&(arpcache.req_list));
			arp_send_request(iface,ip4);
		}
	}
    pthread_mutex_unlock(&arpcache.lock);	
}

// insert the IP->mac mapping into arpcache, if there are pending packets
// waiting for this mapping, fill the ethernet header for each of them, and send
// them out
void arpcache_insert(u32 ip4, u8 mac[ETH_ALEN])
{
	fprintf(stderr, "TODO: insert ip->mac entry, and send all the pending packets.\n");
	pthread_mutex_lock(&arpcache.lock);
	
	int pos=-1;
	for(int i=0;i<32;i++){
	    if(arpcache.arp_cache_entry entries[i].valid==0){
            pos=i;
			break;
	    }
	}
	if(pos==-1) pos=31;
		
	arpcache.arp_cache_entry entries[pos].valid=1;
	arpcache.arp_cache_entry entries[pos].ip4=ip4;
	memcpy(arpcache.arp_cache_entry entries[pos].mac,mac,ETH_ALEN);
    arpcache.arp_cache_entry entries[pos].added=time(NULL);	
	
	
	struct arp_req *req_entry = NULL, *req_q;
	list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		if(req_entry->ip4==ip4){
		    struct cached_pkt *pkt_entry = NULL, *pkt_q;
		    list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
				struct ether_header *eh = (struct ether_header *)pkt_entry->packet;
		        memcpy(eh->ether_dhost, dst_mac, ETH_ALEN);
                iface_send_packet(req_entry->iface, pkt_entry->packet, pkt_entry->len);
                list_delete_entry(&(pkt_entry->list));
			}
		}
        list_delete_entry(&(req_entry->list));
        free(req_entry);
	}
    pthread_mutex_unlock(&arpcache.lock);	
}

// sweep arpcache periodically
//
// For the IP->mac entry, if the entry has been in the table for more than 15
// seconds, remove it from the table.
// For the pending packets, if the arp request is sent out 1 second ago, while 
// the reply has not been received, retransmit the arp request. If the arp
// request has been sent 5 times without receiving arp reply, for each
// pending packet, send icmp packet (DEST_HOST_UNREACHABLE), and drop these
// packets.
void *arpcache_sweep(void *arg) 
{
	while (1) {
		sleep(1);
		pthread_mutex_lock(&arpcache.lock);
		fprintf(stderr, "TODO: sweep arpcache periodically: remove old entries, resend arp requests .\n");
		
		struct arp_req *req_entry = NULL, *req_q;
		list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
		    if(req_entry->retries>5){
                struct cached_pkt *pkt_entry = NULL, *pkt_q;
				list_for_each_entry_safe(pkt_entry, pkt_q, &(req_entry->cached_packets), list) {
                    pthread_mutex_unlock(&arpcache.lock);
                    icmp_send_packet(cpkt->packet,cpkt->len,ICMP_DEST_UNREACH,ICMP_HOST_UNREACH);
                    list_delete_entry(&(pkt_entry->list));
                    free(pkt_entry->packet);
				}
				list_delete_entry(&(req_entry->list));
				free(req_entry);
			}
		}
			
        time_t now_time = time(NULL);
        for (int i = 0; i < MAX_ARP_SIZE; i++) {
            if (now_time - arpcache.entries[i].added > 15) 
                arpcache.entries[i].valid = 0;
        }
		
		now_time = time(NULL);
		req_entry = NULL;
	    list_for_each_entry_safe(req_entry, req_q, &(arpcache.req_list), list) {
			if(now_time-req_entry->send>1){
				req_entry->retries += 1;
				arp_send_request(req_entry->iface, req_entry->ip4);
			}
		}
		
		pthread_mutex_unlock(&arpcache.lock);
	}

	return NULL;
}
