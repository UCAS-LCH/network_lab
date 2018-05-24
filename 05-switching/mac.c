#include "mac.h"
#include "headers.h"
#include "log.h"

mac_port_map_t mac_port_map;

void init_mac_hash_table()
{
	bzero(&mac_port_map, sizeof(mac_port_map_t));

	pthread_mutexattr_init(&mac_port_map.attr);
	pthread_mutexattr_settype(&mac_port_map.attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&mac_port_map.lock, &mac_port_map.attr);

	pthread_create(&mac_port_map.tid, NULL, sweeping_mac_port_thread, NULL);
}

void destory_mac_hash_table()
{
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *tmp, *entry;
	for (int i = 0; i < HASH_8BITS; i++) {
		entry = mac_port_map.hash_table[i];
		if (!entry) 
			continue;

		tmp = entry->next;
		while (tmp) {
			entry->next = tmp->next;
			free(tmp);
			tmp = entry->next;
		}
		free(entry);
	}
	pthread_mutex_unlock(&mac_port_map.lock);
}

iface_info_t *lookup_port(u8 mac[ETH_ALEN])
{
	// TODO: implement the lookup process here
        pthread_mutex_lock(&mac_port_map.lock);
        mac_port_entry_t *entry;
        int find=0;
	for (int i = 0; i < HASH_8BITS; i++) {
		entry = mac_port_map.hash_table[i];
                while(entry){
                        if(bcmp(entry->mac,mac,ETH_ALEN)==0){
                             find=1;
                             break;
                        }
                        entry=entry->next;
                }
                if(find){
                        entry->visited = time(NULL); 
                        break;//for
                }
        }     
        pthread_mutex_unlock(&mac_port_map.lock);
        if(find)
              return entry->iface;
        else
	      return NULL;
}

void insert_mac_port(u8 mac[ETH_ALEN], iface_info_t *iface)
{
	// TODO: implement the insertion process here
    pthread_mutex_lock(&mac_port_map.lock);
     mac_port_entry_t *entry, *tmp;

        tmp = (mac_port_entry_t *)malloc(sizeof(mac_port_entry_t));
	memcpy(tmp->mac, mac, ETH_ALEN);
	tmp->iface = iface;
	tmp->next = NULL;
	tmp->visited = time(NULL);

        //insert
        u8 hash_value;
        hash_value=hash8(mac, ETH_ALEN);
        for(entry = mac_port_map.hash_table[hash_value]; entry && entry->next;	entry = entry->next);
        if(!entry)
               mac_port_map.hash_table[hash_value] = tmp;
        else
               entry->next = tmp;   
        pthread_mutex_unlock(&mac_port_map.lock);
        
}

void dump_mac_port_table()
{
	mac_port_entry_t *entry = NULL;
	time_t now = time(NULL);

	//fprintf(stdout, "dumping the mac_port table:\n");
	pthread_mutex_lock(&mac_port_map.lock);
	for (int i = 0; i < HASH_8BITS; i++) {
		entry = mac_port_map.hash_table[i];
		while (entry) {
			fprintf(stdout, ETHER_STRING " -> %s, %d\n", ETHER_FMT(entry->mac), \
					entry->iface->name, (int)(now - entry->visited));

			entry = entry->next;
		}
	}

	pthread_mutex_unlock(&mac_port_map.lock);
}

int sweep_aged_mac_port_entry()
{
	// TODO: implement the sweeping process here
    mac_port_entry_t *entry, *p,*q;
    int del_num=0;
    time_t now = time(NULL);
    pthread_mutex_lock(&mac_port_map.lock);
	for (int i = 0; i < HASH_8BITS; i++) {
		p = entry = mac_port_map.hash_table[i];
		if (!p) 
			continue;

		q = p->next;                
		while (q) {
                if(now - q->visited > MAC_PORT_TIMEOUT){
			        p->next = q->next;
			        free(q);
                    del_num++;
                }
                else
                    p=p->next;
                q=p->next;
        }
		if(now - entry->visited >= MAC_PORT_TIMEOUT){
			mac_port_map.hash_table[i] = entry->next;
			free(entry);
			del_num++;
		}
    }
    pthread_mutex_unlock(&mac_port_map.lock);                
	return del_num++;
}

void *sweeping_mac_port_thread(void *nil)
{
	while (1) {
		sleep(1);
		int n = sweep_aged_mac_port_entry();

		if (n > 0)
			log(DEBUG, "%d aged entries in mac_port table are removed.\n", n);
	}

	return NULL;
}
