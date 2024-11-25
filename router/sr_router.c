/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

#define DEBUG_CHECK_PACKET   0
#define DEBUG_PROCESS_PACKET 1
#define ETH_ARP              1
#define ETH_IP               2
#define ETH_IP_ICMP          3

static int frame_type = 0; 
/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */



/*---------------------------------------------------------------------
 * Method: sr_check_packet(uint8_t* packet, unsigned int len)
 *
 * Checking the validation of received paket and type of packet
 *
 *---------------------------------------------------------------------*/

bool sr_check_packet(uint8_t* packet, unsigned int len)
{
	uint16_t cksum_iphdr, cksum_icmphdr;
	uint16_t minlen_hdr = sizeof(sr_ethernet_hdr_t);
	sr_ethernet_hdr_t *eth_hdr;
	sr_ip_hdr_t *ip_hdr;
	sr_icmp_hdr_t *icmp_hdr;
	frame_type = 0;
	#if DEBUG_CHECK_PACKET 
	print_hdrs(packet, len); 
	#endif
	
	if (len < minlen_hdr)
	{
		printf("The length of received packet is smaller than minimum length of Ethernet\n");
		return false;
	}
	#if DEBUG_CHECK_PACKET
		printf("Frame: Ethernet");
	#endif
	eth_hdr = (sr_ethernet_hdr_t *) packet;
	/* IPv4 */
	if (eth_hdr->ether_type == htons(ethertype_ip))
	{
		minlen_hdr += sizeof(sr_ip_hdr_t);
		if (len < minlen_hdr)
		{
			printf("The length of received packet is smaller than minimum length of IPv4\n");
			return false;
		}
		ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
		cksum_iphdr = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
		if (cksum_iphdr != 0xFFFF)
		{
			printf("Incorrect header checksum of IPv4\n");
			return false;
		}
		frame_type = ETH_IP;
		#if DEBUG_CHECK_PACKET
				printf(" + IPv4");
		#endif
		/* ICMP */
		if (ip_hdr->ip_p == ip_protocol_icmp)
		{
			minlen_hdr += sizeof(sr_icmp_hdr_t);
			if(len < minlen_hdr)
			{
				printf("The length of received packet is smaller than minimum length of ICMP\n");
				return false;
			}
			icmp_hdr = (sr_icmp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
			cksum_icmphdr = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
			if(cksum_icmphdr != 0xFFFF)
			{
				printf("Incorrect header checksum of ICMP\n");
				return false;
			}
			frame_type = ETH_IP_ICMP;
			#if DEBUG_CHECK_PACKET
				printf(" + ICMP");
			#endif
		} 
	} 
	/* ARP */
	else if (eth_hdr->ether_type == htons(ethertype_arp))
	{
		minlen_hdr += sizeof(sr_arp_hdr_t);
		if (len < minlen_hdr)
		{
			printf("The length of received packet is smaller than minimum length of ARP\n");
			return false;
		}
		frame_type = ETH_ARP;
		#if DEBUG_CHECK_PACKET
			printf(" + ARP");
		#endif
	}
	#if DEBUG_CHECK_PACKET
		printf("\n");
	#endif
	return true;
}


/*---------------------------------------------------------------------
 * Method: sr_check_packet(uint8_t* packet, unsigned int len)
 *
 * Sending reply message back to a sending host
 *
 *---------------------------------------------------------------------*/

void sr_send_icmp_echo(struct sr_instance *sr, uint8_t *packet, char* interface, enum sr_packet_state state)
{
	sr_ethernet_hdr_t *eth_hdr_recv = (sr_ethernet_hdr_t *) packet;
	sr_ip_hdr_t *ip_hdr_recv = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
	struct sr_if *if_out = sr_get_interface(sr, interface);

	uint16_t payload_len = htons(ip_hdr_recv->ip_len) - sizeof(sr_ip_hdr_t) - sizeof(sr_icmp_hdr_t);
	uint8_t *buf =(uint8_t *) calloc((sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t) + payload_len), 1);
	int buf_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t) + payload_len;
	sr_ethernet_hdr_t *eth_hdr_reply = (sr_ethernet_hdr_t *) calloc(sizeof(sr_ethernet_hdr_t), 1);
	sr_ip_hdr_t *ip_hdr_reply = (sr_ip_hdr_t *) calloc(sizeof(sr_ip_hdr_t), 1);
	sr_icmp_hdr_t *icmp_pkt_reply = calloc(sizeof(sr_icmp_hdr_t) + payload_len, 1);

	if (state == echo_reply)
	{		
		icmp_pkt_reply->icmp_type = 0;
		icmp_pkt_reply->icmp_code = 0;
	}
	else
		return;
	memcpy((uint8_t *)icmp_pkt_reply + sizeof(sr_icmp_hdr_t), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t), payload_len);
	icmp_pkt_reply->icmp_sum = 0;
	icmp_pkt_reply->icmp_sum = cksum(icmp_pkt_reply, sizeof(sr_icmp_hdr_t) + payload_len);

	ip_hdr_reply->ip_v   = ip_hdr_recv->ip_v;
	ip_hdr_reply->ip_hl  = ip_hdr_recv->ip_hl;
	ip_hdr_reply->ip_tos = ip_hdr_recv->ip_tos;
	ip_hdr_reply->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t) + payload_len);
	ip_hdr_reply->ip_id  = ip_hdr_recv->ip_id + 1;
	ip_hdr_reply->ip_off = htons(IP_DF);
	ip_hdr_reply->ip_ttl = 64;
	ip_hdr_reply->ip_p 	 = ip_protocol_icmp;
	ip_hdr_reply->ip_src = ip_hdr_recv->ip_dst;
	ip_hdr_reply->ip_dst = ip_hdr_recv->ip_src;
	ip_hdr_reply->ip_sum = 0;
	ip_hdr_reply->ip_sum = cksum(ip_hdr_reply, sizeof(sr_ip_hdr_t));

	memcpy(eth_hdr_reply->ether_dhost, eth_hdr_recv->ether_shost, ETHER_ADDR_LEN);
	memcpy(eth_hdr_reply->ether_shost, if_out->addr, ETHER_ADDR_LEN);
	eth_hdr_reply-> ether_type = htons(ethertype_ip);

	memcpy(buf, eth_hdr_reply, sizeof(sr_ethernet_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t), ip_hdr_reply, sizeof(sr_ip_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_pkt_reply, sizeof(sr_icmp_hdr_t) + payload_len);

	/*print_hdrs(buf, buf_len);*/
	sr_send_packet(sr, buf, buf_len, interface);

	free(eth_hdr_reply);
	free(ip_hdr_reply);
	free(icmp_pkt_reply);
	free(buf);
}	


/*---------------------------------------------------------------------
 * Method: sr_check_packet(uint8_t* packet, unsigned int len)
 *
 * Sending messages back to a sending host if any error occur
 *
 *---------------------------------------------------------------------*/

void sr_send_icmp_report(struct sr_instance *sr, uint8_t *packet, char* interface, enum sr_packet_state state)
{
	sr_ethernet_hdr_t *eth_hdr_recv = (sr_ethernet_hdr_t *) packet;
	sr_ip_hdr_t *ip_hdr_recv = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
	struct sr_if *if_out = sr_get_interface(sr, interface);

	uint8_t *buf =(uint8_t *) calloc((sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t)), 1);
	int buf_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
	sr_ethernet_hdr_t *eth_hdr_reply = (sr_ethernet_hdr_t *) calloc(sizeof(sr_ethernet_hdr_t), 1);
	sr_ip_hdr_t *ip_hdr_reply = (sr_ip_hdr_t *) calloc(sizeof(sr_ip_hdr_t), 1);
	sr_icmp_t3_hdr_t *icmp_hdr_reply = calloc(sizeof(sr_icmp_t3_hdr_t), 1);

	switch (state)
	{
		case dst_net_unreachable:
			icmp_hdr_reply->icmp_type = 3;
			icmp_hdr_reply->icmp_code = 0;
			break;
		case dst_host_unreachable:
			icmp_hdr_reply->icmp_type = 3;
			icmp_hdr_reply->icmp_code = 1;
			break;
		case port_unreachable:
			icmp_hdr_reply->icmp_type = 3;
			icmp_hdr_reply->icmp_code = 3;
			break;
		case time_exceeded:
			icmp_hdr_reply->icmp_type = 11;
			icmp_hdr_reply->icmp_code = 0;
		default:
			return;
			break;
	}
	icmp_hdr_reply->unused = 0;
	icmp_hdr_reply->next_mtu = 0;
	memcpy(icmp_hdr_reply->data, packet + sizeof(sr_ethernet_hdr_t), ICMP_DATA_SIZE);
	icmp_hdr_reply->icmp_sum = 0;
	icmp_hdr_reply->icmp_sum = cksum(icmp_hdr_reply, sizeof(sr_icmp_t3_hdr_t));

	ip_hdr_reply->ip_v   = ip_hdr_recv->ip_v;
	ip_hdr_reply->ip_hl  = ip_hdr_recv->ip_hl;
	ip_hdr_reply->ip_tos = ip_hdr_recv->ip_tos;
	ip_hdr_reply->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
	ip_hdr_reply->ip_id  = ip_hdr_recv->ip_id + 1;
	ip_hdr_reply->ip_off = htons(IP_DF);
	ip_hdr_reply->ip_ttl = 64;
	ip_hdr_reply->ip_p 	 = ip_protocol_icmp;
	ip_hdr_reply->ip_src = ip_hdr_recv->ip_dst;
	ip_hdr_reply->ip_dst = ip_hdr_recv->ip_src;
	ip_hdr_reply->ip_sum = 0;
	ip_hdr_reply->ip_sum = cksum(ip_hdr_reply, sizeof(sr_ip_hdr_t));

	memcpy(eth_hdr_reply->ether_dhost, eth_hdr_recv->ether_shost, ETHER_ADDR_LEN);
	memcpy(eth_hdr_reply->ether_shost, if_out->addr, ETHER_ADDR_LEN);
	eth_hdr_reply-> ether_type = htons(ethertype_ip);

	memcpy(buf, eth_hdr_reply, sizeof(sr_ethernet_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t), ip_hdr_reply, sizeof(sr_ip_hdr_t));
	memcpy(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_hdr_reply, sizeof(sr_icmp_t3_hdr_t));

	/*print_hdrs(buf, buf_len);*/
	sr_send_packet(sr, buf, buf_len, interface);
	free(eth_hdr_reply);
	free(ip_hdr_reply);
	free(icmp_hdr_reply);
	free(buf);
}

/*---------------------------------------------------------------------
 * Method: enum sr_packet_state sr_forwarding_packet(struct sr_instance *sr,  uint8_t * packet, unsigned int len, uint32_t ip_dst)
 *
 * Check the existence route of destination IP and TTL of transmitting packet
 * Find entry in routing table  has the longest prefix match with the destination IP address.
 * If IP->MAC mapping is in cache, forwarding packet, else send ARP broadcast
 *
 *---------------------------------------------------------------------*/

enum sr_packet_state sr_forwarding_packet(struct sr_instance *sr,  uint8_t * packet, unsigned int len, uint32_t ip_dst)
{
	uint8_t *buf = calloc(len, 1);
	struct sr_rt *rt; 
	struct sr_arpentry *entry;
	struct sr_arpreq *req;
	struct sr_if *nexthop_if;
	enum sr_packet_state state = success;

	memcpy(buf, packet, len);
	if (((sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t)))->ip_ttl == 1)
	{
		printf ("time_exceeded\n");
		free(buf);
		return state = time_exceeded;
	}
	rt = rt_longest_prefix_match(sr, ip_dst);
	if (!rt)
	{
        printf ("dst_net_unreachable\n");
		free(buf);
		return state = dst_net_unreachable;
	}
	

	nexthop_if = sr_get_interface(sr, rt->interface);
	entry = sr_arpcache_lookup(&sr->cache, ip_dst);
	if (entry) 
	{
		/*use next_hop_ip->mac mapping in entry to send the packet*/
		memcpy(((sr_ethernet_hdr_t *) buf)->ether_dhost, entry->mac, ETHER_ADDR_LEN);
		memcpy(((sr_ethernet_hdr_t *) buf)->ether_shost, nexthop_if->addr, ETHER_ADDR_LEN);
		/*sr_arpcache_dump(&sr->cache);*/
		free(entry);
	}
	else
	{
		req = sr_arpcache_queuereq(&sr->cache, ip_dst, packet, len, nexthop_if->name);
		state = sr_handle_arpreq(sr, req);
		return state;
	}

	((sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t)))->ip_ttl--;
	((sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t)))->ip_sum = 0;
	((sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t)))->ip_sum = cksum((sr_ip_hdr_t *) (buf + sizeof(sr_ethernet_hdr_t)), sizeof(sr_ip_hdr_t));

	/*print_hdrs(buf, len);*/
	sr_send_packet(sr, buf, len, nexthop_if->name);
	free(buf);
	return state;
}



/*---------------------------------------------------------------------
 * Method: sr_processing_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
 *
 * According to the type of received packet, processing it 
 *
 *---------------------------------------------------------------------*/

void sr_processing_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len, char *interface)
{
	struct sr_if *if_node; 
	struct sr_arpreq *req;
	enum sr_packet_state state;
	sr_arp_hdr_t *arp_hdr;
	sr_ip_hdr_t *ip_hdr;
	struct sr_packet *pkt;
	switch(frame_type){
		case ETH_ARP:
			arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
			for (if_node = sr->if_list; if_node != NULL; if_node = if_node->next)
			{
				if(if_node->ip == arp_hdr->ar_tip)
				{
					if (arp_hdr->ar_op == htons(arp_op_request))
					{
						sr_send_arp_reply(sr, arp_hdr, if_node);
						break; 
					}
					else if (arp_hdr->ar_op == htons(arp_op_reply))
					{
						req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
						if (req)
						{
							/* send all packets on the req->packets linked list */
							for (pkt = req->packets; pkt != NULL; pkt = pkt->next)
							{
								state = sr_forwarding_packet(sr, pkt->buf, pkt->len, arp_hdr->ar_sip);
							}
							sr_arpreq_destroy(&sr->cache, req);
						}
						break;
					}
				}	
			}
			break;
		case ETH_IP:
			ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
			for (if_node = sr->if_list; if_node != NULL; if_node = if_node->next)
			{
				/* Packet containing TCP or UDP is destined for router's interface*/
				if (ip_hdr->ip_dst == if_node->ip)
				{
					printf("UDP/TCP: Destination is router's interface\n");
					sr_send_icmp_report(sr, packet, interface, port_unreachable);
					return;
				}
			
			}
			/* Packet should be forward */
			printf("UDP/TCP: Destination is not router's interface\n");
			state = sr_forwarding_packet(sr, packet, len, ip_hdr->ip_dst);
			if (state != success)
			{
				printf("UDP/TCP: Packet has problem\n");
				sr_send_icmp_report(sr, packet, interface, state);
			}

			break;
		case ETH_IP_ICMP:
			ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
			for (if_node = sr->if_list; if_node != NULL; if_node = if_node->next)
			{
				/* Packet containing ICMP is destined for router's interface*/
				if (ip_hdr->ip_dst == if_node->ip)
				{
					printf("ICMP: Destination is router's interface\n");
					sr_send_icmp_echo(sr, packet, interface, echo_reply);
					return;
				}
			}
			/* Packet should be forward */
			printf("ICMP: Destination is not router's interface\n");
			state = sr_forwarding_packet(sr, packet, len, ip_hdr->ip_dst);
			if (state != success)
			{
				printf("ICMP: Packet has problem\n");
				sr_send_icmp_report(sr, packet, interface, state);
			}
			break;
		default:
			break;
	}
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);
  /*
  printf("*** -> Received packet of length %d \n",len);
  printf("*** -> Received packet of interface %s \n", interface);
  */
  /* fill in code here */

	if (sr_check_packet(packet, len) == false){
		printf("Unknown packets\n");
		return;
	}
	sr_processing_packet(sr, packet, len, interface); 
}/* end sr_ForwardPacket */
