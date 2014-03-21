#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <net/tcp.h>
#include <net/ip.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/inet.h>
#include <net/checksum.h>
#include <linux/vmalloc.h>

#include "acc.h"

/*
 *  Get the incoming pkts
 *  Discard the pure ack from remote which we are already send to UP LAYER  
 *  The ACKs which we generate will go through here? how to avoid?
 *  It is neccesery to save ACK from remote here?  Or Just genrate nilACKs when we do at POSTROUTING hook
 *
 *  Right NOW, all the function is JUST FOR test, and port 80 is used
 * */
static unsigned int nf_hook_in(unsigned int hooknum,
		struct sk_buff *sk,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct sk_buff *skb = sk;
	struct tcphdr *th = NULL;
	struct iphdr *iph = ip_hdr(sk);
	struct acc_conn *ap;
	
	th = tcp_hdr(skb); /* Donot use skb_network_header, that's real annoy */
	
	if (th->dest == htons(80)) {
		if (th->syn) {
			ap = acc_conn_get(iph->protocol, iph->saddr, iph->daddr, th->source, th->dest);		
			if (ap == NULL) {
				ap = acc_conn_new(iph->protocol, iph->saddr, iph->daddr, th->source, th->dest);	
				if (ap == NULL) {
					//ACC_DEBUG("IN Alloc acc_conn struct failed\n");
					goto accept;
				}
				ap->rcv_isn = ntohl(th->seq);
				ap->rcv_seq = ntohl(th->seq);
				ap->rcv_ack_seq = ntohl(th->ack_seq);
				ap->rcv_end_seq = ap->rcv_isn + th->fin + th->syn + skb->len - iph->ihl * 4 - th->doff * 4;
			}
			goto accept;
		}

		ap = acc_conn_get(iph->protocol, iph->saddr, iph->daddr, th->source, th->dest);	
		if (ap == NULL) {
			//ACC_DEBUG("Cannot get conn when expire and free\n");
			goto accept;
		} 
		
		ap->rcv_end_seq = ntohl(th->seq) + th->syn + th->fin + skb->len - th->doff * 4 - iph->ihl * 4;
		ap->rcv_ack_seq = ntohl(th->ack_seq);
		ap->rcv_seq = ntohl(th->seq);
		
		if(th->fin) {
			/*  Expire acc_conn here is not the BEST 
			 *  When to do it?			
			 * 			*/
			acc_conn_expire(ap);

		/* nilACK detected, Maybe is our acc_ack, Just accept it right now */
		} else if (is_nilack(skb, 0)) {	
			if (ntohl(th->ack_seq) < ap->acc_ack) {
				ACC_DEBUG("IN Discard peer pure old ack, ack_seq=%u  cur_ack=%u\n", ntohl(th->ack_seq), ap->acc_ack);
				goto drop;
			}
		} else if (th->ack) {  //ACK with data
			ap = acc_conn_get(iph->protocol, iph->saddr, iph->daddr, th->source, th->dest);
			if (ap == NULL) {
				//ACC_DEBUG("IN ACK packet, get acc_conn failed\n");
				goto accept;
			}

			/*  This is for test 
			 *  I am not sure copy the ack is a right way
			 * 			*/ 
			if (ap->ack_nr == 0) {
				ap->ack = skb_copy(skb, GFP_ATOMIC);
			}
			ap->ack_nr ++;	
		} 	
accept:
		ACC_DEBUG("IN   seq=%u  ack_seq=%u\n", ntohl(th->seq),  ntohl(th->ack_seq));
		return NF_ACCEPT;
	}
	return NF_ACCEPT;

drop:
	return NF_DROP;
}


/*
 *  PKTs out going process,  It is real confuse here
 *  How to make the acc_acks rcv by IP stack 
 *  Right now, netif_rx is using here, but it will cause other problem
 * */
static unsigned int nf_hook_out(unsigned int hooknum,
		struct sk_buff *sk,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct sk_buff *skb = sk;
	struct tcphdr *th = NULL;
	struct iphdr *iph = ip_hdr(sk);
	struct sk_buff *ack_skb;
	struct acc_conn *ap;
	struct sk_buff *data;

	th = tcp_hdr(skb);
	if (th->source == htons(80)) {
		ap = acc_conn_get(iph->protocol, iph->daddr, iph->saddr, th->dest, th->source);
		if (ap == NULL) {
			ACC_DEBUG("OUT get acc_conn failed\n");
			goto accept;
		}
	
		if (th->syn) {
			ap->seq = ntohl(th->seq);
			ap->end_seq = TCP_SKB_CB(skb)->end_seq; /* skb alreay go through TCP layer, use TCP_SKB_CB safely */		
			ap->ack_seq = ntohl(th->ack_seq);
			goto accept;
		}

		if (is_nilack(skb, 1)) { /* Ignore the pure ACKs */
			ACC_DEBUG("OUT Nilack ack_seq=%u\n", ntohl(th->ack_seq));
			goto accept;
		}
		
		/*  Data block transmit start, dev_queue_xmit is used here to transmit our cached Data
		 *  we need to stolen the data and cache them
		 *  then generate the right ACKs and send to UP layer	
		 *	*/
		//ACC_DEBUG("OUT get acc_conn success, ack_nr=%u\n", ap->ack_nr);

		/*  Enqueue the pkt from TCP layer 
		 *  sk_buff_head is quiet hard to use, we have bug here
		 * */
		//data = skb_copy(skb, GFP_ATOMIC);
		//acc_skb_enqueue(ap, data);
		ap->trigger --;
		
		if (th->fin || th->rst || ap->trigger == 0) {
			//ACC_DEBUG("Do send queue here\n");
			//acc_send_queue(ap);
			ap->trigger = 10;
		} else {
			/* Generage ACKs */
			ack_skb = acc_alloc_ack(ap, skb);
			if (ack_skb) {
				//ACC_DEBUG("Alloc ack_skb success\n");	
				ACC_DEBUG("M-IN seq=%u  ack_seq=%u , OUTGOING-PKT seq=%u ack_seq=%u end_seq=%u\n",
						ntohl(tcp_hdr(ack_skb)->seq), ntohl(tcp_hdr(ack_skb)->ack_seq),
						ntohl(tcp_hdr(skb)->seq), ntohl(tcp_hdr(skb)->ack_seq), TCP_SKB_CB(skb)->end_seq);
				ap->acc_ack = ntohl(tcp_hdr(ack_skb)->ack_seq);
				
				/*Damn ... It is not working sometimes ...
				 *  netif_rx is a bad idea
				 * */
				netif_rx(ack_skb);
			}
			//ACC_DEBUG("netif_rx ok\n");
		}
		//return NF_STOLEN;
		//return NF_DROP;
		goto accept;
accept:

		ACC_DEBUG("OUT  seq=%u  ack_seq=%u\n", ntohl(th->seq), ntohl(th->ack_seq));
		return NF_ACCEPT;
	}

	return NF_ACCEPT;
}


static struct nf_hook_ops nfin = {
	.hook = nf_hook_in,
	.hooknum = NF_INET_PRE_ROUTING,
	.pf = NFPROTO_IPV4,
	.priority = NF_IP_PRI_FIRST,
};

static struct nf_hook_ops nfout = {
	.hook = nf_hook_out,
	.hooknum = NF_INET_POST_ROUTING,
	.pf = NFPROTO_IPV4,
	.priority = NF_IP_PRI_LAST,
};

int __init acc_init(void)
{
	acc_conn_init();
	
	nf_register_hook(&nfout);
	nf_register_hook(&nfin);

	printk("AccNet test module init\n");
	return 0;
}

void __exit acc_exit(void)
{
	acc_conn_cleanup();

	nf_unregister_hook(&nfin);
	nf_unregister_hook(&nfout);
	printk("AccNet test module exit\n");
	return;
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("ZY");
MODULE_DESCRIPTION("ACC Func Test");
MODULE_ALIAS("ACC Module Test");


module_init(acc_init);
module_exit(acc_exit);
