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

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ZY");
MODULE_DESCRIPTION("ACC Func Test");
MODULE_ALIAS("ACC Module Test");

/*
 *  Debug format:  flag[S:F:R] seq ack 
 *
 *	TODO
 */


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
	struct acc_conn *cp;

	/* NOTE: In comint pkts just get into network
	 * the tcp_hdr func couldnot work!
	 * */
	th = (struct tcphdr *)(skb_network_header(skb) + iph->ihl * 4);

	if (th->dest != htons(80)) {
		return NF_ACCEPT;
	}

	if (th->syn) {
		cp = acc_conn_get(iph->protocol, iph->saddr, iph->daddr, th->source, th->dest, ACC_IN);		
		if (cp == NULL) {
			cp = acc_conn_new(iph->protocol, iph->saddr, iph->daddr, th->source, th->dest);	
			if (cp == NULL) {
				ACC_DEBUG("IN Alloc acc_conn struct failed\n");
				goto accept;
			}
			cp->rcv_isn = ntohl(th->seq);
			cp->rcv_seq = ntohl(th->seq);
			cp->rcv_ack_seq = ntohl(th->ack_seq);
			cp->rcv_end_seq = cp->rcv_isn + th->fin +
				th->syn + skb->len - iph->ihl * 4 - th->doff * 4;

			cp->in_seq_start = ntohl(th->seq);
			cp->in_okfn = okfn;
			cp->indev = skb->dev;
			/* Init the mac head of acc_conn */
			memcpy(cp->src_mac, eth_hdr(skb)->h_source, ETH_ALEN);
			memcpy(cp->dst_mac, eth_hdr(skb)->h_dest, ETH_ALEN);
		}
		goto accept;
	}

	cp = acc_conn_get(iph->protocol, iph->saddr, iph->daddr, th->source, th->dest, ACC_IN);	
	if (cp == NULL) {
		//ACC_DEBUG("Cannot get conn when expire and free\n");
		goto accept;
	} 
	cp->rcv_end_seq = ntohl(th->seq) + th->syn + th->fin + skb->len - th->doff * 4 - iph->ihl * 4;
	cp->rcv_ack_seq = ntohl(th->ack_seq);
	cp->rcv_seq = ntohl(th->seq);

	if(th->fin) {
		/*  Expire acc_conn here is not the BEST 
		 *  When to do it?			
		 * 			*/
		acc_conn_expire(cp);

		/* nilACK detected, Maybe is our acc_ack, Just accept it right now */
	} else if (is_nilack(skb, 0)) {	
		if (ntohl(th->ack_seq) == cp->acc_ack) {
			//ACC_DEBUG("RECV OUR ACC ACKS ack_seq=%u  cur_ack=%u\n", ntohl(th->ack_seq), ap->acc_ack);
			//goto drop;
		}
	} else if (th->ack) {  //ACK with data
		cp->ack_nr ++;	
	} 	
accept:
	if (cp && !th->syn) {
		ACC_DEBUG("IN %u:%u:%u seq %u:%u ack_seq %u\n",
				th->syn, th->fin, th->rst, 
				ntohl(th->seq)-cp->in_seq_start, cp->rcv_end_seq - cp->in_seq_start,  ntohl(th->ack_seq) - cp->out_seq_start);
	} else { 
		ACC_DEBUG("IN %u:%u:%u seq %u ack_seq %u\n",th->syn, th->fin, th->rst, ntohl(th->seq),  ntohl(th->ack_seq));
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
	struct acc_conn *cp;
	struct sk_buff *data;
	int ret;


	th = tcp_hdr(skb);
	if (th->source != htons(80)) {
		return NF_ACCEPT;
	}
	cp = acc_conn_get(iph->protocol, iph->saddr, iph->daddr, th->source, th->dest, ACC_OUT);
	if (cp == NULL) {
		ACC_DEBUG("INFO: local_out get acc_conn failed\n");
		return NF_ACCEPT;
	}

	if (th->syn) {
		cp->out_seq_start = ntohl(th->seq);

		cp->seq = ntohl(th->seq); 
		/* skb alreay go through TCP layer, use TCP_SKB_CB safely */		
		cp->end_seq = TCP_SKB_CB(skb)->end_seq;			
		cp->ack_seq = ntohl(th->ack_seq);
		cp->out_okfn = okfn;
		cp->outdev = skb->dev;

		//ACC_DEBUG("OUT: seq %u ack_seq %u\n",ntohl(th->seq), ntohl(th->ack_seq));
		goto accept;
	}

	if (is_nilack(skb, 1)) { /* Ignore the pure ACKs */
		//ACC_DEBUG("OUT: seq %uack_seq %u : nilack\n",ntohl(th->seq), ntohl(th->ack_seq));
		goto accept;
	}

	//ret = acc_send_skb(skb, ap);
	//goto pkt_stolen;

	/*  Data block transmit start, dev_queue_xmit is used here to transmit our cached Data
	 *  we need to stolen the data and cache them
	 *  then generate the right ACKs and send to UP layer	
	 *	*/

	if (!th->fin || !th->rst) {
		//acc_skb_enqueue(ap, skb);
		//ACC_DEBUG("skb enqueu seq=%u\n", ntohl(tcp_hdr(skb)->seq));
		//ap->trigger --;
	}

	//if (th->fin || th->rst || cp->trigger == 0) {
	if (th->fin || th->rst) {
		//ACC_DEBUG("Do send queue here\n");
		//ACC_DEBUG("start to send pkts\n");
		//acc_send_queue(cp);
		//cp->trigger = 5;

		goto accept;
	} else {
		/* Generage ACKs */
		ack_skb = acc_alloc_nilack(cp, skb);
		if (ack_skb) {
			//ACC_DEBUG("M-IN seq=%u  ack_seq=%u , OUTGOING-PKT seq=%u ack_seq=%u end_seq=%u\n",
			//		ntohl(tcp_hdr(ack_skb)->seq), ntohl(tcp_hdr(ack_skb)->ack_seq),
			//		ntohl(tcp_hdr(skb)->seq), ntohl(tcp_hdr(skb)->ack_seq), TCP_SKB_CB(skb)->end_seq);
			ACC_DEBUG("ACC-IN: seq %u ack_seq %u\n", 
					ntohl(tcp_hdr(ack_skb)->seq) - cp->in_seq_start, 
					ntohl(tcp_hdr(ack_skb)->ack_seq) - cp->out_seq_start);
			cp->acc_ack = ntohl(tcp_hdr(ack_skb)->ack_seq);

			NF_HOOK(PF_INET, NF_INET_PRE_ROUTING, ack_skb, ack_skb->dev, NULL, skb_dst(ack_skb)->input);
			//goto pkt_stolen;
			/* IS goto stolen, but for debug, we get to accept */
			goto accept;
		} else {
			ACC_DEBUG("ERROR: allock skb failed\n");
		}
	}
	
accept:
	if (cp && !th->syn)  {
		ACC_DEBUG("OUT %u:%u:%u seq %u:%u ack_seq %u\n",
				th->syn, th->fin, th->rst, 
				ntohl(th->seq) - cp->out_seq_start, TCP_SKB_CB(skb)->end_seq - cp->out_seq_start,  ntohl(th->ack_seq) - cp->in_seq_start);
	} else  {
		ACC_DEBUG("OUT %u:%u:%u seq %u ack_seq %u\n",th->syn, th->fin, th->rst, ntohl(th->seq),  ntohl(th->ack_seq));
	}

	return NF_ACCEPT;

pkt_stolen:
	return NF_STOLEN;
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

module_init(acc_init);
module_exit(acc_exit);
