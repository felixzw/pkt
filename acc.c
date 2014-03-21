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
MODULE_AUTHOR("Fell");
MODULE_DESCRIPTION("test");
MODULE_ALIAS("module test netfiler");


static unsigned int nf_hook_in(unsigned int hooknum,
		struct sk_buff *sk,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct sk_buff *skb = sk;
	struct tcphdr *tcphdr = NULL;
	struct iphdr *iph = ip_hdr(sk);
	struct acc_conn *ap;
	
	tcphdr = (struct tcphdr *)(skb_network_header(skb) + iph->ihl * 4);
	// for test port 80 only
	if (tcphdr->dest == htons(80)) {
		
		if (tcphdr->syn) {
			ap = acc_conn_get(iph->protocol, iph->saddr, iph->daddr, tcphdr->source, tcphdr->dest);		
			if (ap == NULL) {
				ap = acc_conn_new(iph->protocol, iph->saddr, iph->daddr, tcphdr->source, tcphdr->dest);	
				if (ap == NULL) {
					//ACC_DEBUG("IN Alloc acc_conn struct failed\n");
					goto accept;
				}
				ap->rcv_isn = tcphdr->seq;
				//ap->rcv_seq = tcphdr->seq;
			}
			goto accept;
		}

		ap = acc_conn_get(iph->protocol, iph->saddr, iph->daddr, tcphdr->source, tcphdr->dest);	
		if (ap == NULL) {
			//ACC_DEBUG("Cannot get conn when expire and free\n");
			goto accept;
		} 
		
		ap->last_end_seq = ntohl(tcphdr->seq) + tcphdr->syn + tcphdr->fin + skb->len - tcphdr->doff * 4 - iph->ihl * 4;
		
		if(tcphdr->fin) {
			acc_conn_expire(ap);
		} else if (is_nilack(skb, 0)) { //nil ACK
			//if (ntohl(tcphdr->ack_seq) <= ap->cur_ack) {
			//	ACC_DEBUG("IN Discard peer pure old ack, ack_seq=%u  cur_ack=%u\n", ntohl(tcphdr->ack_seq), ap->cur_ack);
			//	goto drop;
			//}
		} else if (tcphdr->ack) {  //ACK with data
			ap = acc_conn_get(iph->protocol, iph->saddr, iph->daddr, tcphdr->source, tcphdr->dest);
			if (ap == NULL) {
				//ACC_DEBUG("IN ACK packet, get acc_conn failed\n");
				goto accept;
			} 
			if (ap->ack_nr == 0) {
				ap->ack = skb_copy(skb, GFP_ATOMIC);
			}
			ap->ack_nr ++;	
		} 	
accept:
		ACC_DEBUG("IN   seq=%u  ack_seq=%u\n", ntohl(tcphdr->seq),  ntohl(tcphdr->ack_seq));
		return NF_ACCEPT;
	}
	return NF_ACCEPT;

drop:
	return NF_DROP;
}

static unsigned int nf_hook_out(unsigned int hooknum,
		struct sk_buff *sk,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	struct sk_buff *skb = sk;
	struct tcphdr *tcphdr = NULL;
	struct iphdr *iph = ip_hdr(sk);
	struct sk_buff *ack_skb;
	struct acc_conn *ap;
	struct sk_buff *data;

	//tcphdr = (struct tcphdr *)(skb_network_header(skb) + iph->ihl * 4);
	tcphdr = tcp_hdr(skb);
	if (tcphdr->source == htons(80)) {
		if (is_nilack(skb, 1)) {
			ACC_DEBUG("OUT Nilack ack_seq=%u\n", ntohl(tcphdr->ack_seq));
			goto accept;
		}
		if (!tcphdr->syn) {
			ap = acc_conn_get(iph->protocol, iph->daddr, iph->saddr, tcphdr->dest, tcphdr->source);
			if (ap == NULL) {
				ACC_DEBUG("OUT get acc_conn failed\n");
				goto accept;
			}
			//ACC_DEBUG("OUT get acc_conn success, ack_nr=%u\n", ap->ack_nr);
			if (tcphdr->ack && TCP_SKB_CB(skb)->end_seq == ap->rcv_isn + 1) {
				goto accept;
			}
			/* Enqueue the pkt from TCP layer */
			//data = skb_copy(skb, GFP_ATOMIC);
			//acc_skb_enqueue(ap, data);
			ap->trigger --;
			if (tcphdr->fin || tcphdr->rst || ap->trigger == 0) {
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
					ap->cur_ack = ntohl(tcp_hdr(ack_skb)->ack_seq);
					netif_rx(ack_skb);
				}
				//ACC_DEBUG("netif_rx ok\n");
			}
			//return NF_STOLEN;
			//return NF_DROP;
			goto accept;
		}
accept:

		ACC_DEBUG("OUT  seq=%u  ack_seq=%u\n", ntohl(tcphdr->seq), ntohl(tcphdr->ack_seq));
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
module_init(acc_init);
module_exit(acc_exit);
