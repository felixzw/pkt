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

#include "pkt.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Fell");
MODULE_DESCRIPTION("test");
MODULE_ALIAS("module test netfiler");

struct list_head *acc_conn_tab;
/*  SLAB cache for IPVS connections */
static struct kmem_cache  *acc_conn_cachep;
struct acc_aligned_lock *__acc_conntbl_lock_array;

static inline void ct_read_lock(unsigned key)
{
	read_lock(&__acc_conntbl_lock_array[key&CT_LOCKARRAY_MASK].l);
}
static inline void ct_read_unlock(unsigned key)
{
	read_unlock(&__acc_conntbl_lock_array[key&CT_LOCKARRAY_MASK].l);
}

static inline void ct_write_lock(unsigned key)
{
	write_lock(&__acc_conntbl_lock_array[key&CT_LOCKARRAY_MASK].l);
}

static inline void ct_write_unlock(unsigned key)
{
	write_unlock(&__acc_conntbl_lock_array[key&CT_LOCKARRAY_MASK].l);
}



static inline unsigned __hash(int proto, __be32 saddr, __be32 daddr, __be16 sport, __be16 dport, int reverse)
{
	unsigned hash;
	if (reverse) {
		 hash = (proto + saddr + daddr + sport + dport)%100;
	} else {
		 hash = (proto + saddr + daddr + sport + dport)%100;
	}
	return hash;
}

struct acc_conn *acc_conn_get(int proto, __be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	unsigned hash;
	struct acc_conn *ap;

	hash = __hash(proto, saddr, daddr, sport, dport, 0);
	ct_read_lock(hash);

	list_for_each_entry(ap, &acc_conn_tab[hash], c_list) {
		if (saddr==ap->saddr && sport==ap->sport &&
		    dport==ap->dport && daddr==ap->daddr &&
		    proto == ap->proto) {
			/* HIT */
			ct_read_unlock(hash);
			return ap;
		}
	}

	ct_read_unlock(hash);
	return NULL;
}

static inline int acc_conn_unhash(struct acc_conn *ap)
{
	unsigned hash;
	int ret = 0;

	hash = __hash(ap->proto, ap->saddr, ap->daddr, ap->sport, ap->dport, 0);
	
	ct_write_lock(hash);
	
	list_del(&ap->c_list);

	ct_write_unlock(hash);

	return ret;
}

struct acc_conn *acc_conn_new(int proto, __be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	struct acc_conn* ap;
	unsigned hash;
	
	ap = kmem_cache_alloc(acc_conn_cachep, GFP_ATOMIC);
	if (ap == NULL) {
		return NULL;
	}

	memset(ap, 0, sizeof(*ap));
	INIT_LIST_HEAD(&ap->c_list);
	ap->proto = proto;
	ap->saddr = saddr;
	ap->daddr = daddr;
	ap->sport = sport;
	ap->dport = dport;
	ap->state = SYN_RCV;
	
	ap->acc_ssthresh = 20;
	ap->ack = NULL;
	ap->ack_nr = 0;
	ap->trigger = 10;
	ap->rcv_isn = 0;
	skb_queue_head_init(&(ap->acc_queue));

	/* Hash to acc_conn_tab */
	hash = __hash(proto, saddr, daddr, sport, dport, 0);	
	ct_write_lock(hash);
	list_add(&ap->c_list, &acc_conn_tab[hash]);
	ct_write_unlock(hash);

	return ap;
}

void acc_conn_expire(struct acc_conn *ap)
{
	if (ap->ack) {
		kfree_skb(ap->ack);
	}
	acc_conn_unhash(ap);
	kmem_cache_free(acc_conn_cachep, ap);
}

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
					return NF_ACCEPT;
				}
				//ACC_DEBUG("IN Alloc acc_conn struct success\n");	
				ap->rcv_isn = tcphdr->seq;
			}
		} else if (tcphdr->fin) {
			ap = acc_conn_get(iph->protocol, iph->saddr, iph->daddr, tcphdr->source, tcphdr->dest);	
			if (ap == NULL) {
				return NF_ACCEPT;
			} 
			acc_conn_expire(ap);
			//ACC_DEBUG("IN ACC conn expire and free success\n");
		} else if (tcphdr->ack) {
			ap = acc_conn_get(iph->protocol, iph->saddr, iph->daddr, tcphdr->source, tcphdr->dest);
			if (ap == NULL) {
				//ACC_DEBUG("IN ACK packet, get acc_conn failed\n");
				return NF_ACCEPT;
			} 
			if (ap->ack_nr == 0) {
				ap->ack = skb_copy(skb, GFP_ATOMIC);
			}
			ap->ack_nr ++;	
			//ACC_DEBUG("IN ACK packet, get acc_conn success ack_nr=%u\n", ap->ack_nr);
		} 	
	}
	return NF_ACCEPT;
}

void acc_skb_enqueue (struct acc_conn *ap, struct sk_buff *newskb)
{
	struct sk_buff_head *list = &(ap->acc_queue);
	//struct dst_entry *old_dst;

	//old_dst = skb_dst(newskb);
	//skb_dst_set(newskb, NULL);
	// ...
	//skb_dst_set(newskb, old_dst);
	//dst_release(old_dst);

	//ACC_DEBUG("PKT: seq=%u ack_seq \n", TCP_SKB_CB(newskb)->seq);
	skb_queue_tail(list, newskb);
}

struct sk_buff *acc_alloc_ack(struct acc_conn *ap, struct sk_buff *skb)
{
	struct sk_buff *newack;
	struct tcphdr *tcphdr = NULL;
	struct tcphdr *newtcph = NULL;
	struct iphdr *iph = ip_hdr(skb);
	struct iphdr *newiph;
	unsigned int tcphoff ;
	struct dst_entry *old_dst;
	__u32 seq, end_seq, ack_seq;
	
	tcphdr = (struct tcphdr *)(skb_network_header(skb) + iph->ihl * 4);
	seq = (tcphdr->seq);
	end_seq = (TCP_SKB_CB(skb)->end_seq);
	ack_seq = (tcphdr->ack_seq);

	old_dst = skb_dst(ap->ack);
	newack = skb_copy(ap->ack, GFP_ATOMIC);
	tcphoff = ip_hdrlen(newack);
	
	skb_dst_set(newack, NULL);
	// ...
	skb_dst_set(newack, old_dst);
	dst_release(old_dst);

	newiph = ip_hdr(newack);
	newtcph = (struct tcphdr *)(skb_network_header(newack) + newiph->ihl * 4);

	if (!skb_make_writable(newack, sizeof(struct tcphdr) + tcphoff )) {
		//ACC_DEBUG("skb_make_writable failed\n");
		return NULL;
	}

	newtcph->seq = htonl(ack_seq - 1);
	newtcph->ack_seq = htonl(end_seq); 
	/* full checksum calculation */
	newtcph->check = 0;
	newack->csum = skb_checksum(newack, tcphoff, newack->len - tcphoff, 0);
	newtcph->check = csum_tcpudp_magic(newiph->saddr,
			newiph->daddr,
			newack->len - tcphoff,
			newiph->protocol,
			newack->csum);
	newack->ip_summed = CHECKSUM_UNNECESSARY;

	newack->pkt_type = PACKET_HOST;
	
	return newack;
}

void acc_send_queue(struct acc_conn *ap)
{
	struct sk_buff *skb;
	struct rtable *rt;		/* Route to the other host */
	while (!skb_queue_empty(&(ap->acc_queue))) {
		skb = skb_dequeue(&(ap->acc_queue));
		dev_queue_xmit(skb);
		//rt = (struct rtable *)skb_dst(skb);
		//NF_HOOK(PF_INET, NF_INET_LOCAL_OUT, (skb), NULL, (rt)->u.dst.dev, dst_output);
#if 0
		NF_HOOK_COND(PF_INET, NF_INET_POST_ROUTING, skb, NULL, skb->dev,
			    ip_finish_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));		
#endif
	}
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

	tcphdr = (struct tcphdr *)(skb_network_header(skb) + iph->ihl * 4);
	if (tcphdr->source == htons(80)) {
		if (!tcphdr->syn) {
			ap = acc_conn_get(iph->protocol, iph->daddr, iph->saddr, tcphdr->dest, tcphdr->source);
			if (ap == NULL) {
				ACC_DEBUG("OUT get acc_conn failed\n");
				return NF_ACCEPT;
			}
			ACC_DEBUG("OUT get acc_conn success, ack_nr=%u\n", ap->ack_nr);
			if (tcphdr->ack && TCP_SKB_CB(skb)->end_seq == ap->rcv_isn + 1) {
				return NF_ACCEPT;
			}

			/* Enqueue the pkt from TCP layer */
			data = skb_copy(skb, GFP_ATOMIC);
			acc_skb_enqueue(ap, data);
			ap->trigger --;
			if (tcphdr->fin || tcphdr->rst || ap->trigger == 0) {
			//	acc_send_queue(ap);
				ACC_DEBUG("Do not send queue here\n");
				ap->trigger = 10;
			} else {
				/* Generage ACKs */
				ack_skb = acc_alloc_ack(ap, skb);
				if (ack_skb)	
					ACC_DEBUG("Alloc ack_skb success\n");	
				netif_rx(ack_skb);
				//ACC_DEBUG("netif_rx ok\n");
			}
			//return NF_STOLEN;
			//return NF_DROP;
			return NF_ACCEPT;
		}
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

void acc_clean_up(void)
{
	/* Release the empty cache */
	kmem_cache_destroy(acc_conn_cachep);

	vfree(acc_conn_tab);

	/*icymoon: free the lock array, for our tiny hash lock*/
	vfree(__acc_conntbl_lock_array);
}

int acc_conn_init(void)
{
	unsigned idx;
	acc_conn_tab = vmalloc(ACC_CONN_TAB_SIZE*sizeof(struct list_head));
	if (!acc_conn_tab) {
		goto e_nomem;
	}
	/* Allocate acc_conn slab cache */
	acc_conn_cachep = kmem_cache_create("acc_conn",
			sizeof(struct acc_conn), 0,
			SLAB_HWCACHE_ALIGN, NULL);
	if (!acc_conn_cachep) {
		goto clean_conn_cachep;
	}
	/* icymoon: Allocate our lock array, each lock for each hash entry*/
	__acc_conntbl_lock_array = vmalloc(CT_LOCKARRAY_SIZE * sizeof(struct acc_aligned_lock));
	if (!__acc_conntbl_lock_array )
	{
		goto clean_conn_lock;
	}

	for (idx = 0; idx < ACC_CONN_TAB_SIZE; idx++) {
		INIT_LIST_HEAD(&acc_conn_tab[idx]);
	}

	for (idx = 0; idx < CT_LOCKARRAY_SIZE; idx++)  {
		__acc_conntbl_lock_array[idx].l = RW_LOCK_UNLOCKED;
	}

	return 0;

clean_conn_lock:
	vfree(__acc_conntbl_lock_array);
clean_conn_cachep:
	kmem_cache_destroy(acc_conn_cachep);
	vfree(acc_conn_tab);
e_nomem:
	return -ENOMEM;
}

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
	acc_clean_up();

	nf_unregister_hook(&nfin);
	nf_unregister_hook(&nfout);
	printk("AccNet test module exit\n");
	return;
}
module_init(acc_init);
module_exit(acc_exit);
