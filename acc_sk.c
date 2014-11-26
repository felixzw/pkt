#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "acc.h"
/*
 * It is ugly here ...
 * */

int is_nilack(struct sk_buff *skb, int dir)
{
	struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *th = (struct tcphdr *)(skb_network_header(skb) + iph->ihl * 4);
	__u32 end_seq = ntohl(th->seq) + th->syn + th->fin + skb->len - th->doff * 4 - ip_hdr(skb)->ihl * 4;
	if (dir == 0) { /* IN coming pkt */
		if (th->ack && ntohl(th->seq) == end_seq) {
			return 1;
		}
	} else {  /* Out going pkt */
		if (th->ack && TCP_SKB_CB(skb)->seq == TCP_SKB_CB(skb)->end_seq) {
			printk("== %u %u\n", TCP_SKB_CB(skb)->seq, TCP_SKB_CB(skb)->end_seq);
			return 1;
		}

	}
	return 0;
}

void acc_skb_enqueue (struct acc_conn *ap, struct sk_buff *skb)
{
	struct sk_buff *nskb;
	struct sk_buff_head *list = &(ap->send_queue);
	//struct dst_entry *old_dst;

	//old_dst = skb_dst(nskb);
	//skb_dst_set(nskb, NULL);
	// ...
	//skb_dst_set(nskb, old_dst);
	//dst_release(old_dst);

	//ACC_DEBUG("PKT: seq=%u ack_seq \n", TCP_SKB_CB(nskb)->seq);

	nskb = skb_copy(skb, GFP_ATOMIC);
	if (nskb->cloned) {
		nskb->cloned = 0;
	}
	atomic_set(&nskb->users, 1);
	skb_queue_tail(list, nskb);
}

struct sk_buff *acc_alloc_nilack(struct acc_conn *ap, struct sk_buff *skb)
{
	struct sk_buff *nskb;
	struct tcphdr *th;
	struct iphdr *iph;
	__u32 nseq, nack_seq;
	int l4len, ret;
	struct rtable *rt;
	struct flowi fl = {};

	iph = (struct iphdr *)ip_hdr(skb);
	th = (struct tcphdr *)(skb_network_header(skb) + iph->ihl * 4);
	
	nseq =  htonl(ap->rcv_end_seq);  /* NOTE: The ack packet donot take any sequence */
	nack_seq = htonl((TCP_SKB_CB(skb)->end_seq));

	nskb = alloc_skb(MAX_TCP_HEADER, GFP_ATOMIC);
	if (nskb == NULL) {
		ACC_DEBUG("alloc skb failed\n");
		return NULL;
	}
	/* Reserve space for headers and prepare control bits. */
	skb_reserve(nskb, MAX_TCP_HEADER);
	
	th = (struct tcphdr *)skb_push(nskb, sizeof(struct tcphdr));
	th->source    = ap->sport;
	th->dest    = ap->dport;
	th->doff    = sizeof(struct tcphdr) >> 2;
	th->seq        = nseq;
	th->ack_seq  = nack_seq;
	th->window    = htons(0xFFFF);

	th->fin = 0;
	th->syn = 0;
	th->ack = 1;
	th->rst = 0;
	//*(((__be16 *)th) + 6) = htons(((tcp_header_size >> 2) << 12) | TCPCB_FLAG_ACK);

	skb_reset_transport_header(nskb);

	iph = (struct iphdr *)skb_push(nskb, sizeof(struct iphdr));
	iph->ihl    = sizeof(struct iphdr) >> 2;
	iph->version    = 4;
	iph->tot_len    = htons(nskb->len);
	iph->ttl    = 64;
	iph->protocol    = IPPROTO_TCP;
	iph->saddr    = ap->saddr;
	iph->daddr    = ap->daddr;
	ip_send_check(iph);
	skb_reset_network_header(nskb);

	th->check = 0;
	nskb->csum = skb_checksum(nskb, ip_hdrlen(nskb), nskb->len - ip_hdrlen(nskb), 0);
	th->check = csum_tcpudp_magic(iph->saddr,
			iph->daddr,
			nskb->len - ip_hdrlen(nskb),
			iph->protocol,
			nskb->csum);
	nskb->ip_summed = CHECKSUM_UNNECESSARY;
	nskb->pkt_type = PACKET_HOST;
	/* NOTE: skb->dev will used in ip_local_deliver_finish */
	nskb->dev = ap->indev;
	/* ip_route_me_harder expects skb->dst to be set */
	//skb_dst_set(nskb, dst_clone(skb_dst(ap->ack)));

	//fl.nl_u.ip4_u.daddr = iph->daddr;
	//if (ip_route_input(nskb, iph->daddr, iph->saddr, RT_TOS(iph->tos), ap->indev) != 0)
	/*if (ip_route_me_harder(nskb, RTN_LOCAL))
	{
		ACC_DEBUG("ip_route_output_key");
		kfree_skb(nskb);
		return NULL;
	}
	*/
	//skb_dst_set(nskb, &rt->u.dst);
	//printk("skb->len: %u\n", skb->len);
	ret = ip_route_input(nskb, iph->daddr, iph->saddr, iph->tos, ap->indev);
	if (ret) {
		ACC_DEBUG("ip_route_input failed %u\n", -ret);
		kfree_skb(nskb);
		return NULL;
	}

	//ACC_DEBUG("ip_local_deliver pointer=%p \n", skb_dst(nskb)->input);
	return nskb;
}

#if 0
struct sk_buff *acc_alloc_ack(struct acc_conn *ap, struct sk_buff *skb)
{
	struct sk_buff *nack;
	struct tcphdr *th = NULL;
	struct tcphdr *newth = NULL;
	struct iphdr *iph = ip_hdr(skb);
	struct iphdr *newiph;
	unsigned int tcphoff ;
	struct dst_entry *old_dst;
	__u32 seq, end_seq, ack_seq;
	
	th = (struct tcphdr *)(skb_network_header(skb) + iph->ihl * 4);

	seq = ntohl(th->seq);
	end_seq = (TCP_SKB_CB(skb)->end_seq);
	ack_seq = ntohl(th->ack_seq);

	old_dst = skb_dst(ap->ack);
	nack = skb_copy(ap->ack, GFP_ATOMIC);
	tcphoff = ip_hdrlen(nack);
	
	skb_dst_set(nack, NULL);
	// ...
	skb_dst_set(nack, old_dst);
	dst_release(old_dst);

	newiph = ip_hdr(nack);
	newth = tcp_hdr(nack);

	if (!skb_make_writable(nack, sizeof(struct tcphdr) + tcphoff)) {
		//ACC_DEBUG("skb_make_writable failed\n");
		return NULL;
	}

	//ACC_DEBUG("alloc_ack seq=%u  ack_seq=%u\n", htonl(ack_seq - 1), htonl(end_seq));
	ACC_DEBUG("cur_skb: seq=%u  ack_seq=%u\n", ntohl(tcp_hdr(skb)->seq), ntohl(tcp_hdr(skb)->ack_seq));
	newth->seq = htonl(ap->rcv_end_seq);  /* NOTE: The ack packet donot take any sequence */
	newth->ack_seq = htonl(end_seq); 
	/* full checksum calculation */
	newth->check = 0;
	nack->csum = skb_checksum(nack, tcphoff, nack->len - tcphoff, 0);
	newth->check = csum_tcpudp_magic(newiph->saddr,
			newiph->daddr,
			nack->len - tcphoff,
			newiph->protocol,
			nack->csum);
	nack->ip_summed = CHECKSUM_UNNECESSARY;

	nack->pkt_type = PACKET_HOST;
	
	return nack;
}
#endif

int acc_send_skb(struct sk_buff *skb, struct acc_conn *ap)
{
	int mtu;
	struct iphdr *iph = ip_hdr(skb);
	struct dst_entry * old_dst;

	/* save old dst */
	old_dst = skb_dst(skb);
	skb_dst_set(skb, NULL);

	/* MTU checking */
	skb->dev = ap->indev;
	mtu = skb->dev->mtu;

	if ((skb->len > mtu) && (iph->frag_off&__constant_htons(IP_DF))) {
		/* replace with old dst, or we will send icmp to ourself */
		skb_dst_set(skb, old_dst);
		icmp_send(skb, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED, htonl(mtu));
		goto tx_error;
	}

	/* skb_dst(skb) has been updated, we don't need old_dst any more, drop old route */
	dst_release(old_dst);

	/* copy-on-write the packet before mangling it 
	if (!skb_make_writable(skb, sizeof(struct iphdr))) {
		goto tx_error;
	}
	
	if (skb_cow(skb, skb->dev->hard_header_len)) {
		goto tx_error;
	}
	//ip_hdr(skb)->saddr = cp->vaddr;
	//ip_hdr(skb)->daddr = cp->caddr;
	
	//ip_send_check(ip_hdr(skb));
	*/
	skb_push(skb, ETH_HLEN);
	//unset mac header for setting mac address 
	skb_set_mac_header(skb, 0-sizeof(struct ethhdr));


	/* FIXME: when application helper enlarges the packet and the length
	 * 	   is larger than the MTU of outgoing device, there will be still
	 * 	   	   MTU problem. */

	/* Another hack: avoid icmp_send in ip_fragment */
	skb->local_df = 1;
	//skb->data = (unsigned char *)skb_mac_header(skb);

	//skb->len += ETH_HLEN;

	skb->pkt_type = PACKET_OUTGOING;
	
	if (ap->dst_mac == NULL || ap->src_mac == NULL) {
		ACC_DEBUG("NULL pointer of mac\n");
		return 1;
	}
#if 0
  else {
		ACC_DEBUG("SNED ACC-MAC SRC %2x.%2x.%2x.%2x.%2x.%2x\n", 
				ap->src_mac[0],
				ap->src_mac[1],
				ap->src_mac[2],
				ap->src_mac[3],
				ap->src_mac[4],
				ap->src_mac[5]);

		ACC_DEBUG("SEND ACC-MAC DEST %2x.%2x.%2x.%2x.%2x.%2x\n", 
				ap->dst_mac[0],
				ap->dst_mac[1],
				ap->dst_mac[2],
				ap->dst_mac[3],
				ap->dst_mac[4],
				ap->dst_mac[5]);
	}
#endif	
	memcpy(eth_hdr(skb)->h_source, ap->dst_mac, ETH_ALEN);
	
	if (!skb_mac_header_was_set(skb)) {
		ACC_DEBUG("SKB MAC ERROR\n");
		return 1;
	}

	memcpy(eth_hdr(skb)->h_dest, ap->src_mac, ETH_ALEN);

	eth_hdr(skb)->h_proto = htons(ETH_P_IP);

	ACC_DEBUG("dev_queue_xmit out\n");	

	dev_queue_xmit(skb);
	return 0;
tx_error:
	kfree_skb(skb);
	return 1;
}


/*
 * NOTE: Must clone skb first before we send it out 
 * */
void acc_send_queue(struct acc_conn *ap)
{
	struct sk_buff *skb, *n, *buff;
	struct dst_entry *old_dst;

	skb_queue_walk_safe(&(ap->send_queue), skb, n)  {
		//skb_unlink(skb, &(ap->acc_queue));
		//dev_queue_xmit(skb);
		buff = skb_clone(skb, GFP_ATOMIC);
		acc_send_skb(buff, ap);
		ACC_DEBUG("Sending data: seq=%u\n", ntohl(tcp_hdr(skb)->seq));
	}
	
	//while (!skb_queue_empty(&(ap->acc_queue))) {
	//	skb = skb_dequeue(&(ap->acc_queue));
	
		/*old_dst = skb_dst(skb);
		skb_dst_set(skb, NULL);
		skb_dst_set(skb, old_dst);
		dst_release(old_dst);

		if (!skb_make_writable(skb, sizeof(struct tcphdr) + tcp_hdr(skb)->doff*4)) {
			//ACC_DEBUG("skb_make_writable failed\n");
			return;
		}
		*/
	//	skb->pkt_type = PACKET_OUTGOING; 
		//dev_queue_xmit(skb);
		//rt = (struct rtable *)skb_dst(skb);
		//NF_HOOK(PF_INET, NF_INET_LOCAL_OUT, (skb), NULL, (rt)->u.dst.dev, dst_output);
#if 0
		NF_HOOK_COND(PF_INET, NF_INET_POST_ROUTING, skb, NULL, skb->dev,
			    ip_finish_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));		
#endif
	//}
}

