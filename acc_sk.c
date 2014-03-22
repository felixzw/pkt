#include "acc.h"

/*
 * It is ugly here ...
 * */

int is_nilack(struct sk_buff *skb, int dir)
{
	struct tcphdr *th = tcp_hdr(skb);
	__u32 end_seq = ntohl(th->seq) + th->syn + th->fin + skb->len - th->doff * 4 - ip_hdr(skb)->ihl * 4;
	if (dir == 0) { /* IN coming pkt */
		if (th->ack && ntohl(th->seq) == end_seq) {
			return 1;
		}
	} else {  /* Out going pkt */
		if (th->ack && TCP_SKB_CB(skb)->seq == TCP_SKB_CB(skb)->end_seq) {
			return 1;
		}

	}
	return 0;
}

void acc_skb_enqueue (struct acc_conn *ap, struct sk_buff *nskb)
{
	struct sk_buff_head *list = &(ap->send_queue);
	struct dst_entry *old_dst;

	//old_dst = skb_dst(nskb);
	//skb_dst_set(nskb, NULL);
	// ...
	//skb_dst_set(nskb, old_dst);
	//dst_release(old_dst);

	//ACC_DEBUG("PKT: seq=%u ack_seq \n", TCP_SKB_CB(nskb)->seq);
	skb_queue_tail(list, nskb);
}

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

void acc_send_queue(struct acc_conn *ap)
{
	struct sk_buff *skb, *n;
	struct dst_entry *old_dst;
	/* Route to the other host */

	//skb_queue_walk_safe(&(ap->acc_queue), skb, n)  {
	//	skb_unlink(skb, &(ap->acc_queue));
	//	dev_queue_xmit(skb);
	//	ACC_DEBUG("Sending data: seq=%u\n", ntohl(tcp_hdr(skb)->seq));
	//}
	
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

