#include "acc.h"

static inline int is_nilack(struct sk_buff *skb, int dir)
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

void acc_skb_enqueue (struct acc_conn *ap, struct sk_buff *newskb)
{
	struct sk_buff_head *list = &(ap->acc_queue);
	struct dst_entry *old_dst;

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

	seq = ntohl(tcphdr->seq);
	end_seq = (TCP_SKB_CB(skb)->end_seq);
	ack_seq = ntohl(tcphdr->ack_seq);

	old_dst = skb_dst(ap->ack);
	newack = skb_copy(ap->ack, GFP_ATOMIC);
	tcphoff = ip_hdrlen(newack);
	
	skb_dst_set(newack, NULL);
	// ...
	skb_dst_set(newack, old_dst);
	dst_release(old_dst);

	newiph = ip_hdr(newack);
	newtcph = tcp_hdr(newack);

	if (!skb_make_writable(newack, sizeof(struct tcphdr) + tcphoff)) {
		//ACC_DEBUG("skb_make_writable failed\n");
		return NULL;
	}

	//ACC_DEBUG("alloc_ack seq=%u  ack_seq=%u\n", htonl(ack_seq - 1), htonl(end_seq));
	ACC_DEBUG("cur_skb: seq=%u  ack_seq=%u\n", ntohl(tcp_hdr(skb)->seq), ntohl(tcp_hdr(skb)->ack_seq));
	newtcph->seq = htonl(ap->last_end_seq);  /* NOTE: The ack packet donot take any sequence */
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

