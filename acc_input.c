#include "acc.h"


/*
 *	Input direction
 *	When we recv the new data ACK, trigger the clean_rtx
 *	1) Free the skb which seq is lower than new ack_seq
 *	2) Trigger to send nilack?

 *	skb in rtx queue already have cb[control block]
 * */
static int acc_clean_rtx_queue(struct acc_conn *cp, u32 ack)
{
	struct sk_buff *skb;
	int fully_acked = 1;

	while ((skb = acc_write_queue_head(cp)) && skb != acc_send_head(cp)) {
		struct tcp_skb_cb *scb = TCP_SKB_CB(skb);
		if (after(scb->end_seq, ack)) {
			fully_acked = 0;
		}
	
		if (!fully_acked)
			break;

		cp->snd_wnd ++;
		acc_unlink_write_queue(skb, cp);
		__kfree_skb(skb);
	}
}



