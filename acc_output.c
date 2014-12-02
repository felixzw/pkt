#include "acc.h"

static int acc_data_snd(struct acc_conn *cp)
{
	struct sk_buff *skb;
	int snd_cnt = 0;

	while ((skb = acc_write_queue_head(cp)) && skb != acc_send_head(cp)) {
		if (snd_cnt > cp->snd_wnd) {
			break;
		}

		/* Send */
		skb->pkt_type = PACKET_OUTGOING;
		/* Exchange mac address, 00-00-00-00-00-00 for loopback dev */
		if(likely(ARPHRD_ETHER == skb->dev->type || ARPHRD_LOOPBACK == skb->dev->type)) {
			unsigned char t_hwaddr[ETH_ALEN];

			/* Move the data pointer to point to the link layer header */
			struct ethhdr *eth = (struct ethhdr *)eth_hdr(skb);
			skb->data = (unsigned char *)eth_hdr(skb);
			skb->len += ETH_HLEN; //sizeof(skb->mac.ethernet);

			memcpy((eth->h_dest), cp->dst_mac, ETH_ALEN);
			memcpy((eth->h_source), cp->src_mac, ETH_ALEN);
		}

		dev_queue_xmit(skb);

		/* Ajust the send head */
		acc_advance_send_head(cp, skb);
	}
}



