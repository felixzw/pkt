#include "acc.h"

static int acc_data_snd(struct acc_conn *cp)
{
	struct sk_buff *skb;
	int snd_cnt = 0;

	while ((skb = acc_write_queue_head(cp)) && skb != acc_send_head(sk)) {
		while (snd_cnt < cp->snd_wnd) {

		}
	
	}
}



