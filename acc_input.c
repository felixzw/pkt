#include "acc.h"


/*
 *	Input direction
 *	When we recv the new data ACK, trigger the clean_rtx
 *	1) Free the skb which seq is lower than new ack_seq
 *	2) Trigger to send nilack?
 * */
static int acc_clean_rtx_queue(struct acc_conn *cp, u32 ack)
{

}



