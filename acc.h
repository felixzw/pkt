#include <asm/types.h>                  /* for __uXX types */

#include <linux/list.h>                 /* for struct list_head */
#include <linux/spinlock.h>             /* for struct rwlock_t */
#include <linux/skbuff.h>               /* for struct sk_buff */
#include <linux/ip.h>                   /* for struct iphdr */
#include <asm/atomic.h>                 /* for struct atomic_t */
#include <linux/netdevice.h>		/* for struct neighbour */
#include <net/dst.h>			/* for struct dst_entry */
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <linux/compiler.h>
#include <linux/proc_fs.h>

#define ACC_CONN_TAB_SIZE 0xfff
#define CT_LOCKARRAY_MASK 0xfff
#define CT_LOCKARRAY_SIZE 0xfff

#define ACC_IN  0
#define ACC_OUT 1

#define ACC_DEBUG(msg...) \
	printk(KERN_INFO "ACC: " msg);

enum {
	SYN_RCV = 1,
	ESTAB,
	CLOSE,
};

struct acc_conn {
	struct list_head c_list;
	__be32 saddr;
	__be32 daddr;
	__be16 sport;
	__be16 dport;
	__be16 proto;

	struct net_device *indev;
	struct net_device *outdev;
	u8 src_mac[ETH_ALEN];
	u8 dst_mac[ETH_ALEN];

	__u32 state;  /* Intend for TCP/IP stack states */

	/*
	 *  This is important for pkts mangling 
	 *  NOTE: All seq are u32	
	 *  end_seq is using for calc pure ack
	 */
	__u32 seq;
	__u32 end_seq;

	__u32 ack_seq;
	__u32 rcv_seq;

	__u32 rcv_end_seq;
	__u32 rcv_ack_seq;
	
	__u32 rcv_isn; /* This is for? */
	__u32 acc_ack;  /* The seq ACC already ACKed, so we can drop the same incoming pure ack packet */

	__u32 in_seq_start;
	__u32 out_seq_start;
	
	/* skb queue for ACC */
	struct sk_buff_head send_queue;
	struct sk_buff_head rcv_queue; /* NOT using right now */

	struct sk_buff_head acc_write_queue;

	//struct sk_buff *ack; /* Cache the ack from remote, ugly here */

	/*
	 *  L4  strategy 
	 *  cwnd 
	 *  ssthresh
	 * */

	__u32 ssthresh;
	__u32 cwnd;
	
	/*
	* ACK will trigger to send data
	* each ACK will send snd_wnd's pkts
	*/
	__u32 snd_wnd;
	
	__u32 snd_una;
	// for debug using
	__u32 trigger;
	__u32 ack_nr;

	int (*in_okfn)(struct sk_buff *);
	int (*out_okfn)(struct sk_buff *);
};

/*
 * lock array element for acc_conn
 */
struct acc_aligned_lock
{
    rwlock_t	l;
};



extern int is_nilack(struct sk_buff *skb, int dir);
extern void acc_skb_enqueue (struct acc_conn *ap, struct sk_buff *newskb);
extern struct sk_buff *acc_alloc_ack(struct acc_conn *ap, struct sk_buff *skb);
extern struct sk_buff *acc_alloc_nilack(struct acc_conn *ap, struct sk_buff *skb);
extern void acc_send_queue(struct acc_conn *ap);
extern int acc_send_skb(struct sk_buff *skb, struct acc_conn *ap);



extern struct acc_conn *acc_conn_new(int proto, __be32 saddr, __be32 daddr, __be16 sport, __be16 dport);
extern struct acc_conn *acc_conn_get(int proto, __be32 saddr, __be32 daddr, __be16 sport, __be16 dport, int dir);
extern void acc_conn_expire(struct acc_conn *ap);
extern void acc_conn_cleanup(void);
extern int acc_conn_init(void);


/**
 *      ACC WRITE QUEUE OPS
 **/
static inline void acc_unlink_write_queue(struct sk_buff *skb, struct acc_conn *cp)
{
	__skb_unlink (skb, &cp->acc_write_queue);
}

static inline void acc_write_queue_empty(struct acc_conn *cp)
{
	return skb_queue_empty(&cp->acc_write_queue);
}

static inline void __acc_add_write_queue_head(struct acc_conn *cp, struct sk_buff *skb)
{
	__skb_queue_head(&cp->acc_write_queue, skb);
}

static inline void __acc_add_write_queue_tail(struct acc_conn *cp, struct sk_buff *skb)
{
	__skb_queue_tail(&cp->acc_write_queue, skb);
}

static inline void acc_add_write_queue_tail(struct acc_conn *cp, struct sk_buff *skb)
{
	__acc_add_write_queue_tail(cp, skb);

	/* Queue it, remembering where we must start sending. */
	/*
	if (sk->sk_send_head == NULL) {
		sk->sk_send_head = skb;

		if (tcp_sk(sk)->highest_sack == NULL)
			tcp_sk(sk)->highest_sack = skb;
	}
	*/
}

static inline struct sk_buff *acc_write_queue_head(struct acc_conn *cp)
{
	return skb_peek(&cp->sk_write_queue);
}
