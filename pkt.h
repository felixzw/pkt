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
#include <linux/compiler.h>
#include <linux/proc_fs.h>

#define ACC_CONN_TAB_SIZE 0xfff
#define CT_LOCKARRAY_MASK 0xfff
#define CT_LOCKARRAY_SIZE 0xfff

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

	__u32 state;
	__u32 ack_nr;

	struct sk_buff *ack;
	__u32 acc_ssthresh;
	struct sk_buff_head acc_queue;

	__be32 rcv_isn;
	__u32 trigger;
};

/*
 * lock array element for acc_conn
 */
struct acc_aligned_lock
{
    rwlock_t	l;
};


