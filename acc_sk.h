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


