#include "acc.h"


#define ACC_CONN_TAB_SIZE 0xfff
#define CT_LOCKARRAY_MASK 0xfff
#define CT_LOCKARRAY_SIZE 0xfff

#define ACC_DEBUG(msg...) \
	printk(KERN_INFO "ACC: " msg);



struct list_head *acc_conn_tab;
/*  SLAB cache for IPVS connections */
static struct kmem_cache  *acc_conn_cachep;
struct acc_aligned_lock *__acc_conntbl_lock_array;

static inline void ct_read_lock(unsigned key)
{
	read_lock(&__acc_conntbl_lock_array[key&CT_LOCKARRAY_MASK].l);
}
static inline void ct_read_unlock(unsigned key)
{
	read_unlock(&__acc_conntbl_lock_array[key&CT_LOCKARRAY_MASK].l);
}

static inline void ct_write_lock(unsigned key)
{
	write_lock(&__acc_conntbl_lock_array[key&CT_LOCKARRAY_MASK].l);
}

static inline void ct_write_unlock(unsigned key)
{
	write_unlock(&__acc_conntbl_lock_array[key&CT_LOCKARRAY_MASK].l);
}

static inline unsigned __hash(int proto, __be32 saddr, __be32 daddr, __be16 sport, __be16 dport, int reverse)
{
	unsigned hash;
	if (reverse) {
		 hash = (proto + saddr + daddr + sport + dport)%100;
	} else {
		 hash = (proto + saddr + daddr + sport + dport)%100;
	}
	return hash;
}

static inline int acc_conn_unhash(struct acc_conn *ap)
{
	unsigned hash;
	int ret = 0;

	hash = __hash(ap->proto, ap->saddr, ap->daddr, ap->sport, ap->dport, 0);
	
	ct_write_lock(hash);
	
	list_del(&ap->c_list);

	ct_write_unlock(hash);

	return ret;
}

struct acc_conn *acc_conn_get(int proto, __be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	unsigned hash;
	struct acc_conn *ap;

	hash = __hash(proto, saddr, daddr, sport, dport, 0);
	ct_read_lock(hash);

	list_for_each_entry(ap, &acc_conn_tab[hash], c_list) {
		if (saddr==ap->saddr && sport==ap->sport &&
		    dport==ap->dport && daddr==ap->daddr &&
		    proto == ap->proto) {
			/* HIT */
			ct_read_unlock(hash);
			return ap;
		}
	}

	ct_read_unlock(hash);
	return NULL;
}



struct acc_conn *acc_conn_new(int proto, __be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	struct acc_conn* ap;
	unsigned hash;
	
	ap = kmem_cache_alloc(acc_conn_cachep, GFP_ATOMIC);
	if (ap == NULL) {
		return NULL;
	}

	memset(ap, 0, sizeof(*ap));
	INIT_LIST_HEAD(&ap->c_list);
	ap->proto = proto;
	ap->saddr = saddr;
	ap->daddr = daddr;
	ap->sport = sport;
	ap->dport = dport;
	ap->state = SYN_RCV;
	
	ap->acc_ssthresh = 20;
	ap->ack = NULL;
	ap->ack_nr = 0;
	ap->trigger = 10;
	ap->rcv_isn = 0;
	ap->last_end_seq = 0;
	//ap->rcv_seq = 0;
	skb_queue_head_init(&(ap->acc_queue));

	/* Hash to acc_conn_tab */
	hash = __hash(proto, saddr, daddr, sport, dport, 0);	
	ct_write_lock(hash);
	list_add(&ap->c_list, &acc_conn_tab[hash]);
	ct_write_unlock(hash);

	return ap;
}

void acc_conn_expire(struct acc_conn *ap)
{
	if (ap->ack) {
		kfree_skb(ap->ack);
	}
	acc_conn_unhash(ap);
	kmem_cache_free(acc_conn_cachep, ap);
}


void acc_conn_cleanup(void)
{
	/* Release the empty cache */
	kmem_cache_destroy(acc_conn_cachep);

	vfree(acc_conn_tab);

	/*icymoon: free the lock array, for our tiny hash lock*/
	vfree(__acc_conntbl_lock_array);
}

int acc_conn_init(void)
{
	unsigned idx;
	acc_conn_tab = vmalloc(ACC_CONN_TAB_SIZE*sizeof(struct list_head));
	if (!acc_conn_tab) {
		goto e_nomem;
	}
	/* Allocate acc_conn slab cache */
	acc_conn_cachep = kmem_cache_create("acc_conn",
			sizeof(struct acc_conn), 0,
			SLAB_HWCACHE_ALIGN, NULL);
	if (!acc_conn_cachep) {
		goto clean_conn_cachep;
	}
	/* icymoon: Allocate our lock array, each lock for each hash entry*/
	__acc_conntbl_lock_array = vmalloc(CT_LOCKARRAY_SIZE * sizeof(struct acc_aligned_lock));
	if (!__acc_conntbl_lock_array )
	{
		goto clean_conn_lock;
	}

	for (idx = 0; idx < ACC_CONN_TAB_SIZE; idx++) {
		INIT_LIST_HEAD(&acc_conn_tab[idx]);
	}

	for (idx = 0; idx < CT_LOCKARRAY_SIZE; idx++)  {
		__acc_conntbl_lock_array[idx].l = RW_LOCK_UNLOCKED;
	}

	return 0;

clean_conn_lock:
	vfree(__acc_conntbl_lock_array);
clean_conn_cachep:
	kmem_cache_destroy(acc_conn_cachep);
	vfree(acc_conn_tab);
e_nomem:
	return -ENOMEM;
}


