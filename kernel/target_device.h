/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef __TARGET_DEVICE_H__
#define __TARGET_DEVICE_H__

#include <linux/version.h>
#include <linux/list.h>
#include <linux/wait.h>

struct target;

struct target_device {
	struct list_head list;
	int id;
	int usage;

	wait_queue_head_t thread_wait;
	struct task_struct *dev_thread;
	int poll_flags;

	spinlock_t ready_list_lock;
	struct list_head ready_list;		/* queued commands */
	struct semaphore io_sem;
	struct list_head io_list;		/* list of cmnds waiting for i/o */
	//struct list_head wait_list;		/* list of cmnds waiting for data pdus
	//					   to be sent/received */

	int blk_shift;
	int idx_shift;		// PAGE_CACHE_SHIFT - blk_shift
	int blk_cnt;

	struct file *file;
	struct address_space *mapping;

	struct proc_dir_entry *proc_dir;

	// ops structure?
	void (*read)(struct target_device *, struct page *,
		     unsigned int start, unsigned int end);
	void (*write)(struct target_device *, struct page *,
		      unsigned int start, unsigned int end);
};

extern struct target_device *target_bdev_attach(struct file *file);
extern void target_bdev_detach(struct target_device *device);

static inline wait_queue_head_t *page_waitqueue(struct page *page)
{
	const zone_t *zone = page_zone(page);
	wait_queue_head_t *wait = zone->wait_table;
	unsigned long hash = (unsigned long)page;

#if BITS_PER_LONG == 64
#define GOLDEN_RATIO_PRIME 0x9e37fffffffc0001UL
	/*  Sigh, gcc can't optimise this alone like it does for 32 bits. */
	unsigned long n = hash;
	n <<= 18;
	hash -= n;
	n <<= 33;
	hash -= n;
	n <<= 3;
	hash += n;
	n <<= 3;
	hash -= n;
	n <<= 4;
	hash += n;
	n <<= 2;
	hash += n;
#else
#define GOLDEN_RATIO_PRIME 0x9e370001UL
	/* On some cpus multiply is faster, on others gcc will do shifts */
	hash *= GOLDEN_RATIO_PRIME;
#endif

	hash >>= zone->wait_table_shift;

	return &wait[hash];
}


#endif	/* __TARGET_DEVICE_H__ */
