/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef __TARGET_H__
#define __TARGET_H__

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/wait.h>

struct target_device;
struct target_cmnd;

struct target {
	struct list_head list;
	u32 id;

	struct proc_dir_entry *proc_dir;

	//spinlock_t list_lock;
	//struct list_head io_list;
};

#define TARGET_CMND_MAX_PAGES	8
#define TARGET_CMND_MAX_DATA	(TARGET_CMND_MAX_PAGES * PAGE_CACHE_SIZE)

struct target_cmnd_head {
	struct target_cmnd *next;
	u32 pg_cnt;
	unsigned long idx;
	u32 offset;
	u32 size;

	struct page *wait_page;
	wait_queue_t wq;
};

struct target_cmnd {
	struct target_cmnd *next;
	u32 pg_cnt;
	union {
		struct {
			unsigned long idx;
			u32 offset;
			u32 size;

			struct page *wait_page;
			wait_queue_t wq;
			struct page *io_pages[TARGET_CMND_MAX_PAGES];
			// FIXME
			//struct buffer_head *bh[TARGET_CMND_MAX_PAGES];
		} pg;
		char data[1];
	} u;
};

#define TARGET_WRITE		0
#define TARGET_WRITE_ASYNC	1
#define TARGET_ASYNC		2
//#define TARGET_READ		3

extern struct target_cmnd *target_cmnd_create(void);
extern int target_alloc_pages(struct target_cmnd *cmnd, int count);
extern void target_free_pages(struct target_cmnd *cmnd);
extern void target_init_read(struct target_device *dev, struct target_cmnd *tcmnd, loff_t offset, u32 size);
extern int target_get_read_pages(struct target_device *dev, struct target_cmnd *cmnd);
extern void target_init_write(struct target_device *dev, struct target_cmnd *tcmnd, loff_t offset, u32 size);
extern void target_get_async_pages(struct target_device *dev, struct target_cmnd *tcmnd, u32 size);
extern int target_get_write_pages(struct target_device *dev, struct target_cmnd *cmnd);
extern int target_sync_async_pages(struct target_device *dev, struct target_cmnd *tcmnd);
extern void target_clear_pages(struct target_cmnd *tcmnd, int offset, int size);
extern int target_commit_pages(struct target_device *dev, struct target_cmnd *cmnd);
extern int target_wait_pages(struct target_device *dev, struct target_cmnd *cmnd);
extern int target_sync_pages(struct target_device *dev, struct target_cmnd *cmnd);
extern void target_put_pages(struct target_cmnd *cmnd);
extern int target_init(void);
extern void target_exit(void);

#endif	/* __TARGET_H__ */
