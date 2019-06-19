/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <linux/compiler.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/pagemap.h>

#include "target.h"
#include "target_dbg.h"
#include "target_device.h"

#define D_GENERIC	0

#if TARGET_EVENTS

static struct target_event target_event_buffer[EVENT_COUNT];
static unsigned long target_event_cnt;
static spinlock_t target_event_lock = SPIN_LOCK_UNLOCKED;

void target_print_events(void)
{
	struct target_event *event;
	unsigned long i, flags;

	spin_lock_irqsave(&target_event_lock, flags);
	i = target_event_cnt < EVENT_COUNT ? 0 : target_event_cnt - EVENT_COUNT;
	printk("target_events: %lu-%lu\n", i, target_event_cnt);
	for (; i < target_event_cnt; i++) {
		event = target_event_buffer + (i & EVENT_MASK);
		printk("%u: ", event->time);
		switch (event->type) {
		case E_ALLOC_PAGES: printk("alloc pages "); break;
		case E_ALLOC_CMND: printk("alloc cmnd "); break;
		case E_ALLOC_PAGE: printk("alloc page "); break;
		case E_ALLOC_PAGE_FAILED: printk("alloc page failed "); break;
		case E_FREE_PAGES: printk("free pages "); break;
		case E_FREE_PAGE: printk("free page "); break;
		case E_FREE_CMND: printk("free cmnd "); break;
		case E_WAIT_READ_PAGE: printk("wait read page "); break;
		case E_READ_PAGES: printk("read pages "); break;
		case E_GOT_NEW_PAGE: printk("got new page "); break;
		case E_GOT_OLD_PAGE: printk("got old page "); break;
		case E_DO_READ_PAGE: printk("do read page "); break;
		case E_WAIT_WRITE_PAGE: printk("wait write page "); break;
		case E_GET_ASYNC_PAGES: printk("get async pages "); break;
		case E_GET_WRITE_PAGES: printk("get write pages "); break;
		case E_GOT_NUP2DATE_PAGE: printk("got !up2date page "); break;
		case E_GOT_LOCKED_PAGE: printk("got locked page "); break;
		case E_GOT_UP2DATE_PAGE: printk("got up2date page "); break;
		case E_INSERTED_ASYNC_PAGE: printk("inserted async page "); break;
		case E_GOT_OTHER_PAGE: printk("got other page "); break;
		case E_COPY_READ_PAGE: printk("copy read page "); break;
		case E_COPY_WRITE_PAGE: printk("copy write page "); break;
		case E_CLEAR_PAGES: printk("clear pages "); break;
		case E_CLEAR_PAGE: printk("clear page "); break;
		case E_COMMIT_PAGES: printk("commit pages "); break;
		case E_COPY_ASYNC_PAGE: printk("copy async page "); break;
		case E_GOT_ASYNC_PAGE: printk("got async page "); break;
		case E_DO_WRITE_PAGE: printk("do write page "); break;
		case E_WAIT_PAGES: printk("wait pages "); break;
		case E_SYNC_PAGES: printk("sync pages "); break;
		case E_GOT_PAGE: printk("got page "); break;
		case E_WAIT_PAGE: printk("wait page "); break;
		case E_PUT_PAGES: printk("put pages "); break;
		case E_PUT_PAGE: printk("put page "); break;
		case E_BDEV_READ: printk("bdev read "); break;
		case E_BDEV_WRITE: printk("bdev write "); break;
		case E_BDEV_END_READ: printk("bdev end read "); break;
		case E_BDEV_END_WRITE: printk("bdev end write "); break;
		case IE_CMND_CREATE: printk("iscsi cmnd create "); break;
		case IE_CMND_REMOVE: printk("iscsi cmnd remove "); break;
		case IE_CMND_START_READ: printk("iscsi cmnd start read "); break;
		case IE_CMND_SCSI: printk("iscsi cmnd scsi "); break;
		case IE_CMND_FINISH_READ: printk("iscsi cmnd finish read "); break;
		case IE_CMND_EXECUTE: printk("iscsi cmnd execute "); break;
		case IE_CMND_INIT_WRITE: printk("iscsi cmnd init write "); break;
		case IE_CMND_START_WRITE: printk("iscsi cmnd start write "); break;
		case IE_CMND_FINISH_WRITE: printk("iscsi cmnd finish write "); break;
		case IE_CMND_RELEASE: printk("iscsi cmnd release "); break;
		case IE_CMND_PREPARE_SEND: printk("iscsi cmnd prepare send "); break;
		case IE_CMND_SEND_PDU: printk("iscsi cmnd send pdu "); break;
		case IE_CMND_RECEIVE_PDU: printk("iscsi cmnd receive pdu "); break;
		case IE_CMND_UNMAP_PDU: printk("iscsi cmnd unmap pdu "); break;
		case IE_SCSI_QUEUE: printk("iscsi scsi queue "); break;
		case IE_SCSI_EXECUTE: printk("iscsi scsi execute "); break;
		case IE_SESSION_INSERT: printk("iscsi session insert "); break;
		case IE_SESSION_REMOVE: printk("iscsi session remove "); break;
		case IE_SESSION_INSERT_TTT: printk("iscsi session insert ttt "); break;
		case IE_SESSION_REMOVE_TTT: printk("iscsi session remove ttt "); break;
		case IE_SESSION_PUSH: printk("iscsi session push "); break;
		case IE_SESSION_CHECK_CMDSN: printk("iscsi session check cmdsn "); break;
		case IE_SESSION_UPDATE_STATSN: printk("iscsi session update statsn "); break;
		case IE_DEV_LOOP: printk("dev loop "); break;
		}
		if (event->dev)
			printk("0x%p,", event->dev);
		else
			printk("0,");
		if (event->cmnd)
			printk("0x%p,", event->cmnd);
		else
			printk("0,");
		printk("%lu\n", event->pg_idx);
	}
	spin_unlock_irqrestore(&target_event_lock, flags);
}

#endif /* TARGET_EVENTS */

#define dprintk(debug, fmt...) ({	\
	if (debug)			\
		printk(fmt);		\
})

static kmem_cache_t *target_cmnd_cache;

struct target_cmnd *target_cmnd_create(void)
{
	struct target_cmnd *cmnd;

	cmnd = kmem_cache_alloc(target_cmnd_cache, GFP_KERNEL);
	dprintk(D_GENERIC, "target_cmnd_create: %p\n", cmnd);
	TE1(E_ALLOC_CMND, NULL, cmnd);
	memset(cmnd, 0, sizeof(*cmnd));

	return cmnd;
}

int target_alloc_pages(struct target_cmnd *cmnd, int count)
{
	int i;

	dprintk(D_GENERIC, "target_alloc_pages: %p %d (%d)\n", cmnd, count, cmnd->pg_cnt);
	TE1(E_ALLOC_PAGES, NULL, cmnd);
	for (i = cmnd->pg_cnt; i < count; i++) {
		while (i >= TARGET_CMND_MAX_PAGES) {
			struct target_cmnd *tmp;

			if (!(tmp = cmnd->next)) {
				tmp = cmnd->next = kmem_cache_alloc(target_cmnd_cache, GFP_KERNEL);
				dprintk(D_GENERIC, "target_cmnd_alloc: %p\n", tmp);
				TE1(E_ALLOC_CMND, NULL, cmnd);
				memset(tmp, 0, sizeof(*tmp));
			}
			cmnd = tmp;
			i = cmnd->pg_cnt;
			count -= TARGET_CMND_MAX_PAGES;
		}
		do {
			cmnd->u.pg.io_pages[i] = alloc_page(GFP_KERNEL);
			TE2(E_ALLOC_PAGE, NULL, cmnd, i);
		} while (!cmnd->u.pg.io_pages[i]);
	}
	cmnd->pg_cnt = i;

	return 0;
}

void target_free_pages(struct target_cmnd *tcmnd)
{
	struct target_cmnd *cmnd;
	int i;

	if (!tcmnd)
		return;
	dprintk(D_GENERIC, "target_free_pages: %p %d\n", tcmnd, tcmnd->pg_cnt);
	TE1(E_FREE_PAGES, NULL, tcmnd);
	do {
		for (i = 0; i < tcmnd->pg_cnt; i++) {
			__free_page(tcmnd->u.pg.io_pages[i]);
			TE2(E_FREE_PAGE, NULL, tcmnd, i);
		}
		cmnd = tcmnd->next;
		dprintk(D_GENERIC, "target_cmnd_free: %p\n", tcmnd);
		TE1(E_FREE_CMND, NULL, tcmnd);
		kmem_cache_free(target_cmnd_cache, tcmnd);
	} while ((tcmnd = cmnd));
}

static inline struct page *__target_alloc_page(struct address_space *mapping)
{
	struct page *page;
	do {
		//page = page_cache_alloc(mapping);
		page = alloc_pages(mapping->gfp_mask & ~__GFP_FS, 0);
		if (!page) {
			TE1(E_ALLOC_PAGE_FAILED, NULL, NULL);
			target_print_events();
		}
	} while (!page);
	page->flags &= ~((1<<PG_locked)|(1<<PG_uptodate)|(1<<PG_async));
	return page;
}

static inline struct page *__target_read_page(struct target_device *dev,
		struct address_space *mapping, unsigned long idx)
{
	struct page *page = __target_alloc_page(mapping);

	page->mapping = mapping;
	page->index = idx;
	if (TryLockPage(page))
		BUG();
	TE2(E_DO_READ_PAGE, dev, NULL, page->index);
	dev->read(dev, page, 0, PAGE_CACHE_SIZE);
	return page;
}


#define target_alloc_page(mapping, page) ({		\
	if (!page)					\
		page = __target_alloc_page(mapping);	\
})

#define target_free_page(page) ({			\
	if (page)					\
		page_cache_release(page);		\
})

static inline void target_copy_page(struct page *dst, struct page *src)
{
	copy_page(kmap(dst), kmap(src));
	kunmap(dst);
	kunmap(src);
}


static struct target_cmnd *target_cmnd_alloc_next(struct target_cmnd *tcmnd, unsigned long pg_idx)
{
	struct target_cmnd *cmnd;

	tcmnd->pg_cnt = TARGET_CMND_MAX_PAGES;
	if (!(cmnd = tcmnd->next)) {
		cmnd = tcmnd->next = kmem_cache_alloc(target_cmnd_cache, GFP_KERNEL);
		dprintk(D_GENERIC, "target_cmnd_alloc: %p\n", cmnd);
		TE1(E_ALLOC_CMND, NULL, cmnd);
		memset(cmnd, 0, sizeof(*cmnd));
		cmnd->u.pg.idx = pg_idx;
	}
	return cmnd;
}

static int target_wait_read_page(struct target_cmnd *tcmnd, struct page *page)
{
	wait_queue_head_t *waitqueue = page_waitqueue(page);
	if (tcmnd->u.pg.wait_page)
		BUG();

	add_wait_queue_exclusive(waitqueue, &tcmnd->u.pg.wq);
	if (PageLocked(page)) {
		tcmnd->u.pg.wait_page = page;
		run_task_queue(&tq_disk);
		dprintk(D_GENERIC, "wait page %lx:%p(%lx)\n", page->index, page, page->flags);
		TE2(E_WAIT_READ_PAGE, NULL, tcmnd, page->index);
		return 1;
	}
	remove_wait_queue(waitqueue, &tcmnd->u.pg.wq);
	return 0;
}

void target_init_read(struct target_device *dev, struct target_cmnd *tcmnd, loff_t offset, u32 size)
{
	init_waitqueue_entry(&tcmnd->u.pg.wq, dev->dev_thread);
	tcmnd->u.pg.idx = offset >> PAGE_CACHE_SHIFT;
	tcmnd->u.pg.offset = offset & ~PAGE_CACHE_MASK;
	tcmnd->u.pg.size = size;
}

int target_get_read_pages(struct target_device *dev, struct target_cmnd *tcmnd)
{
	struct address_space *mapping = dev->mapping;
	struct target_cmnd *cmnd;
	struct page *page;
	struct page *cached_page = NULL;
	unsigned long pg_idx;
	unsigned int pg_offset, pg_end;
	unsigned int pg_cnt, pg_nr;
	int busy = 0;

	cmnd = tcmnd;
	pg_idx = cmnd->u.pg.idx;
	pg_offset = cmnd->u.pg.offset;
	pg_end = cmnd->u.pg.size + pg_offset;
	pg_nr = ((pg_end - 1) >> PAGE_CACHE_SHIFT) + 1;
	pg_cnt = cmnd->pg_cnt;

	dprintk(D_GENERIC, "target_read_pages: %p %d (%d) %lx,%x-%x\n", tcmnd, pg_nr, pg_cnt, pg_idx, pg_offset, pg_end);
	TE1(E_READ_PAGES, dev, cmnd);
	if ((page = tcmnd->u.pg.wait_page)) {
		wait_queue_head_t *waitqueue = page_waitqueue(page);
		remove_wait_queue(waitqueue, &tcmnd->u.pg.wq);
		tcmnd->u.pg.wait_page = NULL;

		pg_cnt = page->index - pg_idx;
		while (pg_cnt >= TARGET_CMND_MAX_PAGES) {
			if (cmnd->pg_cnt > TARGET_CMND_MAX_PAGES)
				printk("target_get_pages: unexpected pg_cnt %u\n", cmnd->pg_cnt);
			pg_cnt -= TARGET_CMND_MAX_PAGES;
			pg_idx += TARGET_CMND_MAX_PAGES;
			pg_end -= TARGET_CMND_MAX_DATA;
			pg_nr -= TARGET_CMND_MAX_PAGES;
			pg_offset = 0;
			cmnd = cmnd->next;
		}

		if (pg_cnt) {
			pg_idx += pg_cnt;
			pg_end -= pg_cnt << PAGE_CACHE_SHIFT;
			pg_offset = 0;
		}
		goto retry;
	}

	do {
		if (pg_cnt >= TARGET_CMND_MAX_PAGES) {
			if (pg_cnt > TARGET_CMND_MAX_PAGES)
				BUG();
			cmnd = target_cmnd_alloc_next(cmnd, pg_idx);
			pg_cnt = 0;
			pg_nr -= TARGET_CMND_MAX_PAGES;
		}

		if (!(page = cmnd->u.pg.io_pages[pg_cnt])) {
			target_alloc_page(mapping, cached_page);
			page = try_grab_cache_page(mapping, pg_idx, &cached_page);
			cmnd->u.pg.io_pages[pg_cnt] = page;
			if (!cached_page) {
				TE2(E_GOT_NEW_PAGE, dev, cmnd, pg_idx);
				goto do_read;
			}
			TE2(E_GOT_OLD_PAGE, dev, cmnd, pg_idx);
		}
	retry:
		if (!Page_Uptodate(page)) {
			if (TryLockPage(page))
				goto lock_failed;
		do_read:
			// previous read error???
			TE2(E_DO_READ_PAGE, dev, cmnd, pg_idx);
			dev->read(dev, page, pg_offset, pg_end);
		}
	back:
		pg_idx++;
		pg_end -= PAGE_CACHE_SIZE;
		pg_offset = 0;
	} while (++pg_cnt < pg_nr);

	cmnd->pg_cnt = pg_cnt;

	target_free_page(cached_page);

	return busy;

 lock_failed:
	busy++;
	if (tcmnd->u.pg.wait_page)
		goto back;
	if (target_wait_read_page(tcmnd, page))
		goto back;
	busy--;
	goto retry;
}

void target_init_write(struct target_device *dev, struct target_cmnd *tcmnd, loff_t offset, u32 size)
{
	init_waitqueue_entry(&tcmnd->u.pg.wq, dev->dev_thread);
	tcmnd->pg_cnt = 2;
	tcmnd->u.pg.idx = (offset >> PAGE_CACHE_SHIFT) - 2;
	tcmnd->u.pg.offset = (offset & ~PAGE_CACHE_MASK) + 2 * PAGE_CACHE_SIZE;
	tcmnd->u.pg.size = size;
}

static int target_write_wait_page(struct target_cmnd *tcmnd, struct page *page)
{
	if (tcmnd->u.pg.wait_page)
		BUG();

	do {
		wait_queue_head_t *waitqueue = page_waitqueue(page);
		add_wait_queue_exclusive(waitqueue, &tcmnd->u.pg.wq);
		if (PageLocked(page)) {
			tcmnd->u.pg.wait_page = page;
			run_task_queue(&tq_disk);
			dprintk(D_GENERIC, "wait page %lx:%p(%lx)\n", page->index, page, page->flags);
			TE2(E_WAIT_WRITE_PAGE, NULL, tcmnd, page->index);
			return 1;
		}
		remove_wait_queue(waitqueue, &tcmnd->u.pg.wq);
	} while (TryLockPage(page));

	return 0;
}

static inline struct page *target_try_get_write_page(struct target_cmnd *tcmnd,
		struct address_space *mapping, unsigned long pg_idx, struct page **cached_page)
{
	struct page *page;

	page = try_grab_cache_page(mapping, pg_idx, cached_page);
	if (!*cached_page || !TryLockPage(page) ||
	    !target_write_wait_page(tcmnd, page))
		return page;
	return NULL;
}


void target_get_async_pages(struct target_device *dev, struct target_cmnd *tcmnd, u32 size)
{
	struct address_space *mapping = dev->mapping;
	struct target_cmnd *cmnd;
	struct page *page = NULL;
	unsigned long pg_idx;
	unsigned int pg_cnt, pg_nr;

	cmnd = tcmnd;
	pg_cnt = cmnd->pg_cnt;
	pg_nr = (cmnd->u.pg.offset + size + PAGE_CACHE_SIZE - 1) >> PAGE_CACHE_SHIFT;
	pg_idx = tcmnd->u.pg.idx;

	while (pg_cnt >= TARGET_CMND_MAX_PAGES) {
		if (pg_nr <= TARGET_CMND_MAX_PAGES)
			return;
		if (!cmnd->next)
			break;
		cmnd = cmnd->next;
		pg_cnt = cmnd->pg_cnt;
		pg_nr -= TARGET_CMND_MAX_PAGES;
		pg_idx += TARGET_CMND_MAX_PAGES;
	}
	pg_idx += pg_cnt;
	
	dprintk(D_GENERIC, "target_get_async_pages: %p,%d (%d) %lx\n", tcmnd, pg_nr, pg_cnt, pg_idx);
	TE2(E_GET_ASYNC_PAGES, dev, tcmnd, size);

	while (pg_cnt < pg_nr) {
		if (pg_cnt >= TARGET_CMND_MAX_PAGES) {
			cmnd = target_cmnd_alloc_next(cmnd, pg_idx);
			pg_cnt = 0;
			pg_nr -= TARGET_CMND_MAX_PAGES;
		}

		page = __target_alloc_page(mapping);
		TE2(E_ALLOC_PAGE, NULL, cmnd, pg_idx);
		set_bit(PG_async, &page->flags);
		page->index = pg_idx++;
		cmnd->u.pg.io_pages[pg_cnt++] = page;
	}
	cmnd->pg_cnt = pg_cnt;
}

int target_get_write_pages(struct target_device *dev, struct target_cmnd *tcmnd)
{
	struct address_space *mapping = dev->mapping;
	struct target_cmnd *cmnd;
	struct page *page, *tmp_page;
	struct page *cached_page = NULL;
	unsigned long pg_idx;
	unsigned int pg_cnt, pg_nr;
	int busy = 1;

	cmnd = tcmnd;
	pg_cnt = 2;

	if ((page = tcmnd->u.pg.wait_page)) {
		wait_queue_head_t *waitqueue = page_waitqueue(page);
		remove_wait_queue(waitqueue, &tcmnd->u.pg.wq);
		pg_cnt = page->index - cmnd->u.pg.idx;
		page_cache_release(page);
		tcmnd->u.pg.wait_page = NULL;
	}

	pg_idx = tcmnd->u.pg.idx + pg_cnt;
	pg_nr = (tcmnd->u.pg.offset + tcmnd->u.pg.size) >> PAGE_CACHE_SHIFT;
	dprintk(D_GENERIC, "target_get_write_pages: %p,%d (%d) %lx,%x-%x\n", tcmnd, pg_nr, pg_cnt, pg_idx, cmnd->u.pg.offset, cmnd->u.pg.size);
	TE2(E_GET_WRITE_PAGES, dev, cmnd, pg_nr);

	if (pg_cnt == 2 && tcmnd->u.pg.offset & ~PAGE_CACHE_MASK) {
		tmp_page = cmnd->u.pg.io_pages[2];
		if (!tmp_page) {
			target_alloc_page(mapping, cached_page);
			page = try_grab_cache_page(mapping, pg_idx, &cached_page);
			if (!Page_Uptodate(page)) {
				if (cached_page) {
					tcmnd->u.pg.io_pages[0] = page;
					page = cached_page;
					cached_page = NULL;
					TE2(E_GOT_NUP2DATE_PAGE, dev, cmnd, pg_idx);
				} else {
					tcmnd->u.pg.io_pages[0] = __target_read_page(dev, mapping, pg_idx);
					TE2(E_GOT_LOCKED_PAGE, dev, cmnd, pg_idx);
				}
				if (test_bit(PG_async, &page->flags))
					BUG();
				set_bit(PG_async, &page->flags);
			} else
				TE2(E_GOT_UP2DATE_PAGE, dev, cmnd, pg_idx);
			cmnd->u.pg.io_pages[2] = page;
		} else if (!tcmnd->u.pg.io_pages[0]) {
			page = try_grab_cache_page(mapping, pg_idx, &tmp_page);
			if (!tmp_page) {
				tcmnd->u.pg.io_pages[0] = __target_read_page(dev, mapping, pg_idx);
				TE2(E_INSERTED_ASYNC_PAGE, dev, cmnd, pg_idx);
			} else {
				tcmnd->u.pg.io_pages[0] = page;
				TE2(E_GOT_OTHER_PAGE, dev, cmnd, pg_idx);
			}
		}

		pg_cnt++;
		if (pg_cnt > pg_nr) {
			busy = 0;
			goto out;
		}
		pg_idx++;
	}
	while (pg_cnt >= TARGET_CMND_MAX_PAGES) {
		pg_cnt -= TARGET_CMND_MAX_PAGES;
		pg_nr -= TARGET_CMND_MAX_PAGES;
		cmnd = cmnd->next;
	}


	while (pg_cnt < pg_nr) {
		if (pg_cnt >= TARGET_CMND_MAX_PAGES) {
			cmnd = target_cmnd_alloc_next(cmnd, pg_idx);
			pg_cnt = 0;
			pg_nr -= TARGET_CMND_MAX_PAGES;
		}

		page = cmnd->u.pg.io_pages[pg_cnt];
		if (!page) {
			target_alloc_page(mapping, cached_page);
			page = try_grab_cache_page(mapping, pg_idx, &cached_page);
			if (!Page_Uptodate(page)) {
				if (cached_page) {
					page_cache_release(page);
					page = cached_page;
					cached_page = NULL;
					TE2(E_GOT_NUP2DATE_PAGE, dev, cmnd, pg_idx);
				} else
					TE2(E_GOT_LOCKED_PAGE, dev, cmnd, pg_idx);
				if (test_bit(PG_async, &page->flags))
					BUG();
				set_bit(PG_async, &page->flags);
			} else
				TE2(E_GOT_UP2DATE_PAGE, dev, cmnd, pg_idx);
			cmnd->u.pg.io_pages[pg_cnt] = page;
		} else
			TE2(E_GOT_OTHER_PAGE, dev, cmnd, pg_idx);
		pg_cnt++;
		pg_idx++;
	}

	if ((tcmnd->u.pg.offset + tcmnd->u.pg.size) & ~PAGE_CACHE_MASK) {
		if (pg_cnt >= TARGET_CMND_MAX_PAGES) {
			cmnd = target_cmnd_alloc_next(cmnd, pg_idx);
			pg_cnt = 0;
		}

		tmp_page = cmnd->u.pg.io_pages[pg_cnt];
		if (!tmp_page) {
			target_alloc_page(mapping, cached_page);
			page = try_grab_cache_page(mapping, pg_idx, &cached_page);
			if (!Page_Uptodate(page)) {
				if (cached_page) {
					tcmnd->u.pg.io_pages[1] = page;
					page = cached_page;
					cached_page = NULL;
					TE2(E_GOT_NUP2DATE_PAGE, dev, cmnd, pg_idx);
				} else {
					tcmnd->u.pg.io_pages[1] = __target_read_page(dev, mapping, pg_idx);
					TE2(E_GOT_LOCKED_PAGE, dev, cmnd, pg_idx);
				}
				if (test_bit(PG_async, &page->flags))
					BUG();
				set_bit(PG_async, &page->flags);
			} else
				TE2(E_GOT_UP2DATE_PAGE, dev, cmnd, pg_idx);
			cmnd->u.pg.io_pages[pg_cnt] = page;
		} else if (!tcmnd->u.pg.io_pages[1]) {
			page = try_grab_cache_page(mapping, pg_idx, &tmp_page);
			if (!tmp_page) {
				tcmnd->u.pg.io_pages[1] = __target_read_page(dev, mapping, pg_idx);
				TE2(E_INSERTED_ASYNC_PAGE, dev, cmnd, pg_idx);
			} else {
				tcmnd->u.pg.io_pages[1] = page;
				TE2(E_GOT_OTHER_PAGE, dev, cmnd, pg_idx);
			}
		}
		pg_cnt++;
	}
	busy = 0;
 out:
	cmnd->pg_cnt = pg_cnt;

	target_free_page(cached_page);

	return busy;
}

static struct page *target_copy_async_page(struct target_cmnd *tcmnd,
					   struct page *read_page, struct page *write_page,
					   unsigned int offset, unsigned int end)
{
	char *read_data, *write_data;

	if (!test_bit(PG_async, &write_page->flags)) {
		TE2(E_GOT_UP2DATE_PAGE, NULL, tcmnd, write_page->index);
		if (read_page)
			BUG();
		return TryLockPage(write_page) && target_write_wait_page(tcmnd, write_page) ? NULL : write_page;
	}
	if (!Page_Uptodate(read_page) && target_wait_read_page(tcmnd, read_page))
		return NULL;

	if (PageLocked(write_page)) {
		TE2(E_COPY_READ_PAGE, NULL, tcmnd, write_page->index);
		read_data = kmap(read_page);
		write_data = kmap(write_page);
		if (offset)
			memcpy(write_data, read_data, offset);
		if (end < PAGE_CACHE_SIZE)
			memcpy(write_data + end, read_data + end, PAGE_CACHE_SIZE - end);
		kunmap(read_page);
		kunmap(write_page);

		read_page->mapping = NULL;
		page_cache_release(read_page);
		clear_bit(PG_async, &write_page->flags);
		SetPageUptodate(write_page);
		return write_page;
	} else {
		if (TryLockPage(read_page) && target_write_wait_page(tcmnd, read_page))
			return NULL;
		TE2(E_COPY_WRITE_PAGE, NULL, tcmnd, write_page->index);
		read_data = kmap(read_page);
		write_data = kmap(write_page);
		if (end > PAGE_CACHE_SIZE)
			end = PAGE_CACHE_SIZE;
		memcpy(read_data + offset, write_data + offset, end - offset);
		kunmap(read_page);
		kunmap(write_page);

		clear_bit(PG_async, &write_page->flags);
		page_cache_release(write_page);
		return read_page;
	}
}

void target_clear_pages(struct target_cmnd *tcmnd, int offset, int size)
{
	struct page *page;
	int len, pg_idx;

	dprintk(D_GENERIC, "target_clear: %p,%x:%x\n", tcmnd, offset, size);
	TE1(E_CLEAR_PAGES, NULL, tcmnd);
	offset += tcmnd->u.pg.offset;
	for (; offset >= TARGET_CMND_MAX_DATA; offset -= TARGET_CMND_MAX_DATA)
		tcmnd = tcmnd->next;

	pg_idx = offset >> PAGE_CACHE_SHIFT;
	offset &= ~PAGE_CACHE_MASK;

	len = min(size, (int)PAGE_CACHE_SIZE - offset);
	page = tcmnd->u.pg.io_pages[pg_idx];
	memset(kmap(page) + offset, 0, len);
	SetPageDirty(page);
	kunmap(page);

	while ((size -= len)) {
		if (++pg_idx >= TARGET_CMND_MAX_PAGES) {
			tcmnd = tcmnd->next;
			pg_idx = 0;
		}
		len = min(size, (int)PAGE_CACHE_SIZE);
		page = tcmnd->u.pg.io_pages[pg_idx];
		TE2(E_CLEAR_PAGE, NULL, tcmnd, pg_idx);
		memset(kmap(page), 0, len);
		SetPageDirty(page);
		kunmap(page);
	}
}

int target_commit_pages(struct target_device *dev, struct target_cmnd *tcmnd)
{
	struct address_space *mapping = dev->mapping;
	struct target_cmnd *cmnd;
	struct page *page, *tmp_page;
	unsigned long pg_idx;
	unsigned int pg_offset, pg_end;
	unsigned int pg_nr;
	int pg_cnt;

	cmnd = tcmnd;
	pg_nr = cmnd->pg_cnt;
	pg_cnt = 2;

	if ((page = tcmnd->u.pg.wait_page)) {
		wait_queue_head_t *waitqueue = page_waitqueue(page);
		if (PageLocked(page)) {
			run_task_queue(&tq_disk);
			return 1;
		}
		remove_wait_queue(waitqueue, &tcmnd->u.pg.wq);
		pg_cnt = page->index - tcmnd->u.pg.idx;
		tcmnd->u.pg.wait_page = NULL;
	}

	pg_idx = tcmnd->u.pg.idx + pg_cnt;
	pg_offset = cmnd->u.pg.offset;
	pg_end = pg_offset + cmnd->u.pg.size - (pg_cnt << PAGE_CACHE_SHIFT);
	dprintk(D_GENERIC, "target_commit_pages: %p %d %lx,%x-%x\n", tcmnd, tcmnd->pg_cnt, pg_idx, pg_offset, pg_end);
	TE1(E_COMMIT_PAGES, dev, tcmnd);

	if (pg_cnt == 2 && (pg_offset &= ~PAGE_CACHE_MASK)) {
		page = target_copy_async_page(tcmnd, tcmnd->u.pg.io_pages[0], cmnd->u.pg.io_pages[2], pg_offset, pg_end);
		if (!page)
			return 1;
		tcmnd->u.pg.io_pages[0] = NULL;
		cmnd->u.pg.io_pages[2] = page;
		TE2(E_DO_WRITE_PAGE, dev, cmnd, page->index);
		dev->write(dev, page, pg_offset, pg_end);
		pg_idx++;
		pg_cnt++;
		if (pg_end <= PAGE_CACHE_SIZE)
			return 0;
		pg_end -= PAGE_CACHE_SIZE;
	}
	while (pg_cnt >= TARGET_CMND_MAX_PAGES) {
		pg_cnt -= TARGET_CMND_MAX_PAGES;
		pg_nr = cmnd->pg_cnt;
		cmnd = cmnd->next;
	}

	while (pg_end >= PAGE_CACHE_SIZE) {
		if (pg_cnt >= pg_nr) {
			cmnd = cmnd->next;
			pg_nr = cmnd->pg_cnt;
			pg_cnt = 0;
		}

		page = cmnd->u.pg.io_pages[pg_cnt];
		if (test_bit(PG_async, &page->flags)) {
			if (!PageLocked(page)) {
				tmp_page = page;
				page = target_try_get_write_page(tcmnd, mapping, page->index, &tmp_page);
				if (!page)
					return 1;
				if (tmp_page) {
					target_copy_page(page, tmp_page);
					clear_bit(PG_async, &tmp_page->flags);
					page_cache_release(tmp_page);
					cmnd->u.pg.io_pages[pg_cnt] = page;
					TE2(E_COPY_ASYNC_PAGE, dev, cmnd, page->index);
				} else {
					clear_bit(PG_async, &page->flags);
					TE2(E_INSERTED_ASYNC_PAGE, dev, cmnd, page->index);
				}
			} else {
				clear_bit(PG_async, &page->flags);
				TE2(E_GOT_ASYNC_PAGE, dev, cmnd, page->index);
			}
		} else {
			if (TryLockPage(page) && target_write_wait_page(tcmnd, page))
				return 1;
			TE2(E_GOT_LOCKED_PAGE, dev, cmnd, page->index);
		}
		SetPageUptodate(page); 
		TE2(E_DO_WRITE_PAGE, dev, cmnd, page->index);
		dev->write(dev, page, 0, pg_end);

		pg_cnt++;
		pg_idx++;
		pg_end -= PAGE_CACHE_SIZE;
	}

	if (pg_end) {
		if (pg_cnt >= pg_nr) {
			cmnd = cmnd->next;
			pg_nr = cmnd->pg_cnt;
			pg_cnt = 0;
		}

		page = target_copy_async_page(tcmnd, tcmnd->u.pg.io_pages[1], cmnd->u.pg.io_pages[pg_cnt], 0, pg_end);
		if (!page)
			return 1;
		tcmnd->u.pg.io_pages[1] = NULL;
		cmnd->u.pg.io_pages[pg_cnt] = page;
		TE2(E_DO_WRITE_PAGE, dev, cmnd, page->index);
		dev->write(dev, page, 0, pg_end);
	}

	return 0;
}

int target_wait_pages(struct target_device *dev, struct target_cmnd *tcmnd)
{
	struct target_cmnd *cmnd;
	struct page *page;
	unsigned int pg_cnt, pg_nr;

	dprintk(D_GENERIC, "target_wait_pages: %p\n", tcmnd);
	TE1(E_WAIT_PAGES, dev, tcmnd);
	if ((page = tcmnd->u.pg.wait_page)) {
		wait_queue_head_t *waitqueue = page_waitqueue(page);
		if (!Page_Uptodate(page)) {
			run_task_queue(&tq_disk);
			return 1;
		}
		dprintk(D_GENERIC, "got page %lx\n", page->index);
		TE2(E_GOT_PAGE, dev, tcmnd, page->index);
		remove_wait_queue(waitqueue, &tcmnd->u.pg.wq);
		tcmnd->u.pg.wait_page = NULL;
		pg_cnt = page->index - tcmnd->u.pg.idx;
		for (cmnd = tcmnd; pg_cnt >= (pg_nr = cmnd->pg_cnt); pg_cnt -= pg_nr)
			cmnd = cmnd->next;
		goto do_sync;
	}

	cmnd = tcmnd;
	do {
		pg_cnt = 0;
		pg_nr = cmnd->pg_cnt;
	do_sync:
		do {
			page = cmnd->u.pg.io_pages[pg_cnt];
			if (!page)
				continue;
			if (!Page_Uptodate(page)) {
				wait_queue_head_t *waitqueue = page_waitqueue(page);
				add_wait_queue(waitqueue, &tcmnd->u.pg.wq);
				if (!Page_Uptodate(page)) {
					dprintk(D_GENERIC, "wait page %d %lx:%p(%lx)\n", pg_cnt, page->index, page, page->flags);
					TE2(E_WAIT_PAGE, dev, cmnd, page->index);
					tcmnd->u.pg.wait_page = page;
					run_task_queue(&tq_disk);
					return 1;
				}
				remove_wait_queue(waitqueue, &tcmnd->u.pg.wq);
			}
			if (PageError(page)) {
				printk("page %ld had write errors...\n", page->index);
				clear_bit(PG_error, &page->flags);
			}
		} while (++pg_cnt < pg_nr);
	} while ((cmnd = cmnd->next));

	return 0;
}

int target_sync_pages(struct target_device *dev, struct target_cmnd *tcmnd)
{
	struct target_cmnd *cmnd;
	struct page *page;
	unsigned int pg_cnt, pg_nr;

	dprintk(D_GENERIC, "target_sync_pages: %p\n", tcmnd);
	TE1(E_SYNC_PAGES, dev, tcmnd);
	if ((page = tcmnd->u.pg.wait_page)) {
		wait_queue_head_t *waitqueue = page_waitqueue(page);
		if (PageLaunder(page)) {
			run_task_queue(&tq_disk);
			return 1;
		}
		dprintk(D_GENERIC, "got page %lx\n", page->index);
		TE2(E_GOT_PAGE, dev, tcmnd, page->index);
		remove_wait_queue(waitqueue, &tcmnd->u.pg.wq);
		tcmnd->u.pg.wait_page = NULL;
		pg_cnt = page->index - tcmnd->u.pg.idx;
		for (cmnd = tcmnd; pg_cnt >= (pg_nr = cmnd->pg_cnt); pg_cnt -= pg_nr)
			cmnd = cmnd->next;
		goto do_sync;
	}

	cmnd = tcmnd;
	do {
		pg_cnt = 0;
		pg_nr = cmnd->pg_cnt;
	do_sync:
		do {
			page = cmnd->u.pg.io_pages[pg_cnt];
			if (!page)
				continue;
			if (PageLaunder(page)) {
				wait_queue_head_t *waitqueue = page_waitqueue(page);
				add_wait_queue(waitqueue, &tcmnd->u.pg.wq);
				if (PageLaunder(page)) {
					dprintk(D_GENERIC, "wait page %d %lx:%p(%lx)\n", pg_cnt, page->index, page, page->flags);
					TE2(E_WAIT_PAGE, dev, cmnd, page->index);
					tcmnd->u.pg.wait_page = page;
					run_task_queue(&tq_disk);
					return 1;
				}
				remove_wait_queue(waitqueue, &tcmnd->u.pg.wq);
			}
			UnlockPage(page);
			if (PageError(page)) {
				printk("page %ld had write errors...\n", page->index);
				clear_bit(PG_error, &page->flags);
			}
		} while (++pg_cnt < pg_nr);
	} while ((cmnd = cmnd->next));

	return 0;
}

void target_put_pages(struct target_cmnd *tcmnd)
{
	struct target_cmnd *cmnd;
	struct page *page;
	int pg_cnt;

	dprintk(D_GENERIC, "target_put_pages: %p %d\n", tcmnd, tcmnd->pg_cnt);
	TE1(E_PUT_PAGES, NULL, tcmnd);
	do {
		for (pg_cnt = 0; pg_cnt < tcmnd->pg_cnt; pg_cnt++) {
			page = tcmnd->u.pg.io_pages[pg_cnt];
			if (!page)
				continue;
			TE2(E_PUT_PAGE, NULL, tcmnd, page->index);
			page_cache_release(page);
		}
		cmnd = tcmnd->next;
		dprintk(D_GENERIC, "target_cmnd_free: %p\n", tcmnd);
		TE1(E_FREE_CMND, NULL, tcmnd);
		kmem_cache_free(target_cmnd_cache, tcmnd);
	} while ((tcmnd = cmnd));
}

int target_init(void)
{
	target_cmnd_cache = kmem_cache_create("target_cmnd", sizeof(struct target_cmnd), 0, 0, NULL, NULL);
	return 0;
}

void target_exit(void)
{
	kmem_cache_destroy(target_cmnd_cache);
}
