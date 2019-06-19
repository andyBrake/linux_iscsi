/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/blkdev.h>
#include <linux/init.h>

#include "target.h"
#include "target_dbg.h"
#include "target_device.h"

#define D_GENERIC 0

#define dprintk(debug, fmt...) ({	\
	if (debug)			\
		printk(fmt);		\
})

#define get_bdev(d)	list_entry(d, struct target_bdev, tdev)

struct target_bdev {
	struct target_device tdev;
	kdev_t dev;
};

static void target_bdev_end_read(struct buffer_head *bh, int uptodate)
{
	struct page *page = bh->b_page;

	dprintk(D_GENERIC, "read(%ld,%lx)\n", bh->b_rsector, page->index);
	TE2(E_BDEV_END_READ, NULL, NULL, page->index);
	if (!uptodate)
		set_bit(PG_error, &page->flags);
	SetPageUptodate(page);
	kmem_cache_free(bh_cachep, bh);
	UnlockPage(page);
	page_cache_release(page);
}

static void target_bdev_end_write(struct buffer_head *bh, int uptodate)
{
	struct page *page = bh->b_page;
	wait_queue_head_t *wq = page_waitqueue(page);

	dprintk(D_GENERIC, "write(%ld,%lx,%lx)\n", bh->b_rsector, page->index, page->flags);
	TE2(E_BDEV_END_WRITE, NULL, NULL, page->index);
	if (!uptodate)
		set_bit(PG_error, &page->flags);
	kmem_cache_free(bh_cachep, bh);
	ClearPageLaunder(page);
	if (waitqueue_active(wq))
		wake_up_all(wq);
	page_cache_release(page);
}

static void target_bdev_read(struct target_device *tdev, struct page *page,
			     unsigned int start, unsigned int end)
{
	struct target_bdev *dev = get_bdev(tdev);
	struct buffer_head *bh;

	dprintk(D_GENERIC, "target_bdev_read: %lx(%c),%x-%x\n", page->index,
		Page_Uptodate(page)?'y':'n', start, end);
	if (Page_Uptodate(page)) {
		printk("target_bdev_read?\n");
		return;
	}
	TE2(E_BDEV_READ, NULL, NULL, page->index);

	page_cache_get(page);
	bh = kmem_cache_alloc(bh_cachep, SLAB_KERNEL);
	//if (!bh) panic?
	atomic_set(&bh->b_count, 1);
	set_bit(BH_Lock, &bh->b_state);
	set_bit(BH_Mapped, &bh->b_state);
	set_bh_page(bh, page, 0);
	bh->b_size = PAGE_CACHE_SIZE;
	bh->b_rdev = bh->b_dev = dev->dev;
	bh->b_rsector = page->index * (PAGE_CACHE_SIZE/512);
	bh->b_end_io = target_bdev_end_read;

	if (((page->index + 1) << dev->tdev.idx_shift) > dev->tdev.blk_cnt) {
		if ((page->index << dev->tdev.idx_shift) >= dev->tdev.blk_cnt) {
			printk("access beyond end of device! (%ld,%d)\n",
			       page->index << dev->tdev.idx_shift, dev->tdev.blk_cnt);
			target_bdev_end_read(bh, 0);
			return;
		}
		bh->b_size = (dev->tdev.blk_cnt << dev->tdev.blk_shift) & ~PAGE_CACHE_MASK;
	}
	//generic_make_request(cmnd ? READ : READA, bh);
	generic_make_request(READ, bh);
}

static void target_bdev_write(struct target_device *tdev, struct page *page,
			      unsigned int start, unsigned int end)
{
	struct target_bdev *dev = get_bdev(tdev);
	struct buffer_head *bh;

	dprintk(D_GENERIC, "target_bdev_write: %lx(%c),%x-%x\n", page->index,
		Page_Uptodate(page)?'y':'n', start, end);
	TE2(E_BDEV_WRITE, NULL, NULL, page->index);

	SetPageUptodate(page);
	ClearPageDirty(page);
	SetPageLaunder(page);

	page_cache_get(page);
	bh = kmem_cache_alloc(bh_cachep, SLAB_KERNEL);
	//if (!bh) panic?
	atomic_set(&bh->b_count, 1);
	set_bit(BH_Lock, &bh->b_state);
	set_bit(BH_Mapped, &bh->b_state);
	set_bh_page(bh, page, 0);
	bh->b_size = PAGE_CACHE_SIZE;
	bh->b_rdev = bh->b_dev = dev->dev;
	bh->b_rsector = page->index * (PAGE_CACHE_SIZE/512);
	bh->b_end_io = target_bdev_end_write;

	if (((page->index + 1) << dev->tdev.idx_shift) > dev->tdev.blk_cnt) {
		if ((page->index << dev->tdev.idx_shift) >= dev->tdev.blk_cnt) {
			printk("access beyond end of device! (%ld,%d)\n",
			       page->index << dev->tdev.idx_shift, dev->tdev.blk_cnt);
			target_bdev_end_write(bh, 0);
			return;
		}
		bh->b_size = (dev->tdev.blk_cnt << dev->tdev.blk_shift) & ~PAGE_CACHE_MASK;
	}
	generic_make_request(WRITE, bh);
}

struct target_device *target_bdev_attach(struct file *file)
{
	struct target_bdev *dev;

	dev = kmalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		goto fail2;

	memset(dev, 0, sizeof(*dev));
	dev->dev = file->f_dentry->d_inode->i_rdev;

	dev->tdev.file = file;
	dev->tdev.mapping = file->f_dentry->d_inode->i_mapping;
	
	dev->tdev.read		= target_bdev_read;
	dev->tdev.write		= target_bdev_write;

	dev->tdev.blk_shift = 9;
	dev->tdev.idx_shift = PAGE_CACHE_SHIFT - dev->tdev.blk_shift;
	if (!blk_size[MAJOR(dev->dev)])
		goto fail1;
	dev->tdev.blk_cnt = blk_size[MAJOR(dev->dev)][MINOR(dev->dev)];
	if (dev->tdev.blk_shift < 10)
		dev->tdev.blk_cnt <<= 10 - dev->tdev.blk_shift;
	else
		dev->tdev.blk_cnt >>= dev->tdev.blk_shift - 10;

	return &dev->tdev;

 fail1:
	kfree(dev);
 fail2:
	return NULL;
}

void target_bdev_detach(struct target_device *device)
{
	struct target_bdev *dev = get_bdev(device);

#if 0
	//sync && blkdev_close()!
	head = &dev->tdev.inode->i_mapping->clean_pages;
	for (curr = head->next; curr != head;) {
		page = list_entry(curr, struct page, list);
		curr = curr->next;
		while (PageLocked(page))
			wait_on_page(page);
		atomic_dec(&page->count);
		ClearPageDirty(page);
		remove_inode_page(page);
		page_cache_release(page);
	}
#endif

	kfree(dev);
}

int __init target_bdev_init(void)
{
	return 0;
}
