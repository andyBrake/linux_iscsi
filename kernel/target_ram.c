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
#include "target_device.h"

#define xprintk		printk

#define get_bdev(d)	list_entry(d, struct target_ram, tdev)

struct target_ram {
	struct target_device tdev;
	struct inode *inode;
	kdev_t dev;
};

static void target_ram_read(struct target_device *tdev, struct page *page,
			     unsigned int start, unsigned int end)
{
	xprintk("target_ram_read: %lx(%c),%x-%x\n", page->index,
		Page_Uptodate(page)?'y':'n', start, end);
	if (Page_Uptodate(page)) {
		printk("target_ram_read?\n");
		return;
	}

	if (!PageReserved(page)) {
		SetPageReserved(page);
		atomic_inc(&page->count);
		clear_page(page_address(page));
	}
	SetPageUptodate(page);
	UnlockPage(page);
}

static void target_ram_write(struct target_device *tdev, struct page *page,
			      unsigned int start, unsigned int end)
{
	xprintk("target_ram_write: %lx(%c),%x-%x\n", page->index,
		Page_Uptodate(page)?'y':'n', start, end);

	SetPageUptodate(page);

	if (!PageReserved(page)) {
		SetPageReserved(page);
		atomic_inc(&page->count);
	}
	UnlockPage(page);
}

struct target_device *target_ram_attach(struct file *file)
{
	struct target_ram *dev;

	dev = kmalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		goto fail2;

	memset(dev, 0, sizeof(*dev));
	dev->inode = get_empty_inode();

	dev->tdev.mapping = dev->inode->i_mapping;
	
	dev->tdev.read		= target_ram_read;
	dev->tdev.write		= target_ram_write;

	dev->tdev.blk_shift = 9;
	dev->tdev.idx_shift = PAGE_CACHE_SHIFT - dev->tdev.blk_shift;
	dev->tdev.blk_cnt = 16384;

	return &dev->tdev;

 fail1:
	kfree(dev);
 fail2:
	return NULL;
}

void target_ram_detach(struct target_device *device)
{
	struct target_ram *dev = get_bdev(device);

	if (dev->inode) {
		

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

int __init target_ram_init(void)
{
	return 0;
}
