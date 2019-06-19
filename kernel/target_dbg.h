#ifndef TARGET_DBG_H
#define TARGET_DBG_H

#define TARGET_EVENTS	0

enum target_event_type {
	E_ALLOC_PAGES,
	E_ALLOC_CMND,
	E_ALLOC_PAGE,
	E_ALLOC_PAGE_FAILED,
	E_FREE_PAGES,
	E_FREE_PAGE,
	E_FREE_CMND,
	E_WAIT_READ_PAGE,
	E_READ_PAGES,
	E_GOT_NEW_PAGE,
	E_GOT_OLD_PAGE,
	E_DO_READ_PAGE,
	E_WAIT_WRITE_PAGE,
	E_GET_ASYNC_PAGES,
	E_GET_WRITE_PAGES,
	E_GOT_NUP2DATE_PAGE,
	E_GOT_LOCKED_PAGE,
	E_GOT_UP2DATE_PAGE,
	E_INSERTED_ASYNC_PAGE,
	E_GOT_OTHER_PAGE,
	E_COPY_READ_PAGE,
	E_COPY_WRITE_PAGE,
	E_CLEAR_PAGES,
	E_CLEAR_PAGE,
	E_COMMIT_PAGES,
	E_COPY_ASYNC_PAGE,
	E_GOT_ASYNC_PAGE,
	E_DO_WRITE_PAGE,
	E_WAIT_PAGES,
	E_SYNC_PAGES,
	E_GOT_PAGE,
	E_WAIT_PAGE,
	E_PUT_PAGES,
	E_PUT_PAGE,

	E_BDEV_READ,
	E_BDEV_WRITE,
	E_BDEV_END_READ,
	E_BDEV_END_WRITE,

	IE_CMND_CREATE,
	IE_CMND_REMOVE,
	IE_CMND_START_READ,
	IE_CMND_SCSI,
	IE_CMND_FINISH_READ,
	IE_CMND_EXECUTE,
	IE_CMND_INIT_WRITE,
	IE_CMND_START_WRITE,
	IE_CMND_FINISH_WRITE,
	IE_CMND_RELEASE,
	IE_CMND_PREPARE_SEND,
	IE_CMND_SEND_PDU,
	IE_CMND_RECEIVE_PDU,
	IE_CMND_UNMAP_PDU,
	IE_SCSI_QUEUE,
	IE_SCSI_EXECUTE,
	IE_SESSION_INSERT,
	IE_SESSION_REMOVE,
	IE_SESSION_INSERT_TTT,
	IE_SESSION_REMOVE_TTT,
	IE_SESSION_PUSH,
	IE_SESSION_CHECK_CMDSN,
	IE_SESSION_UPDATE_STATSN,
	IE_DEV_LOOP,
};

struct target_event {
	int time;
	enum target_event_type type;
	void *dev;
	void *cmnd;
	unsigned long pg_idx;
};

#define EVENT_COUNT (1<<14)
#define EVENT_MASK (EVENT_COUNT-1)

extern struct target_event target_event_buffer[EVENT_COUNT];
extern unsigned long target_event_cnt;
extern spinlock_t target_event_lock;

static inline void target_add_event(enum target_event_type type,
		struct target_device *dev,
		struct target_cmnd *cmnd, unsigned long idx)
{
	struct target_event *event;
	unsigned long flags;

	spin_lock_irqsave(&target_event_lock, flags);
	event = target_event_buffer + (target_event_cnt & EVENT_MASK);
	event->time = jiffies;
	event->type = type;
	event->dev = dev;
	event->cmnd = cmnd;
	event->pg_idx = idx;
	target_event_cnt++;
	spin_unlock_irqrestore(&target_event_lock, flags);
}

static inline void iscsi_add_event(enum target_event_type type,
		void *ptr1, void *ptr2, unsigned long val)
{
	struct target_event *event;
	unsigned long flags;

	spin_lock_irqsave(&target_event_lock, flags);
	event = target_event_buffer + (target_event_cnt & EVENT_MASK);
	event->time = jiffies;
	event->type = type;
	event->dev = ptr1;
	event->cmnd = ptr2;
	event->pg_idx = val;
	target_event_cnt++;
	spin_unlock_irqrestore(&target_event_lock, flags);
}

#if TARGET_EVENTS

#define TE1(type, dev, cmnd) target_add_event(type, dev, cmnd, 0)
#define TE2(type, dev, cmnd, idx) target_add_event(type, dev, cmnd, idx)

#define IE1(type, ptr1)		iscsi_add_event(type, NULL, ptr1, 0)
#define IE2(type, ptr1, ptr2)	iscsi_add_event(type, ptr1, ptr2, 0)
#define IE3(type, ptr1, val)	iscsi_add_event(type, NULL, ptr1, val)

extern void target_print_events(void);

#else

#define TE1(type, dev, cmnd)
#define TE2(type, dev, cmnd, idx)

#define IE1(type, ptr1)
#define IE2(type, ptr1, ptr2)
#define IE3(type, ptr1, val)

#define target_print_events()

#endif

#endif
