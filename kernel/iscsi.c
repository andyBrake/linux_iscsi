/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/init.h>
#include <linux/compiler.h>
#ifdef CONFIG_TRACE
#include <linux/trace.h>
#else
#define trace_std_formatted_event(event, ...)
#define trace_create_event(name, ...) 0
#define trace_destroy_event(event)
#endif

#include <asm/uaccess.h>

#include <net/sock.h>
#include <net/tcp.h>
#include <scsi/scsi.h>

#include "iscsi.h"
#include "target.h"
#include "target_dbg.h"
#include "target_device.h"

#define D_GENERIC	0
#define D_THREAD	0
#define D_DUMP_PDU	0
#define D_TASK_MGT	1
#define D_SETUP		0

#define dprintk(debug, fmt...) ({	\
	if (debug)			\
		printk(fmt);		\
})

#define STATUS_SHIFT		1

#ifndef REPORT_LUNS
#define REPORT_LUNS		0xa0
#endif

static int iscsi_target_read_thread(void *arg);
static int iscsi_target_write_thread(void *arg);
static int iscsi_device_thread(void *arg);
static void iscsi_session_defaults(struct iscsi_param *param);
static inline void iscsi_conn_init_read(struct iscsi_conn *conn, void *data, size_t len);
static inline struct iscsi_cmnd *iscsi_cmnd_get_req_cmnd(struct iscsi_cmnd *rsp_cmnd);
static inline struct iscsi_cmnd *iscsi_cmnd_get_rsp_cmnd(struct iscsi_cmnd *req_cmnd);
static inline void iscsi_cmnd_get_length(struct iscsi_pdu *pdu);
static inline void iscsi_cmnd_set_length(struct iscsi_pdu *pdu);
static inline int iscsi_session_pushstate(struct iscsi_cmnd *cmnd);
static inline int iscsi_session_check_cmd_sn(struct iscsi_cmnd *cmnd);
static inline void iscsi_conn_closefd_nolock(struct iscsi_conn *conn);


struct semaphore iscsi_sem;
static struct list_head target_list;
static struct list_head target_device_list;
static kmem_cache_t *iscsi_cmnd_cache;
static wait_queue_head_t iscsi_wq;
static char dummy_data[1024];

static int trace_read_cmnd, trace_execute_cmnd, trace_write_cmnd, trace_execute_scsi;
static long iscsi_jiffies;

/*****************************************************************************/
/*                                   TARGET                                  */
/*****************************************************************************/

/**
 * Create a new iscsi target.
 * Caller must hold iscsi_sem.
 *
 * iscsi_target_create - 
 * @id: id of target
 * @name: default iscsi name
 *
 * @return    -errno
 */

int iscsi_target_create(u32 id, const char *name)
{
	struct iscsi_target *target;
	int err, tid;

	dprintk(D_SETUP, "iscsi_target_create: %u %s\n", id, name);
	target = kmalloc(sizeof(*target), GFP_KERNEL);
	if (!target)
		return -ENOMEM;
	memset(target, 0, sizeof(*target));

	target->target.id = id;
	iscsi_session_defaults(&target->default_param);

	target->name = kmalloc(strlen(name) + 1, GFP_KERNEL);
	strcpy(target->name, name);

	INIT_LIST_HEAD(&target->session_list);
	INIT_LIST_HEAD(&target->lun_list);
	INIT_LIST_HEAD(&target->poll.list);

	init_rwsem(&target->poll.sem);
	poll_initwait(&target->poll.read_poll);
	poll_initwait(&target->poll.write_poll);
	init_waitqueue_head(&target->poll.wq);

	list_add(&target->target.list, &target_list);

	tid = kernel_thread(iscsi_target_read_thread, target, CLONE_FS | CLONE_FILES);
	if (tid < 0) {
		err = tid;
		goto fail1;
	}
	wait_event(target->poll.wq, target->poll.read_flags & POLL_INITIALIZED);

	tid = kernel_thread(iscsi_target_write_thread, target, CLONE_FS | CLONE_FILES);
	if (tid < 0) {
		err = tid;
		goto fail2;
	}
	wait_event(target->poll.wq, target->poll.write_flags & POLL_INITIALIZED);

	iscsi_target_proc_init(target);

	MOD_INC_USE_COUNT;

	return 0;
fail2:
	//stop thread
fail1:
	list_del(&target->target.list);
	kfree(target);
	return err;
}

/**
 * Remove a iscsi target.
 * Caller must hold iscsi_sem.
 *
 * iscsi_target_remove - 
 * @target: ptr to target
 *
 * @return    -errno
 */

int iscsi_target_remove(struct iscsi_target *target)
{
	dprintk(D_SETUP, "iscsi_target_remove: %u\n", target->target.id);

	if (!list_empty(&target->session_list) || !list_empty(&target->lun_list))
		return -EBUSY;

	iscsi_target_proc_exit(target);

	target->poll.read_flags |= POLL_EXIT;
	wake_up_process(target->poll.read_thread);
	wait_event(target->poll.wq, !(target->poll.read_flags & POLL_EXIT));

	target->poll.write_flags |= POLL_EXIT;
	wake_up_process(target->poll.write_thread);
	target->poll.last_write_wake = iscsi_jiffies++;
	wait_event(target->poll.wq, !(target->poll.write_flags & POLL_EXIT));

	list_del(&target->target.list);

	kfree(target->name);
	kfree(target->alias);
	kfree(target);

	MOD_DEC_USE_COUNT;

	return 0;
}

/**
 * Lookup a iscsi target.
 * Caller must hold iscsi_sem.
 *
 * iscsi_target_lookup - 
 * @id: id of target
 *
 * @return    ptr to target or NULL
 */

struct iscsi_target *iscsi_target_lookup(u32 id)
{
	struct list_head *entry;
	struct iscsi_target *target;

	for (entry = target_list.next; entry != &target_list; entry = entry->next) {
		target = list_entry(entry, struct iscsi_target, target.list);
		if (target->target.id == id)
			return target;
	}

	return NULL;
}

/**
 * Find a session of a target.
 * TODO: protect me!!!
 *
 * iscsi_target_lookup_session - 
 * @target: ptr to target
 * @id: id of session
 *
 * @return    ptr to session or NULL
 */

struct iscsi_session *iscsi_target_lookup_session(struct iscsi_target *target, u64 sid)
{
	struct list_head *entry;
	struct iscsi_session *session;

	list_for_each(entry, &target->session_list) {
		session = list_entry(entry, struct iscsi_session, list);
		if (session->sid == sid)
			return session;
	}
	return NULL;
}

/**
 * Find a lun of a target.
 * TODO: protect me!!!
 *
 * iscsi_target_lookup_lun
 * @target: ptr to target
 * @id: id of lun
 *
 * @return    ptr to lun or NULL
 */

struct iscsi_lun *iscsi_target_lookup_lun(struct iscsi_target *target, u32 id)
{
	struct list_head *entry;
	struct iscsi_lun *lun;

	// TODO: FIXME!!! PROTECTME!!!
	list_for_each(entry, &target->lun_list) {
		lun = list_entry(entry, struct iscsi_lun, list);
		if (lun->lun == id)
			return lun;
	}
	return NULL;
}

/**
 * read thread of a target.
 *
 * iscsi_target_read_thread - 
 * @arg: ptr to target
 *
 * @return    ignored
 */

static int iscsi_target_read_thread(void *arg)
{
	struct iscsi_target *target = arg;
	struct iscsi_conn *conn;
	struct iscsi_conn *closed_conn = NULL;
	struct iscsi_cmnd *cmnd;
	struct list_head *entry;
	poll_table *wp;
	struct msghdr msg;
	struct iovec iov[ISCSI_CONN_IOV_MAX];
	unsigned int mask;
	int res, len, i;

	daemonize();
	reparent_to_init();

	/* block signals */
	siginitsetinv(&current->blocked, 0);

	/* Set the name of this process. */
	sprintf(current->comm, "itarget%dr", target->target.id);

	target->poll.read_thread = current;
	wp = NULL;

	set_fs(KERNEL_DS);

	dprintk(D_THREAD, "iscsi_target_read_thread(%u): initialized\n", target->target.id);

	memset(&msg, 0, sizeof(msg));
	target->poll.read_flags = POLL_INITIALIZED;
	wake_up(&target->poll.wq);

	while (!(target->poll.read_flags & POLL_EXIT)) {
		dprintk(D_THREAD, "iscsi_target_read_thread(%u): wakeup\n", target->target.id);
		down_read(&target->poll.sem);
		set_current_state(TASK_INTERRUPTIBLE);
		list_for_each(entry, &target->poll.list) {
			conn = list_entry(entry, struct iscsi_conn, poll_list);
			if (conn->state != ISCSI_CONN_ACTIVE) {
				switch (conn->state) {
				case ISCSI_CONN_CLOSING:
					if (!closed_conn)
						closed_conn = conn;
					continue;
				default:
					continue;
				}
			}
			if (!conn->read_cmnd) {
				dprintk(D_THREAD, "new command at %#Lx:%u\n", conn->session->sid, conn->cid);
				iscsi_conn_create_read_cmnd(conn);
				mask = conn->file->f_op->poll(conn->file, &target->poll.read_poll);
			} else
				mask = conn->file->f_op->poll(conn->file, wp);

			if (mask & POLLIN) while (1) {
				dprintk(D_THREAD, "recv %#Lx:%u: %d\n", conn->session->sid, conn->cid, conn->read_size);
#if D_THREAD
				printk("iov %p:%d\n", conn->read_msg.msg_iov, conn->read_msg.msg_iovlen);
				len = min(conn->read_msg.msg_iovlen, (size_t)ISCSI_CONN_IOV_MAX);
				for (i = 0; i < len; i++)
					printk("%d: %p,%d\n", i, conn->read_msg.msg_iov[i].iov_base, conn->read_msg.msg_iov[i].iov_len);
#endif
				msg.msg_iov = iov;
				msg.msg_iovlen = min(conn->read_msg.msg_iovlen, (size_t)ISCSI_CONN_IOV_MAX);
				for (i = 0, len = 0; i < msg.msg_iovlen; i++) {
					iov[i] = conn->read_msg.msg_iov[i];
					len += iov[i].iov_len;
				}
				res = sock_recvmsg(conn->sock, &msg, len, MSG_DONTWAIT);
				if (res <= 0) {
					if (res == -EAGAIN)
						break;
					if (res == -EINTR)
						continue;
					if (res)
						printk("read error %d at %#Lx:%u\n", -res, conn->session->sid, conn->cid);
					//iscsi_conn_remove(conn);
					iscsi_conn_closefd_nolock(conn);
					if (!closed_conn)
						closed_conn = conn;
					break;
				}
				dprintk(D_THREAD, "recv %#Lx:%u: %d(%d)\n", conn->session->sid, conn->cid, res, conn->read_size);
				conn->read_size -= res;
				if (conn->read_size) {
					while ((len = res, res -= conn->read_msg.msg_iov->iov_len) >= 0) {
						conn->read_msg.msg_iov++;
						conn->read_msg.msg_iovlen--;
					}
					conn->read_msg.msg_iov->iov_base = (u8 *)conn->read_msg.msg_iov->iov_base + len;
					conn->read_msg.msg_iov->iov_len = -res;
#if D_THREAD
					printk("rem %p:%d\n", conn->read_msg.msg_iov, conn->read_msg.msg_iovlen);
					len = min(conn->read_msg.msg_iovlen, (size_t)ISCSI_CONN_IOV_MAX);
					for (i = 0; i < len; i++)
						printk("%d: %p,%d\n", i, conn->read_msg.msg_iov[i].iov_base, conn->read_msg.msg_iov[i].iov_len);
#endif
					continue;
				}
				cmnd = conn->read_cmnd;
				switch (conn->read_state) {
				case IOSTATE_READ_BHS:
					conn->read_state = IOSTATE_READ_AHS;
					iscsi_cmnd_get_length(&cmnd->pdu);
					if (cmnd->pdu.ahssize) {
						cmnd->pdu.ahs = kmalloc(cmnd->pdu.ahssize, GFP_KERNEL);
						iscsi_conn_init_read(conn, cmnd->pdu.ahs, cmnd->pdu.ahssize);
						break;
					}
					/* fall through */
				case IOSTATE_READ_AHS:
					conn->read_state = IOSTATE_READ_DATA;
					iscsi_cmnd_start_read(cmnd);
					if (cmnd->pdu.datasize)
						break;
					/* fall through */
				case IOSTATE_READ_DATA:
					iscsi_cmnd_finish_read(cmnd);
					if (!conn->read_size)
						iscsi_conn_create_read_cmnd(conn);
					break;
				}
			}
		}
		up_read(&target->poll.sem);

		if (closed_conn) {
			iscsi_conn_close(closed_conn);
			closed_conn = NULL;
			/* keep running, there may be more closing connections */
			current->state = TASK_RUNNING;
		} else if (target->poll.read_flags & POLL_REINIT_TABLE) {
			down_write(&target->poll.sem);
			if (!wp) {
				dprintk(D_THREAD, "iscsi_target_read_thread(%u): start reinit\n", target->target.id);
				poll_freewait(&target->poll.read_poll);
				poll_initwait(&target->poll.read_poll);
				wp = &target->poll.read_poll;
				current->state = TASK_RUNNING;
			} else {
				dprintk(D_THREAD, "iscsi_target_read_thread(%u): done reinit\n", target->target.id);
				target->poll.read_flags &= ~POLL_REINIT_TABLE;
				wp = NULL;
			}
			up_write(&target->poll.sem);
		}

		dprintk(D_THREAD, "iscsi_target_read_thread(%u): sleep\n", target->target.id);
		schedule();
	}

	current->state = TASK_RUNNING;

	poll_freewait(&target->poll.read_poll);

	dprintk(D_THREAD, "iscsi_target_read_thread(%u): exit\n", target->target.id);
	target->poll.read_flags &= ~POLL_EXIT;
	wake_up(&target->poll.wq);

	return 0;
}

/**
 * write thread of a target.
 *
 * iscsi_target_write_thread
 * @arg: ptr to target
 *
 * @return    ignored
 */

static int iscsi_target_write_thread(void *arg)
{
	struct iscsi_target *target = arg;
	struct iscsi_conn *conn;
	struct iscsi_cmnd *cmnd;
	struct list_head *entry;
	poll_table *wp;
	unsigned int mask;

	daemonize();
	reparent_to_init();

	/* block signals */
	siginitsetinv(&current->blocked, 0);

	/* Set the name of this process. */
	sprintf(current->comm, "itarget%dw", target->target.id);

	target->poll.write_thread = current;
	wp = NULL;

	set_fs(KERNEL_DS);

	dprintk(D_THREAD, "iscsi_target_write_thread(%u): initialized\n", target->target.id);

	target->poll.write_flags = POLL_INITIALIZED;
	wake_up(&target->poll.wq);

	while (!(target->poll.write_flags & POLL_EXIT)) {
		dprintk(D_THREAD, "iscsi_target_write_thread(%u): wakeup\n", target->target.id);
		down_read(&target->poll.sem);
		set_current_state(TASK_INTERRUPTIBLE);
		list_for_each(entry, &target->poll.list) {
			conn = list_entry(entry, struct iscsi_conn, poll_list);

			if (conn->state != ISCSI_CONN_ACTIVE) {
				switch (conn->state) {
				case ISCSI_CONN_NEW:
					dprintk(D_THREAD, "activate new conn %#Lx:%u\n", conn->session->sid, conn->cid);
					conn->state = ISCSI_CONN_ACTIVE;
					wake_up_process(target->poll.read_thread);
					conn->file->f_op->poll(conn->file, &target->poll.write_poll);
					break;
				}
				continue;
			}
			cmnd = conn->write_cmnd;
			if (!cmnd && !wp)
				continue;

			mask = conn->file->f_op->poll(conn->file, wp);
			if (mask & POLLOUT) while (conn->write_cmnd) {
				target->poll.last_write = iscsi_jiffies++;
				if (iscsi_conn_write_data(conn))
					break;
				switch (conn->write_state) {
				case IOSTATE_WRITE_BHS:
					conn->write_state = IOSTATE_WRITE_DATA;
					/* fall through */
				case IOSTATE_WRITE_DATA:
					iscsi_cmnd_finish_write(conn->write_cmnd);
					if (!conn->write_size) {
						iscsi_cmnd_release(cmnd);
						if (!list_empty(&conn->write_list)) {
							cmnd = list_entry(conn->write_list.next,
									  struct iscsi_cmnd, list);
							iscsi_cmnd_start_write(cmnd);
						} else
							conn->write_cmnd = NULL;
					}
					break;
				}
			}
		}
		up_read(&target->poll.sem);

		if (target->poll.write_flags & POLL_REINIT_TABLE) {
			down_write(&target->poll.sem);
			if (!wp) {
				dprintk(D_THREAD, "iscsi_target_write_thread(%u): start reinit\n", target->target.id);
				poll_freewait(&target->poll.write_poll);
				poll_initwait(&target->poll.write_poll);
				wp = &target->poll.write_poll;
				current->state = TASK_RUNNING;
			} else {
				dprintk(D_THREAD, "iscsi_target_write_thread(%u): done reinit\n", target->target.id);
				target->poll.write_flags &= ~POLL_REINIT_TABLE;
				wp = NULL;
			}
			up_write(&target->poll.sem);
		}

		dprintk(D_THREAD, "iscsi_target_write_thread(%u): sleep\n", target->target.id);
		schedule();
	}

	current->state = TASK_RUNNING;

	poll_freewait(&target->poll.write_poll);

	dprintk(D_THREAD, "iscsi_target_write_thread(%u): exit\n", target->target.id);
	target->poll.write_flags &= ~POLL_EXIT;
	wake_up(&target->poll.wq);

	return 0;
}

/*****************************************************************************/
/*                                   COMMAND                                 */
/*****************************************************************************/

/**
 * create a new command.
 *
 * iscsi_cmnd_create - 
 * @conn: ptr to connection (for i/o)
 *
 * @return    ptr to command or NULL
 */

struct iscsi_cmnd *iscsi_cmnd_create(struct iscsi_conn *conn)
{
	struct iscsi_cmnd *cmnd;

	cmnd = kmem_cache_alloc(iscsi_cmnd_cache, GFP_KERNEL);
	if (cmnd) {
		memset(cmnd, 0, sizeof(*cmnd));
		INIT_LIST_HEAD(&cmnd->pdu_list);
		INIT_LIST_HEAD(&cmnd->list);
		cmnd->conn = conn;
		cmnd->state = ISCSI_STATE_NEW;
		spin_lock(&conn->list_lock);
		conn->cmnd_cnt++;
		list_add_tail(&cmnd->conn_list, &conn->pdu_list);
		spin_unlock(&conn->list_lock);
	}
	dprintk(D_GENERIC, "iscsi_cmnd_create: %p:%p\n", conn, cmnd);
	IE2(IE_CMND_CREATE, conn, cmnd);

	return cmnd;
}

/**
 * create a new command used as response.
 *
 * iscsi_cmnd_create_rsp_cmnd - 
 * @cmnd: ptr to request command
 *
 * @return    ptr to response command or NULL
 */

struct iscsi_cmnd *iscsi_cmnd_create_rsp_cmnd(struct iscsi_cmnd *cmnd)
{
	struct iscsi_cmnd *rsp_cmnd = iscsi_cmnd_create(cmnd->conn);
	if (rsp_cmnd)
		list_add_tail(&rsp_cmnd->pdu_list, &cmnd->pdu_list);
	return rsp_cmnd;
}

/**
 * get ptr to request command, which belongs to this response.
 * NOTE: no error checking.
 *
 * iscsi_cmnd_get_req_cmnd - 
 * @rsp_cmnd: ptr to response command
 *
 * @return    ptr to request command
 */

static inline struct iscsi_cmnd *iscsi_cmnd_get_req_cmnd(struct iscsi_cmnd *rsp_cmnd)
{
	return list_entry(rsp_cmnd->pdu_list.next, struct iscsi_cmnd, pdu_list);
}

/**
 * get ptr to response command, which belongs to this request.
 * NOTE: no error checking.
 *
 * iscsi_cmnd_get_rsp_cmnd - 
 * @req_cmnd: ptr to request command
 *
 * @return    ptr to response comman
 */

static inline struct iscsi_cmnd *iscsi_cmnd_get_rsp_cmnd(struct iscsi_cmnd *req_cmnd)
{
	return list_entry(req_cmnd->pdu_list.prev, struct iscsi_cmnd, pdu_list);
}

/**
 * Free a command.
 * Also frees the additional header.
 *
 * iscsi_cmnd_remove - 
 * @cmnd: ptr to command
 */

void iscsi_cmnd_remove(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn;

	if (!cmnd)
		return;
	dprintk(D_GENERIC, "iscsi_cmnd_remove: %p\n", cmnd);
	IE1(IE_CMND_REMOVE, cmnd);
	conn = cmnd->conn;
	if (cmnd->pdu.ahs)
		kfree(cmnd->pdu.ahs);
	if (!list_empty(&cmnd->list))
		printk("iscsi_cmnd_remove: cmnd %p still on some list?\n", cmnd);
	list_del(&cmnd->list);					    /* move me??? */
	spin_lock(&conn->list_lock);
	conn->cmnd_cnt--;
	list_del(&cmnd->conn_list);
	spin_unlock(&conn->list_lock);
	if (!conn->cmnd_cnt)
		wake_up(&iscsi_wq);
	kmem_cache_free(iscsi_cmnd_cache, cmnd);
}

/**
 * Extracts the size of the additional header and data out of the PDU.
 *
 * iscsi_cmnd_get_length - 
 * @pdu: ptr to pdu
 */

static inline void iscsi_cmnd_get_length(struct iscsi_pdu *pdu)
{
#if defined(__BIG_ENDIAN)
	pdu->ahssize = pdu->bhs.length.ahslength * 4;
	pdu->datasize = pdu->bhs.length.datalength;
#elif defined(__LITTLE_ENDIAN)
	pdu->ahssize = (pdu->bhs.length & 0xff) * 4;
	pdu->datasize = be32_to_cpu(pdu->bhs.length & ~0xff);
#else
#error
#endif
}

/**
 * Stores the size of the additional header and data in the PDU.
 *
 * iscsi_cmnd_set_length
 * @pdu: ptr to pdu
 */

static inline void iscsi_cmnd_set_length(struct iscsi_pdu *pdu)
{
#if defined(__BIG_ENDIAN)
	pdu->bhs.length.ahslength = pdu->ahssize / 4;
	pdu->bhs.length.datalength = pdu->datasize;
#elif defined(__LITTLE_ENDIAN)
	pdu->bhs.length = cpu_to_be32(pdu->datasize) | (pdu->ahssize / 4);
#else
#error
#endif
}

/**
 * iscsi_cmnd_start_read - Start processing an iscsi command.
 * @cmnd: ptr to command
 *
 * Called from the read thread after pdu and the additional header has been read.
 * If more data needs to be read, conn->read_size must be set.
 */

void iscsi_cmnd_start_read(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;

	dprintk(D_GENERIC, "iscsi_cmnd_start_read: %p:%x\n", cmnd, cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK);
	IE3(IE_CMND_START_READ, cmnd, cmnd->pdu.bhs.opcode);
	trace_std_formatted_event(trace_read_cmnd, cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK);
	iscsi_dump_pdu(&cmnd->pdu);

	if (cmnd->pdu.ahssize + cmnd->pdu.datasize + sizeof(struct iscsi_hdr) > conn->session->param.max_data_pdu_length) {
		// drop connection...
	}

	switch (cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK) {
	case ISCSI_OP_NOOP_OUT:
	{
		u32 size, tmp;
		int i;

		if (cmnd->pdu.bhs.itt == cpu_to_be32(ISCSI_RESERVED_TAG)) {
			iscsi_conn_update_stat_sn(cmnd);
			iscsi_session_check_cmd_sn(cmnd);
			break;
		} else if (!iscsi_session_insert_cmnd(cmnd))
			break;

		if ((size = cmnd->pdu.datasize)) {
			conn->read_msg.msg_iov = conn->read_iov;
			i = 0;
			if (cmnd->pdu.bhs.itt != cpu_to_be32(ISCSI_RESERVED_TAG)) {
				cmnd->data = (void *)__get_free_page(GFP_KERNEL);
				tmp = min(size, (u32)PAGE_SIZE);
				conn->read_iov[0].iov_base = cmnd->data;
				conn->read_iov[0].iov_len = tmp;
				conn->read_size += tmp;
				size -= tmp;
				i = 1;
			}

			for (i = 1; size && i < ISCSI_CONN_IOV_MAX; i++) {
				conn->read_iov[i].iov_base = dummy_data;
				tmp = min(size, sizeof(dummy_data));
				conn->read_iov[i].iov_len = tmp;
				conn->read_size += tmp;
				size -= tmp;
			}
			conn->read_overflow = size;
			conn->read_msg.msg_iovlen = i;
			conn->read_size = (conn->read_size + 3) & -4;
		}
		break;
	}
	case ISCSI_OP_SCSI_CMD:
	{
		struct iscsi_scsi_cmd_hdr *req = (struct iscsi_scsi_cmd_hdr *)&cmnd->pdu.bhs;
		struct target_device *dev = NULL;
		struct target_cmnd *tcmnd;

		if (!iscsi_session_insert_cmnd(cmnd))
			break;

		cmnd->lun = iscsi_target_lookup_lun(conn->session->target, be16_to_cpu(req->lun[0]));
		cmnd->data = tcmnd = target_cmnd_create();

		dprintk(D_GENERIC, "scsi command: %02x\n", req->scb[0]);
		IE3(IE_CMND_SCSI, cmnd, req->scb[0]);
		if (cmnd->lun) {
			dev = cmnd->lun->device;
		} else {
			switch (req->scb[0]) {
			case INQUIRY:
			case REPORT_LUNS:
				break;
			default:
				iscsi_cmnd_sense_rsp(cmnd, ILLEGAL_REQUEST, 0x25, 0x0);
				iscsi_cmnd_ignore_data(cmnd);
				return;
			}
		}

		switch (req->scb[0]) {
		case INQUIRY:
		case REPORT_LUNS:
		case TEST_UNIT_READY:
		case VERIFY:
		case START_STOP:
		case READ_CAPACITY:
		case MODE_SENSE:
		case READ_6:
		case READ_10:
			if (!(req->flags & ISCSI_CMD_FINAL) || cmnd->pdu.datasize) {
				/* unexpected unsolicited data */
				iscsi_cmnd_sense_rsp(cmnd, ABORTED_COMMAND, 0xc, 0xc);
				iscsi_cmnd_ignore_data(cmnd);
			}
			break;
		case WRITE_6:
		{
			loff_t offset;
			u32 len;

			if (!(conn->session->param.flags & SESSION_FLG_IMMEDIATEDATA) &&
			    cmnd->pdu.datasize) {
			}
			if ((conn->session->param.flags & SESSION_FLG_INITIAL_RTT) &&
			    !(req->flags & ISCSI_CMD_FINAL)) {
			}

			offset = ((req->scb[1] & 0x1f) << 16) +
				 (req->scb[2] << 8) + req->scb[3];
			len = req->scb[4];
			if (!len)
				len = 256;

			target_init_write(dev, tcmnd, offset << dev->blk_shift, len << dev->blk_shift);

			if (cmnd->pdu.datasize) {
				target_get_async_pages(dev, tcmnd, cmnd->pdu.datasize);
				iscsi_cmnd_receive_pdu(conn, tcmnd, 0, cmnd->pdu.datasize);
			}
			break;
		}
		case WRITE_10:
		{
			loff_t offset;
			u32 len;

			offset = be32_to_cpu(*(u32 *)&req->scb[2]);
			len = (req->scb[7] << 8) + req->scb[8];
			//if (!len) send rsp;

			target_init_write(dev, tcmnd, offset << dev->blk_shift, len << dev->blk_shift);

			if (cmnd->pdu.datasize) {
				target_get_async_pages(dev, tcmnd, cmnd->pdu.datasize);
				iscsi_cmnd_receive_pdu(conn, tcmnd, 0, cmnd->pdu.datasize);
			}
			break;
		}
		default:
			iscsi_cmnd_sense_rsp(cmnd, ILLEGAL_REQUEST, 0x20, 0x0);
			iscsi_cmnd_ignore_data(cmnd);
			break;
		}
		break;
	}
	case ISCSI_OP_SCSI_TASK_MGT_MSG:
		iscsi_session_insert_cmnd(cmnd);
		break;
	case ISCSI_OP_LOGIN_CMD:
		if (!iscsi_session_insert_cmnd(cmnd))
			break;
		iscsi_cmnd_reject(cmnd, ISCSI_REASON_UNSUPPORTED_COMMAND);
		break;
	case ISCSI_OP_TEXT_CMD:
		iscsi_session_insert_cmnd(cmnd);
		break;
	case ISCSI_OP_SCSI_DATA:
	{
		struct iscsi_data_out_hdr *req = (struct iscsi_data_out_hdr *)&cmnd->pdu.bhs;
		struct iscsi_cmnd *scsi_cmnd = NULL;
		u32 offset = be32_to_cpu(req->buffer_offset);

		iscsi_conn_update_stat_sn(cmnd);
		if (req->ttt == cpu_to_be32(ISCSI_RESERVED_TAG)) {
			/* unsolicited burst data */
			scsi_cmnd = iscsi_session_find_cmnd(conn->session, req->itt);
			if (!scsi_cmnd) {
				printk("unable to find scsi task %x\n", req->itt);
				goto skip_data;
			}
			if (scsi_cmnd->pdu.bhs.flags & ISCSI_FLG_FINAL) {
				printk("unexpected data from %x\n", req->itt);
				goto skip_data;
			}
			cmnd->data = scsi_cmnd;
			target_get_async_pages(scsi_cmnd->lun->device, scsi_cmnd->data, offset + cmnd->pdu.datasize);
		} else {
			scsi_cmnd = iscsi_session_find_ttt(conn->session, req->ttt);
			if (!scsi_cmnd) {
				printk("unable to find r2t task %x\n", req->ttt);
				goto skip_data;
			}
			cmnd->data = scsi_cmnd;
			scsi_cmnd = scsi_cmnd->data;
		}

		// CHECKME!
		iscsi_cmnd_receive_pdu(conn, scsi_cmnd->data, offset, cmnd->pdu.datasize);
		break;
	skip_data:
		// reject? FIXME
		cmnd->data = NULL;
		cmnd->pdu.bhs.opcode = ISCSI_OP_DATA_REJECT;
		iscsi_cmnd_skip_pdu(cmnd);
		break;
	}
	case ISCSI_OP_LOGOUT_CMD:
		iscsi_session_insert_cmnd(cmnd);
		break;
	case ISCSI_OP_SNACK_CMD:
		iscsi_conn_update_stat_sn(cmnd);
		break;
	default:
		iscsi_cmnd_reject(cmnd, ISCSI_REASON_UNSUPPORTED_COMMAND);
		break;
	}
}

/**
 * Continue processing an iscsi command.
 * Called from the read thread after data has been read.
 * If more data needs to be read, conn->read_size must be set,
 * otherwise command is usually prepared for execution.
 *
 * iscsi_cmnd_finish_read - 
 * @cmnd: ptr to command
 */

void iscsi_cmnd_finish_read(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;

	dprintk(D_GENERIC, "iscsi_cmnd_finish_read: %p:%x\n", cmnd, cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK);
	IE3(IE_CMND_FINISH_READ, cmnd, cmnd->pdu.bhs.opcode);
	switch (cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK) {
	case ISCSI_OP_NOOP_OUT:
	{
		u32 size, tmp;
		int i;

		size = conn->read_overflow;
		if (size) {
			conn->read_msg.msg_iov = conn->read_iov;
			for (i = 0; size && i < ISCSI_CONN_IOV_MAX; i++) {
				conn->read_iov[i].iov_base = dummy_data;
				tmp = min(size, sizeof(dummy_data));
				conn->read_iov[i].iov_len = tmp;
				conn->read_size += tmp;
				size -= tmp;
			}
			conn->read_size = (conn->read_size + 3) & -4;
			conn->read_overflow = size;
			conn->read_msg.msg_iovlen = i;
		} else
			iscsi_session_push_cmnd(cmnd);
		break;
	}

	case ISCSI_OP_SCSI_CMD:
		if (cmnd->pdu.datasize)
			iscsi_cmnd_unmap_pdu(conn, cmnd->data, 0, cmnd->pdu.datasize);
		iscsi_session_push_cmnd(cmnd);
		break;
	case ISCSI_OP_SCSI_TASK_MGT_MSG:
		iscsi_session_push_cmnd(cmnd);
		break;
	case ISCSI_OP_TEXT_CMD:
		iscsi_session_push_cmnd(cmnd);
		break;
	case ISCSI_OP_SCSI_DATA:
	{
		struct target_device *dev;
		struct iscsi_data_out_hdr *req;
		struct iscsi_cmnd *r2t_cmnd;
		struct iscsi_cmnd *scsi_cmnd;
		struct iscsi_cmnd *rsp_cmnd;
		struct iscsi_scsi_rsp_hdr *rsp;
		u32 size, offset;

		req = (struct iscsi_data_out_hdr *)&cmnd->pdu.bhs;
		if (req->ttt == cpu_to_be32(ISCSI_RESERVED_TAG)) {
			scsi_cmnd = cmnd->data;
			if (conn->read_overflow) {
				offset = be32_to_cpu(req->buffer_offset);
				offset += cmnd->pdu.datasize - conn->read_overflow;
				iscsi_cmnd_receive_pdu(conn, scsi_cmnd->data, offset, conn->read_overflow);
				break;
			}

			if (req->flags & ISCSI_FLG_FINAL) {
				switch (scsi_cmnd->state) {
				case ISCSI_STATE_PUSHED:
					scsi_cmnd->pdu.bhs.flags |= ISCSI_FLG_FINAL;
					break;
				case ISCSI_STATE_QUEUED:
					//lock
					//check
					scsi_cmnd->pdu.bhs.flags |= ISCSI_FLG_FINAL;
					//unlock
					break;
				case ISCSI_STATE_WAIT_RECEIVE:
					//list_del_init(&cmnd->list);
					scsi_cmnd->pdu.bhs.flags |= ISCSI_FLG_FINAL;
					iscsi_device_queue_cmnd(scsi_cmnd);
					break;
				}
			}
			goto remove_data_cmnd;
		}
		r2t_cmnd = cmnd->data;
		if (!r2t_cmnd)
			break;
		scsi_cmnd = r2t_cmnd->data;
		if (conn->read_overflow) {
			offset = be32_to_cpu(req->buffer_offset);
			offset += cmnd->pdu.datasize - conn->read_overflow;
			iscsi_cmnd_receive_pdu(conn, scsi_cmnd->data, offset, conn->read_overflow);
			break;
		}

		if (!(req->flags & ISCSI_FLG_FINAL))
			goto remove_data_cmnd;

		iscsi_session_remove_ttt(r2t_cmnd);
		if (!list_empty(&scsi_cmnd->pdu_list))
			goto remove_data_cmnd;

		rsp_cmnd = iscsi_cmnd_scsi_rsp(scsi_cmnd);
		rsp = (struct iscsi_scsi_rsp_hdr *)&rsp_cmnd->pdu.bhs;

		list_del_init(&scsi_cmnd->list);
		size = iscsi_cmnd_read_size(cmnd);
		if (size) {
			rsp->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
			rsp->residual_count = cpu_to_be32(size);
		}

		dev = scsi_cmnd->lun->device;
		if (target_commit_pages(dev, scsi_cmnd->data)) {
			scsi_cmnd->state = ISCSI_STATE_WAIT_COMMIT;
			if (!list_empty(&scsi_cmnd->list))
				BUG();
			list_add_tail(&scsi_cmnd->list, &dev->io_list);
		} else if (target_sync_pages(dev, scsi_cmnd->data)) {
			scsi_cmnd->state = ISCSI_STATE_WAIT_WRITE;
			if (!list_empty(&scsi_cmnd->list))
				BUG();
			list_add_tail(&scsi_cmnd->list, &dev->io_list);
		} else {
			iscsi_cmnd_init_write(rsp_cmnd);
			scsi_cmnd->state = ISCSI_STATE_SEND_RSP;
			//list_add_tail(&scsi_cmnd->list, &conn->wait_list);
		}
	remove_data_cmnd:
		iscsi_cmnd_unmap_pdu(conn, scsi_cmnd->data, be32_to_cpu(req->buffer_offset), cmnd->pdu.datasize);
		iscsi_cmnd_remove(cmnd);
		break;
	}
	case ISCSI_OP_LOGOUT_CMD:
		iscsi_session_push_cmnd(cmnd);
		break;
	case ISCSI_OP_SNACK_CMD:
		break;
	case ISCSI_OP_SCSI_REJECT:
		target_free_pages(cmnd->data);
		cmnd->data = NULL;
		iscsi_session_push_cmnd(cmnd);
		break;
	case ISCSI_OP_PDU_REJECT: {
		/* rejected cmnd must not be pushed, so exp_cmd_sn doesn't increase */
		struct iscsi_cmnd *rsp_cmnd = iscsi_cmnd_get_rsp_cmnd(cmnd);

		iscsi_cmnd_init_write(rsp_cmnd);
		break;
	}
	case ISCSI_OP_DATA_REJECT:
		iscsi_cmnd_unmap_pdu(conn, cmnd->data, 0, PAGE_SIZE);
		iscsi_cmnd_release(cmnd);
		break;
	default:
		printk("iscsi_cmnd_finish_read: unexpected cmnd op %x\n", cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK);
		break;
	}
}

/**
 * Execute an iscsi command.
 * Called from the read thread and commands are executed here in the right order.
 *
 * iscsi_cmnd_execute - 
 * @cmnd: ptr to command
 */

void iscsi_cmnd_execute(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct iscsi_cmnd *rsp_cmnd;

	dprintk(D_GENERIC, "iscsi_cmnd_execute: %p,%x,%u\n", cmnd, cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK, cmnd->pdu.bhs.sn);
	IE3(IE_CMND_EXECUTE, cmnd, cmnd->pdu.bhs.opcode);
	trace_std_formatted_event(trace_execute_cmnd, cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK);

	switch (cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK) {
	case ISCSI_OP_NOOP_OUT:
	{
		struct iscsi_nop_in_hdr *rsp;
		struct target_cmnd *tcmnd = cmnd->data;

		if (cmnd->pdu.bhs.itt != cpu_to_be32(ISCSI_RESERVED_TAG)) {
			rsp_cmnd = iscsi_cmnd_create_rsp_cmnd(cmnd);
			if (!rsp_cmnd)
				/* close connection */;

			rsp = (struct iscsi_nop_in_hdr *)&rsp_cmnd->pdu.bhs;
			rsp->opcode = ISCSI_OP_NOOP_IN;
			rsp->flags = ISCSI_FLG_FINAL;
			rsp->itt = cmnd->pdu.bhs.itt;
			rsp->ttt = cpu_to_be32(ISCSI_RESERVED_TAG);

			rsp_cmnd->data = tcmnd;
			rsp_cmnd->pdu.datasize = min(cmnd->pdu.datasize, (u32)PAGE_SIZE);
			iscsi_cmnd_init_write(rsp_cmnd);
		} else
			iscsi_cmnd_remove(cmnd);
		break;
	}
	case ISCSI_OP_SCSI_CMD:
	{
		if (cmnd->state != ISCSI_STATE_READ && cmnd->state != ISCSI_STATE_PUSHED)
			printk("iscsi_cmnd_execute: unexpected state %d of cmnd %p\n", cmnd->state, cmnd);
		if (cmnd->lun)
			iscsi_scsi_queuecmnd(cmnd);
		else {
			/* force queued status */
			cmnd->state = ISCSI_STATE_QUEUED;
			iscsi_scsi_execute(cmnd);
		}
		break;
	}
	case ISCSI_OP_SCSI_TASK_MGT_MSG:
	{
		struct iscsi_task_mgt_hdr *req = (struct iscsi_task_mgt_hdr *)&cmnd->pdu.bhs;
		struct iscsi_task_rsp_hdr *rsp;
		struct iscsi_lun *lun = NULL;
		int function;

		{
			struct list_head *cmnd_entry;
			struct iscsi_cmnd *cmnd;
			dprintk(D_TASK_MGT, "task management command: %x\n", req->function);
			target_print_events();
			list_for_each(cmnd_entry, &conn->session->pending_list) {
				cmnd = list_entry(cmnd_entry, struct iscsi_cmnd, list);
				dprintk(D_TASK_MGT, "%p: %u %u\n", cmnd, cmnd->pdu.bhs.opcode &
				       ISCSI_OPCODE_MASK, cmnd->pdu.bhs.sn);
			}
		}

		rsp_cmnd = iscsi_cmnd_create_rsp_cmnd(cmnd);
		if (!rsp_cmnd)
			/* close connection */;
		rsp = (struct iscsi_task_rsp_hdr *)&rsp_cmnd->pdu.bhs;

		rsp->opcode = ISCSI_OP_SCSI_TASK_MGT_RSP;
		rsp->flags = ISCSI_FLG_FINAL;
		rsp->itt = req->itt;

		function = req->function & ISCSI_FUNCTION_MASK;
		switch (function) {
		case ISCSI_FUNCTION_ABORT_TASK:
		case ISCSI_FUNCTION_ABORT_TASK_SET:
		case ISCSI_FUNCTION_CLEAR_ACA:
		case ISCSI_FUNCTION_CLEAR_TASK_SET:
		case ISCSI_FUNCTION_LOGICAL_UNIT_RESET:
			lun = iscsi_target_lookup_lun(conn->session->target, be16_to_cpu(req->lun[0]));
			if (!lun)
				rsp->response = ISCSI_RESPONSE_UNKNOWN_LUN;
		}

		if (!rsp->response) switch (function) {
		case ISCSI_FUNCTION_ABORT_TASK:
			//rsp->response = ISCSI_RESPONSE_UNKNOWN_TASK;
			rsp->response = ISCSI_RESPONSE_FUNCTION_COMPLETE;
			break;
		case ISCSI_FUNCTION_ABORT_TASK_SET:
			rsp->response = ISCSI_RESPONSE_FUNCTION_REJECTED;
			break;
		case ISCSI_FUNCTION_CLEAR_ACA:
			rsp->response = ISCSI_RESPONSE_FUNCTION_REJECTED;
			break;
		case ISCSI_FUNCTION_CLEAR_TASK_SET:
			rsp->response = ISCSI_RESPONSE_FUNCTION_REJECTED;
			break;
		case ISCSI_FUNCTION_LOGICAL_UNIT_RESET:
			// TODO
			rsp->response = ISCSI_RESPONSE_FUNCTION_COMPLETE;
			//rsp->response = ISCSI_RESPONSE_FUNCTION_REJECTED;
			break;
		case ISCSI_FUNCTION_TARGET_WARM_RESET:
			// TODO
			rsp->response = ISCSI_RESPONSE_FUNCTION_COMPLETE;
			//iscsi_conn_closefd_nolock(conn);
			break;
		case ISCSI_FUNCTION_TARGET_COLD_RESET:
			// TODO
			rsp->response = ISCSI_RESPONSE_FUNCTION_COMPLETE;
			iscsi_conn_closefd_nolock(conn);
			break;
		case ISCSI_FUNCTION_TASK_REASSIGN:
			rsp->response = ISCSI_RESPONSE_FUNCTION_REJECTED;
			break;
		default:
			rsp->response = ISCSI_RESPONSE_FUNCTION_REJECTED;
			break;
		}
		iscsi_cmnd_init_write(rsp_cmnd);
		break;
	}
	case ISCSI_OP_TEXT_CMD:
		break;
	case ISCSI_OP_LOGOUT_CMD:
	{
		struct iscsi_logout_req_hdr *req = (struct iscsi_logout_req_hdr *)&cmnd->pdu.bhs;
		struct iscsi_logout_rsp_hdr *rsp;

		rsp_cmnd = iscsi_cmnd_create_rsp_cmnd(cmnd);
		if (!rsp_cmnd)
			/* close connection */;
		rsp = (struct iscsi_logout_rsp_hdr *)&rsp_cmnd->pdu.bhs;
		rsp->opcode = ISCSI_OP_LOGOUT_RSP;
		rsp->flags = ISCSI_FLG_FINAL;
		rsp->itt = req->itt;
		iscsi_cmnd_init_write(rsp_cmnd);
		break;
	}
	case ISCSI_OP_SNACK_CMD:
		break;
	case ISCSI_OP_SCSI_REJECT:
		rsp_cmnd = iscsi_cmnd_get_rsp_cmnd(cmnd);
		iscsi_cmnd_init_write(rsp_cmnd);
		break;
	default:
		printk("iscsi_cmnd_execute: unexpected cmnd op %x\n", cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK);
		break;
	}
}

/**
 * Schedules an iscsi command for writing.
 *
 * iscsi_cmnd_init_write - 
 * @cmnd: ptr to command
 */

void iscsi_cmnd_init_write(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;

	dprintk(D_GENERIC, "iscsi_cmnd_init_write: %p:%x\n", cmnd, cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK);
	IE3(IE_CMND_INIT_WRITE, cmnd, cmnd->pdu.bhs.opcode);
	if (conn->state != ISCSI_CONN_ACTIVE) {
		// move this later into session for recovery
		iscsi_cmnd_release(cmnd);
		return;
	}
	cmnd->state = ISCSI_STATE_WRITE;
	// PROTECT ME!
	if (!list_empty(&cmnd->list))
		BUG();
	list_add_tail(&cmnd->list, &conn->write_list);
	if (!conn->write_cmnd) {
		iscsi_cmnd_start_write(cmnd);
		wake_up_process(conn->session->target->poll.write_thread);
		conn->session->target->poll.last_write_wake = iscsi_jiffies++;
	}
}

/**
 * Start writing of an iscsi command.
 * Initializes conn->write_*.
 * Called from the write thread.
 *
 * iscsi_cmnd_start_write - 
 * @cmnd: ptr to command
 */

void iscsi_cmnd_start_write(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct iovec *iop;
	static int opt = 1;

	dprintk(D_GENERIC, "iscsi_cmnd_start_write: %p:%x\n", cmnd, cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK);
	IE3(IE_CMND_START_WRITE, cmnd, cmnd->pdu.bhs.opcode);
	trace_std_formatted_event(trace_write_cmnd, cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK);
	iscsi_cmnd_set_length(&cmnd->pdu);

	//conn->sock->sk->tp_pinfo.af_tcp.nonagle = 2;
	conn->sock->ops->setsockopt(conn->sock, SOL_TCP, TCP_CORK, (void *)&opt, sizeof(opt));

	conn->write_cmnd = cmnd;
	conn->write_state = IOSTATE_WRITE_BHS;

	conn->write_iop = iop = conn->write_iov;
	iop->iov_base = &cmnd->pdu.bhs;
	iop->iov_len = sizeof(cmnd->pdu.bhs);
	iop++;
	conn->write_size = sizeof(cmnd->pdu.bhs);

	switch (cmnd->pdu.bhs.opcode) {
	case ISCSI_OP_NOOP_IN: {
		iscsi_cmnd_set_sn(cmnd, 1);
		if (cmnd->pdu.datasize) {
			u32 size = (cmnd->pdu.datasize + 3) & -4;
			iop->iov_base = cmnd->data;
			iop->iov_len = size;
			iop++;
			conn->write_size += size;
		}
		break;
	}
	case ISCSI_OP_SCSI_RSP:
		iscsi_cmnd_set_sn(cmnd, 1);
		if (cmnd->pdu.datasize) {
			struct target_cmnd *tcmnd = cmnd->data;
			u32 size = (cmnd->pdu.datasize + 3) & -4;

			iop->iov_base = tcmnd->u.data;
			iop->iov_len = size;
			iop++;
			conn->write_size += size;
		}
		break;
	case ISCSI_OP_SCSI_TASK_MGT_RSP:
		iscsi_cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_TEXT_RSP:
		iscsi_cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_SCSI_DATA_RSP:
	{
		struct iscsi_data_in_hdr *rsp = (struct iscsi_data_in_hdr *)&cmnd->pdu.bhs;
		u32 offset;

		iscsi_cmnd_set_sn(cmnd, (rsp->flags & ISCSI_FLG_FINAL) ? 1 : 0);
		offset = rsp->buffer_offset;
		rsp->buffer_offset = cpu_to_be32(offset);
		iscsi_cmnd_send_pdu(conn, cmnd->data, offset, cmnd->pdu.datasize);
		break;
	}
	case ISCSI_OP_LOGOUT_RSP:
		iscsi_cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_RTT_RSP:
		iscsi_cmnd_set_sn(cmnd, 0);
		cmnd->pdu.bhs.sn = cpu_to_be32(conn->stat_sn);
		break;
	case ISCSI_OP_ASYNC_EVENT:
		iscsi_cmnd_set_sn(cmnd, 1);
		break;
	case ISCSI_OP_REJECT_MSG:
		iscsi_cmnd_set_sn(cmnd, 1);
		break;
	default:
		printk("iscsi_cmnd_start_write: unexpected cmnd op %x\n", cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK);
		break;
	}

	iop->iov_len = 0;
	// move this?
	conn->write_size = (conn->write_size + 3) & -4;
	iscsi_dump_pdu(&cmnd->pdu);
}

/**
 * Finish writing of an iscsi command.
 * If more data needs to be written, set conn->write_size & co.
 *
 * iscsi_cmnd_finish_write - 
 * @cmnd: ptr to command
 */

void iscsi_cmnd_finish_write(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;

	dprintk(D_GENERIC, "iscsi_cmnd_finish_write: %p:%x\n", cmnd, cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK);
	IE3(IE_CMND_FINISH_WRITE, cmnd, cmnd->pdu.bhs.opcode);
	switch (cmnd->pdu.bhs.opcode) {
	case ISCSI_OP_NOOP_IN:
	case ISCSI_OP_SCSI_RSP:
	case ISCSI_OP_SCSI_TASK_MGT_RSP:
	case ISCSI_OP_TEXT_RSP:
		break;
	case ISCSI_OP_SCSI_DATA_RSP:
		//iscsi_cmnd_unmap_pdu(conn, cmnd->data, be32_to_cpu(rsp->buffer_offset), cmnd->pdu.datasize);
		break;
	case ISCSI_OP_LOGOUT_RSP:
		iscsi_conn_closefd_nolock(conn);
		break;
	case ISCSI_OP_RTT_RSP:
	case ISCSI_OP_ASYNC_EVENT:
	case ISCSI_OP_REJECT_MSG:
		break;
	default:
		printk("iscsi_cmnd_finish_write: unexpected cmnd op %x\n", cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK);
		break;
	}
	if (!cmnd->conn->write_size) {
		static int opt = 0;

		cmnd->state = ISCSI_STATE_WRITE_DONE;
		list_del_init(&cmnd->list);
		conn->sock->ops->setsockopt(conn->sock, SOL_TCP, TCP_CORK, (void *)&opt, sizeof(opt));
		//conn->sock->sk->tp_pinfo.af_tcp.nonagle = 0;
		//tcp_push_pending_frames(conn->sock->sk, &conn->sock->sk->tp_pinfo.af_tcp);
	}
}

void iscsi_cmnd_release(struct iscsi_cmnd *cmnd)
{
	struct iscsi_cmnd *req_cmnd;
	int opcode = cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK;

	dprintk(D_GENERIC, "iscsi_cmnd_release: %p:%x\n", cmnd, opcode);
	IE3(IE_CMND_RELEASE, cmnd, cmnd->pdu.bhs.opcode);
	switch (opcode) {
	case ISCSI_OP_NOOP_IN:
		if (cmnd->data)
			free_page((unsigned long)cmnd->data);

		req_cmnd = iscsi_cmnd_get_req_cmnd(cmnd);
		iscsi_session_remove_cmnd(req_cmnd);
		break;
	case ISCSI_OP_SCSI_CMD:
	case ISCSI_OP_SCSI_ABORT:
	{
		struct iscsi_scsi_cmd_hdr *req;

		req = (struct iscsi_scsi_cmd_hdr *)&cmnd->pdu.bhs;
		switch (req->scb[0]) {
		case WRITE_6:
		case WRITE_10:
		case READ_6:
		case READ_10:
			target_put_pages(cmnd->data);
			break;
		case INQUIRY:
		case REPORT_LUNS:
		case READ_CAPACITY:
		case MODE_SENSE:
			target_free_pages(cmnd->data);
			break;
		case START_STOP:
		case TEST_UNIT_READY:
		case VERIFY:
			break;
		default: {
			static int cnt = 5;
			if (cnt > 0) {
				cnt--;
				printk("iscsi_cmnd_release(scsi): unexpected scsi data cmnd %x:%x!\n",
				       cmnd->pdu.bhs.opcode, req->scb[0]);
			}
		}
			break;
		}
		if (!list_empty(&cmnd->pdu_list))
			printk("iscsi_cmnd_release: pdu list not empty!\n");
		iscsi_scsi_dequeuecmnd(cmnd);
		iscsi_session_remove_cmnd(cmnd);
		break;
	}
	case ISCSI_OP_SCSI_REJECT:
		iscsi_session_remove_cmnd(cmnd);
		break;
	case ISCSI_OP_SCSI_RSP:
		req_cmnd = iscsi_cmnd_get_req_cmnd(cmnd);
		list_del_init(&cmnd->pdu_list);
		target_free_pages(cmnd->data);
		iscsi_cmnd_remove(cmnd);
		iscsi_cmnd_release(req_cmnd);
		break;
	case ISCSI_OP_SCSI_TASK_MGT_RSP:
		req_cmnd = iscsi_cmnd_get_req_cmnd(cmnd);
		if ((req_cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK) != ISCSI_OP_SCSI_TASK_MGT_MSG)
			printk("iscsi_cmnd_release(task): unexpected scsi cmnd %x!\n", req_cmnd->pdu.bhs.opcode);

		iscsi_session_remove_cmnd(req_cmnd);
		break;
	case ISCSI_OP_TEXT_RSP:
		list_del_init(&cmnd->list);
		iscsi_session_remove_cmnd(iscsi_cmnd_get_req_cmnd(cmnd));
		break;
	case ISCSI_OP_SCSI_DATA_RSP:
	{
		struct iscsi_data_in_hdr *rsp;
		u32 offset;

		rsp = (struct iscsi_data_in_hdr *)&cmnd->pdu.bhs;
		offset = be32_to_cpu(rsp->buffer_offset);

		req_cmnd = iscsi_cmnd_get_req_cmnd(cmnd);
		list_del_init(&cmnd->pdu_list);
		if (cmnd->pdu.bhs.flags & ISCSI_FLG_FINAL)
			iscsi_cmnd_release(req_cmnd);
		iscsi_cmnd_remove(cmnd);
		break;
	}
	case ISCSI_OP_LOGOUT_RSP:
		iscsi_session_remove_cmnd(iscsi_cmnd_get_req_cmnd(cmnd));
		break;
	case ISCSI_OP_RTT_RSP:
		break;
	case ISCSI_OP_ASYNC_EVENT:
		iscsi_cmnd_remove(cmnd);
		break;
	case ISCSI_OP_REJECT_MSG:
		iscsi_session_remove_cmnd(iscsi_cmnd_get_req_cmnd(cmnd));
		break;
	case ISCSI_OP_DATA_REJECT:
		target_free_pages(cmnd->data);
		iscsi_cmnd_remove(cmnd);
		break;
	default:
		printk("iscsi_cmnd_release: unexpected cmnd op %x\n", opcode);
		break;
	}
}


/**
 * Reject an iscsi command.
 * Reads remaining data and sends a reject response.
 * Called from iscsi_cmnd_start_read.
 *
 * iscsi_cmnd_reject - 
 * @cmnd: ptr to command to reject
 * @reason: reason for reject (see ISCSI_REASON_*)
 */

void iscsi_cmnd_reject(struct iscsi_cmnd *cmnd, int reason)
{
	struct iscsi_cmnd *rej_cmnd;
	struct iscsi_reject_hdr *rsp;

	rej_cmnd = iscsi_cmnd_create_rsp_cmnd(cmnd);
	if (!rej_cmnd)
		/* close connection */;
	rsp = (struct iscsi_reject_hdr *)&rej_cmnd->pdu.bhs;

	rsp->opcode = ISCSI_OP_REJECT_MSG;
	rsp->ffffffff = ISCSI_RESERVED_TAG;
	rsp->reason = reason;
	rej_cmnd->data = cmnd;

	cmnd->pdu.bhs.opcode = ISCSI_OP_PDU_REJECT;

	iscsi_cmnd_skip_pdu(cmnd);
}

/**
 * Create a iscsi response command for a successfull scsi command.
 *
 * iscsi_cmnd_scsi_rsp - 
 * @scsi_cmnd: ptr to scsi command
 *
 * @return    ptr to scsi response or NULL
 */

struct iscsi_cmnd *iscsi_cmnd_scsi_rsp(struct iscsi_cmnd *scsi_cmnd)
{
	struct iscsi_cmnd *cmnd;
	struct iscsi_scsi_cmd_hdr *req;
	struct iscsi_scsi_rsp_hdr *rsp;
	struct target_cmnd *tcmnd;

	cmnd = iscsi_cmnd_create_rsp_cmnd(scsi_cmnd);
	if (!cmnd)
		return NULL;

	req = (struct iscsi_scsi_cmd_hdr *)&scsi_cmnd->pdu.bhs;
	rsp = (struct iscsi_scsi_rsp_hdr *)&cmnd->pdu.bhs;
	rsp->opcode = ISCSI_OP_SCSI_RSP;
	rsp->flags = ISCSI_FLG_FINAL;
	rsp->response = ISCSI_RESPONSE_COMMAND_COMPLETED;
	rsp->cmd_status = GOOD << STATUS_SHIFT;
	rsp->itt = req->itt;

	tcmnd = scsi_cmnd->data;
	if (tcmnd && !tcmnd->pg_cnt) {
		cmnd->data = scsi_cmnd->data;
		scsi_cmnd->data = NULL;
	}

	return cmnd;
}

/**
 * Create a iscsi response command for a scsi command with CHECK_CONDITION status.
 *
 * iscsi_cmnd_sense_rsp
 * @scsi_cmnd: ptr to scsi command
 * @sense_key: sense key
 * @asc:
 * @ascq:
 *
 * @return    ptr to scsi response or NULL
 */

struct iscsi_cmnd *iscsi_cmnd_sense_rsp(struct iscsi_cmnd *scsi_cmnd, u8 sense_key, u8 asc, u8 ascq)
{
	struct iscsi_cmnd *cmnd;
	struct iscsi_scsi_cmd_hdr *req;
	struct iscsi_scsi_rsp_hdr *rsp;
	struct target_cmnd *tcmnd;
	struct iscsi_sense_data *sense;

	cmnd = iscsi_cmnd_create_rsp_cmnd(scsi_cmnd);
	if (!cmnd)
		return NULL;

	req = (struct iscsi_scsi_cmd_hdr *)&scsi_cmnd->pdu.bhs;
	rsp = (struct iscsi_scsi_rsp_hdr *)&cmnd->pdu.bhs;
	rsp->opcode = ISCSI_OP_SCSI_RSP;
	rsp->flags = ISCSI_FLG_FINAL;
	rsp->response = ISCSI_RESPONSE_COMMAND_COMPLETED;
	rsp->cmd_status = CHECK_CONDITION << STATUS_SHIFT;
	rsp->itt = req->itt;

	tcmnd = scsi_cmnd->data;
	if (tcmnd && !tcmnd->pg_cnt) {
		cmnd->data = scsi_cmnd->data;
		scsi_cmnd->data = NULL;
	} else
		tcmnd = cmnd->data = target_cmnd_create();

	sense = (struct iscsi_sense_data *)tcmnd->u.data;
	sense->length = cpu_to_be16(14);
	memset(sense->data, 0, 14);
	sense->data[0] = 0xf0;
	sense->data[2] = sense_key;
	sense->data[7] = 6;	// Additional sense length
	sense->data[12] = asc;
	sense->data[13] = ascq;

	cmnd->pdu.datasize = sizeof(struct iscsi_sense_data) + 14;

	return cmnd;
}

/**
 * Ignore data for this command.
 * Called from iscsi_cmnd_start_read.
 *
 * iscsi_cmnd_skip_pdu - 
 * @cmnd: ptr to command
 */

void iscsi_cmnd_skip_pdu(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct target_cmnd *tcmnd = cmnd->data;
	void *data;
	u32 size;
	int i;

	size = cmnd->pdu.datasize;
	if (size) {
		if (!tcmnd)
			tcmnd = cmnd->data = target_cmnd_create();

		target_alloc_pages(tcmnd, 1);
		data = kmap(tcmnd->u.pg.io_pages[0]);
		size = (size + 3) & -4;
		conn->read_size = size;
		for (i = 0; size > PAGE_CACHE_SIZE; i++, size -= PAGE_CACHE_SIZE) {
			conn->read_iov[i].iov_base = data;
			conn->read_iov[i].iov_len = PAGE_CACHE_SIZE;
			//if (i >= MAX_IOV)...
		}
		conn->read_iov[i].iov_base = data;
		conn->read_iov[i].iov_len = size;
		conn->read_msg.msg_iov = conn->read_iov;
		conn->read_msg.msg_iovlen = ++i;
	}
}

/**
 * Ignore any scsi data and initialize the scsi response.
 * Can only be called after iscsi_cmnd_scsi_rsp or iscsi_cmnd_sense_rsp.
 *
 * iscsi_cmnd_ignore_data
 * @scsi_cmnd: ptr to scsi command
 */

void iscsi_cmnd_ignore_data(struct iscsi_cmnd *scsi_cmnd)
{
	struct iscsi_cmnd *rsp_cmnd;
	struct iscsi_scsi_cmd_hdr *req;
	struct iscsi_scsi_rsp_hdr *rsp;
	u32 size;

	rsp_cmnd = iscsi_cmnd_get_rsp_cmnd(scsi_cmnd);
	rsp = (struct iscsi_scsi_rsp_hdr *)&rsp_cmnd->pdu.bhs;
	req = (struct iscsi_scsi_cmd_hdr *)&scsi_cmnd->pdu.bhs;
	if (rsp->opcode != ISCSI_OP_SCSI_RSP) {
		printk("iscsi_cmnd_ignore_data: unexpected response command %u\n", rsp->opcode);
		return;
	}

	size = iscsi_cmnd_write_size(scsi_cmnd);
	if (size) {
		rsp->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
		rsp->residual_count = cpu_to_be32(size);
	}
	size = iscsi_cmnd_read_size(scsi_cmnd);
	if (size) {
		if (req->flags & ISCSI_CMD_WRITE) {
			rsp->flags |= ISCSI_FLG_BIRESIDUAL_UNDERFLOW;
			rsp->bi_residual_count = cpu_to_be32(size);
		} else {
			rsp->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
			rsp->residual_count = cpu_to_be32(size);
		}
	}
	scsi_cmnd->pdu.bhs.opcode = (scsi_cmnd->pdu.bhs.opcode & ~ISCSI_OPCODE_MASK) | ISCSI_OP_SCSI_REJECT;

	iscsi_cmnd_skip_pdu(scsi_cmnd);
}

/**
 * Prepare the data of iscsi command to be sent.
 * cmnd->data points to a valid target command and is used to create data responses.
 *
 * iscsi_cmnd_prepare_send
 * @cmnd: ptr to command
 */

void iscsi_cmnd_prepare_send(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	struct iscsi_cmnd *data_cmnd;
	struct target_cmnd *tcmnd = cmnd->data;
	struct iscsi_scsi_cmd_hdr *req = (struct iscsi_scsi_cmd_hdr *)&cmnd->pdu.bhs;
	struct iscsi_data_in_hdr *rsp;
	u32 pdusize, expsize, scsisize, size, offset, sn;

	dprintk(D_GENERIC, "iscsi_cmnd_prepare_send: %p\n", cmnd);
	IE1(IE_CMND_PREPARE_SEND, cmnd);
	pdusize = conn->session->param.max_data_pdu_length;
	expsize = iscsi_cmnd_read_size(cmnd);
	size = min(expsize, tcmnd->u.pg.size);
	offset = 0;
	sn = 0;

	while (1) {
		data_cmnd = iscsi_cmnd_create_rsp_cmnd(cmnd);
		data_cmnd->data = tcmnd;
		rsp = (struct iscsi_data_in_hdr *)&data_cmnd->pdu.bhs;

		rsp->opcode = ISCSI_OP_SCSI_DATA_RSP;
		rsp->itt = req->itt;
		rsp->buffer_offset = offset;
		rsp->data_sn = cpu_to_be32(sn);

		if (size <= pdusize) {
			data_cmnd->pdu.datasize = size;
#if 1
			rsp->flags = ISCSI_FLG_FINAL | ISCSI_FLG_STATUS;

			scsisize = tcmnd->u.pg.size;
			if (scsisize < expsize) {
				rsp->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
				size = expsize - scsisize;
			} else if (scsisize > expsize) {
				rsp->flags |= ISCSI_FLG_RESIDUAL_OVERFLOW;
				size = scsisize - expsize;
			}
			rsp->residual_count = cpu_to_be32(size);

			iscsi_cmnd_init_write(data_cmnd);
#else
			iscsi_cmnd_init_write(data_cmnd);
			{
				struct iscsi_cmnd *rsp_cmnd;
				struct iscsi_scsi_rsp_hdr *srsp;

				rsp_cmnd = iscsi_cmnd_scsi_rsp(cmnd);
				srsp = (struct iscsi_scsi_rsp_hdr *)&rsp_cmnd->pdu.bhs;
				scsisize = tcmnd->u.pg.size;
				if (scsisize < expsize) {
					srsp->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
					size = expsize - scsisize;
				} else if (scsisize > expsize) {
					srsp->flags |= ISCSI_FLG_RESIDUAL_OVERFLOW;
					size = scsisize - expsize;
				} else
					size = 0;
				srsp->residual_count = cpu_to_be32(size);

				iscsi_cmnd_init_write(rsp_cmnd);
			}
#endif
			return;
		}

		data_cmnd->pdu.datasize = pdusize;

		size -= pdusize;
		offset += pdusize;
		sn++;

		iscsi_cmnd_init_write(data_cmnd);
	}
}

/**
 * Initialize conn->write_* from a target command to start writing the pdu data.
 * Called from the write thread.
 *
 * iscsi_cmnd_send_pdu - 
 * @conn: ptr to connection
 * @tcmnd: ptr to target command
 * @offset: offset in target data
 * @size: size of pdu
 */

void iscsi_cmnd_send_pdu(struct iscsi_conn *conn, struct target_cmnd *tcmnd, u32 offset, u32 size)
{
	dprintk(D_GENERIC, "iscsi_cmnd_send_pdu: %p %u,%u\n", tcmnd, offset, size);
	IE1(IE_CMND_SEND_PDU, tcmnd);
	offset += tcmnd->u.pg.offset;
	while (offset >= TARGET_CMND_MAX_DATA) {
		tcmnd = tcmnd->next;
		offset -= TARGET_CMND_MAX_DATA;
	}

	conn->write_tcmnd = tcmnd;
	conn->write_offset = offset;
	conn->write_size += size;
}

/**
 * Initialize conn->read_* from a target command to start reading the pdu data.
 * Called from the read thread.
 *
 * iscsi_cmnd_receive_pdu - 
 * @conn: ptr to connection
 * @tcmnd: ptr to target command
 * @offset: offset in target data
 * @size: size of pdu
 */

void iscsi_cmnd_receive_pdu(struct iscsi_conn *conn, struct target_cmnd *tcmnd, u32 offset, u32 size)
{
	int idx, i;

	dprintk(D_GENERIC, "iscsi_cmnd_receive_pdu: %p %u,%u\n", tcmnd, offset, size);
	IE1(IE_CMND_RECEIVE_PDU, tcmnd);
	offset += tcmnd->u.pg.offset;
	while (offset >= TARGET_CMND_MAX_DATA) {
		tcmnd = tcmnd->next;
		offset -= TARGET_CMND_MAX_DATA;
	}

	idx = offset >> PAGE_CACHE_SHIFT;
	offset &= ~PAGE_CACHE_MASK;

	conn->read_msg.msg_iov = conn->read_iov;
	conn->read_size = (size + 3) & -4;
	conn->read_overflow = 0;

	i = 0;
	while (1) {
		conn->read_iov[i].iov_base = kmap(tcmnd->u.pg.io_pages[idx]) + offset;
		if (offset + size <= PAGE_CACHE_SIZE) {
			conn->read_iov[i].iov_len = size;
			conn->read_msg.msg_iovlen = ++i;
			break;
		}
		conn->read_iov[i].iov_len = PAGE_CACHE_SIZE - offset;
		size -= conn->read_iov[i].iov_len;
		offset = 0;
		if (++i >= ISCSI_CONN_IOV_MAX) {
			conn->read_msg.msg_iovlen = i;
			conn->read_overflow = size;
			conn->read_size -= size;
			break;
		}
		if (++idx >= TARGET_CMND_MAX_PAGES) {
			tcmnd = tcmnd->next;
			idx = 0;
		}
	}
}

/**
 * unmap the pdu data after receive.
 *
 * iscsi_cmnd_unmap_pdu - 
 * @conn: ptr to connection
 * @tcmnd: ptr to target command
 * @offset: offset in target data
 * @size: size of pdu.
 */

void iscsi_cmnd_unmap_pdu(struct iscsi_conn *conn, struct target_cmnd *tcmnd, u32 offset, u32 size)
{
	int idx;

	dprintk(D_GENERIC, "iscsi_cmnd_unmap_pdu: %p %u,%u\n", tcmnd, offset, size);
	IE1(IE_CMND_UNMAP_PDU, tcmnd);
	offset += tcmnd->u.pg.offset;
	while (offset >= TARGET_CMND_MAX_DATA) {
		tcmnd = tcmnd->next;
		offset -= TARGET_CMND_MAX_DATA;
	}

	idx = offset >> PAGE_CACHE_SHIFT;
	offset &= ~PAGE_CACHE_MASK;

	while (1) {
		SetPageDirty(tcmnd->u.pg.io_pages[idx]);
		kunmap(tcmnd->u.pg.io_pages[idx]);
		if (offset + size <= PAGE_CACHE_SIZE)
			break;
		size -= PAGE_CACHE_SIZE - offset;
		offset = 0;
		if (++idx >= TARGET_CMND_MAX_PAGES) {
			tcmnd = tcmnd->next;
			idx = 0;
		}
	}
}

/**
 * Set StatSn, ExpSn and MaxSn for outgoing iscsi commands.
 *
 * iscsi_cmnd_set_sn
 * @cmnd: ptr to command
 * @set_stat_sn: != 0, to also set StatSn
 */

void iscsi_cmnd_set_sn(struct iscsi_cmnd *cmnd, int set_stat_sn)
{
	struct iscsi_conn *conn = cmnd->conn;

	if (set_stat_sn)
		cmnd->pdu.bhs.sn = cpu_to_be32(conn->stat_sn++);
	cmnd->pdu.bhs.exp_sn = cpu_to_be32(conn->session->exp_cmd_sn);
	//cmnd->pdu.bhs.max_sn = cpu_to_be32(conn->session->max_cmd_sn);
	cmnd->pdu.bhs.max_sn = cpu_to_be32(conn->session->exp_cmd_sn + 32);
}

/**
 * Extract the expected write length of a scsi command.
 *
 * iscsi_cmnd_write_size - 
 * @cmnd: ptr to command
 *
 * @return    write size
 */

u32 iscsi_cmnd_write_size(struct iscsi_cmnd *cmnd)
{
	struct iscsi_scsi_cmd_hdr *hdr = (struct iscsi_scsi_cmd_hdr *)&cmnd->pdu.bhs;

	if (hdr->flags & ISCSI_CMD_WRITE)
		return be32_to_cpu(hdr->data_length);
	return 0;
}

/**
 * Extract the expected read length of a scsi command.
 *
 * iscsi_cmnd_read_size - 
 * @cmnd: ptr to command
 *
 * @return    read size
 */

u32 iscsi_cmnd_read_size(struct iscsi_cmnd *cmnd)
{
	struct iscsi_scsi_cmd_hdr *hdr = (struct iscsi_scsi_cmd_hdr *)&cmnd->pdu.bhs;

	if (hdr->flags & ISCSI_CMD_READ) {
		if (!(hdr->flags & ISCSI_CMD_WRITE))
			return be32_to_cpu(hdr->data_length);
		if (hdr->flags & ISCSI_CMD_READ) {
			struct iscsi_rlength_ahdr *ahdr = (struct iscsi_rlength_ahdr *)cmnd->pdu.ahs;
			if (ahdr && ahdr->ahstype == ISCSI_AHSTYPE_RLENGTH)
				return be32_to_cpu(ahdr->read_length);
		}
	}
	return 0;
}

static void iscsi_dump_char(int ch)
{
	static unsigned char text[16];
	static int i = 0;

	if (ch < 0) {
		while ((i % 16) != 0) {
			dprintk(D_DUMP_PDU, "   ");
			text[i] = ' ';
			i++;
			if ((i % 16) == 0)
				dprintk(D_DUMP_PDU, " | %.16s |\n", text);
			else if ((i % 4) == 0)
				dprintk(D_DUMP_PDU, " |");
		}
		i = 0;
		return;
	}

	text[i] = (ch < 0x20 || (ch >= 0x80 && ch <= 0xa0)) ? ' ' : ch;
	dprintk(D_DUMP_PDU, " %02x", ch);
	i++;
	if ((i % 16) == 0) {
		dprintk(D_DUMP_PDU, " | %.16s |\n", text);
		i = 0;
	} else if ((i % 4) == 0)
		dprintk(D_DUMP_PDU, " |");
}

void iscsi_dump_pdu(struct iscsi_pdu *pdu)
{
	unsigned char *buf;
	int i;

	buf = (void *)&pdu->bhs;
	dprintk(D_DUMP_PDU, "BHS: (%p,%d)\n", buf, sizeof(pdu->bhs));
	for (i = 0; i < sizeof(pdu->bhs); i++)
		iscsi_dump_char(*buf++);
	iscsi_dump_char(-1);

	buf = (void *)pdu->ahs;
	dprintk(D_DUMP_PDU, "AHS: (%p,%d)\n", buf, pdu->ahssize);
	for (i = 0; i < pdu->ahssize; i++)
		iscsi_dump_char(*buf++);
	iscsi_dump_char(-1);

	dprintk(D_DUMP_PDU, "Data: (%d)\n", pdu->datasize);
}

/*****************************************************************************/
/*                                    QUEUE                                  */
/*****************************************************************************/

/**
 * Check whether the scsi command will be executed immediatly or whether.
 * NOTE that this no guarentee and the queuestate might change.
 *
 * iscsi_scsi_queuestate - 
 * @cmnd: ptr to command
 *
 * @return    1 if executed immediately, otherwise 0
 */

int iscsi_scsi_queuestate(struct iscsi_cmnd *cmnd)
{
	struct iscsi_queue *queue = &cmnd->lun->queue;

	if (cmnd->state != ISCSI_STATE_READ)
		printk("iscsi_cmnd_queuestate: unexpected state %d\n", cmnd->state);

	switch (cmnd->pdu.bhs.flags & ISCSI_CMD_ATTR_MASK) {
	case ISCSI_CMD_UNTAGGED:
	case ISCSI_CMD_SIMPLE:
		return list_empty(&queue->wait_list) && !queue->ordered_cmnd;
	case ISCSI_CMD_ORDERED:
		return queue->active_cnt == 0;
	case ISCSI_CMD_HEAD_OF_QUEUE:
	case ISCSI_CMD_ACA:
		return 1;
	}

	//reject?
	return 0;
}

/**
 * Queue scsi command for execution.
 *
 * iscsi_scsi_queuecmnd - 
 * @cmnd: ptr to command
 */

void iscsi_scsi_queuecmnd(struct iscsi_cmnd *cmnd)
{
	struct iscsi_queue *queue = &cmnd->lun->queue;
	struct iscsi_conn *conn = cmnd->conn;
	struct iscsi_cmnd *cmnd2;

	dprintk(D_GENERIC, "iscsi_cmnd_queue: %p\n", cmnd);
	IE1(IE_SCSI_QUEUE, cmnd);

	spin_lock(&queue->queue_lock);
	switch (cmnd->pdu.bhs.flags & ISCSI_CMD_ATTR_MASK) {
	default:
		//reject?
	case ISCSI_CMD_UNTAGGED:
	case ISCSI_CMD_SIMPLE:
		if (!list_empty(&queue->wait_list) || queue->ordered_cmnd)
			goto pending;
		queue->active_cnt++;
		break;
	case ISCSI_CMD_ORDERED:
		if (queue->active_cnt)
			goto pending;
		queue->ordered_cmnd = cmnd;
		break;
	case ISCSI_CMD_HEAD_OF_QUEUE:
	case ISCSI_CMD_ACA:
		cmnd2 = iscsi_cmnd_create(conn);
		//if (!cmnd2)
		//	reject;
		cmnd2->data = cmnd;
		cmnd2->state = ISCSI_STATE_HOQ_MARKER;
		list_add_tail(&cmnd2->list, &queue->wait_list);
		cmnd2->pdu.bhs.flags = cmnd->pdu.bhs.flags;
		break;
	}
	spin_unlock(&queue->queue_lock);

	iscsi_device_queue_cmnd(cmnd);
	return;
 pending:
	if (!list_empty(&cmnd->list))
		BUG();
	list_add_tail(&cmnd->list, &queue->wait_list);
	cmnd->state = ISCSI_STATE_PENDING;
	spin_unlock(&queue->queue_lock);
	return;
}

/**
 * Dequeue a scsi command.
 * If other scsi commands were block by this one, they are now send now to the device.
 *
 * iscsi_scsi_dequeuecmnd - 
 * @cmnd: ptr to command
 */

void iscsi_scsi_dequeuecmnd(struct iscsi_cmnd *cmnd)
{
	struct iscsi_queue *queue;
	struct iscsi_cmnd *cmnd2;
	struct list_head *entry;

	if (!cmnd->lun)
		return;
	queue = &cmnd->lun->queue;
	switch (cmnd->pdu.bhs.flags & ISCSI_CMD_ATTR_MASK) {
	case ISCSI_CMD_UNTAGGED:
	case ISCSI_CMD_SIMPLE:
		--queue->active_cnt;
		break;
	case ISCSI_CMD_ORDERED:
		if (queue->ordered_cmnd != cmnd)
			printk("iscsi_cmnd_dequeue: unexpected ordered cmnd %p,%p\n", queue->ordered_cmnd, cmnd);
		queue->ordered_cmnd = NULL;
		break;
	case ISCSI_CMD_HEAD_OF_QUEUE:
	case ISCSI_CMD_ACA:
		if (list_empty(&queue->wait_list))
			panic("oops");
		cmnd2 = list_entry(queue->wait_list.next, struct iscsi_cmnd, list);
		if (cmnd == cmnd2->data) {
			list_del_init(&cmnd2->list);
			iscsi_cmnd_remove(cmnd);
			if (queue->ordered_cmnd)
				goto out;
		} else {
			list_for_each(entry, &queue->wait_list) {
				cmnd2 = list_entry(entry, struct iscsi_cmnd, list);
				if (cmnd == cmnd2->data) {
					if (entry != queue->wait_list.next || queue->ordered_cmnd) {
						list_del_init(&cmnd2->list);
						iscsi_cmnd_remove(cmnd);
						goto out;
					}
					list_del_init(&cmnd2->list);
					iscsi_cmnd_remove(cmnd);
				}
			}
		}
		break;
	}

	while (!list_empty(&queue->wait_list)) {
		cmnd2 = list_entry(queue->wait_list.next, struct iscsi_cmnd, list);
		switch ((cmnd->pdu.bhs.flags & ISCSI_CMD_ATTR_MASK)) {
		case ISCSI_CMD_UNTAGGED:
		case ISCSI_CMD_SIMPLE:
			list_del_init(&cmnd->list);
			queue->active_cnt++;
			iscsi_device_queue_cmnd(cmnd);
			break;
		case ISCSI_CMD_ORDERED:
			if (!queue->active_cnt) {
				list_del_init(&cmnd->list);
				queue->ordered_cmnd = cmnd;
				iscsi_device_queue_cmnd(cmnd);
			}
			goto out;
		case ISCSI_CMD_HEAD_OF_QUEUE:
		case ISCSI_CMD_ACA:
			goto out;
		}
	}
 out:
	return;
}

/**
 * Execute a scsi command.
 *
 * iscsi_scsi_execute - 
 * @cmnd: ptr to command
 */

void iscsi_scsi_execute(struct iscsi_cmnd *cmnd)
{
	struct iscsi_scsi_cmd_hdr *req = (struct iscsi_scsi_cmd_hdr *)&cmnd->pdu.bhs;
	struct target_device *dev = NULL;
	struct target_cmnd *tcmnd = cmnd->data;
	loff_t offset;
	u32 size;

	IE1(IE_SCSI_EXECUTE, cmnd);
	if (!(cmnd->pdu.bhs.flags & ISCSI_CMD_FINAL)) {
		cmnd->state = ISCSI_STATE_WAIT_RECEIVE;
		//list_add_tail(&cmnd->list, &conn->wait_list);
		return;
	}
	req->opcode &= ISCSI_OPCODE_MASK;
	trace_std_formatted_event(trace_execute_scsi, req->scb[0]);

	if (cmnd->lun)
		dev = cmnd->lun->device;

	switch (req->scb[0]) {
	case INQUIRY:
	{
		u8 *data;

		target_alloc_pages(tcmnd, 1);
		// move this?
		data = kmap(tcmnd->u.pg.io_pages[0]);
		memset(data, 0, 36);
		if (!dev)
			data[0] = 0x7f;
		data[2] = 3;
		data[3] = 0x42;
		data[4] = 31;
		data[7] = 0x02;
		memcpy(data + 8, "LINUX   ", 8);
		memcpy(data + 16, "ISCSI           ", 16);
		memcpy(data + 32, "0   ", 4);
		kunmap(tcmnd->u.pg.io_pages[0]);

		tcmnd->u.pg.offset = 0;
		tcmnd->u.pg.size = 36;

		iscsi_cmnd_prepare_send(cmnd);
		break;
	}
	case REPORT_LUNS:
	{
		u32 *data, size, len;
		struct iscsi_lun *lun;

		size = be32_to_cpu(*(u32 *)&req->scb[6]);
		if (size < 16) {
			iscsi_cmnd_init_write(iscsi_cmnd_sense_rsp(cmnd, ILLEGAL_REQUEST, 0x24, 0x0));
			return;
		}
		len = 8 + cmnd->conn->session->target->lun_cnt * 8;
		target_alloc_pages(tcmnd, len / PAGE_SIZE + 1);
		data = kmap(tcmnd->u.pg.io_pages[0]);
		*data++ = cpu_to_be32(len);
		*data++ = 0;
		list_for_each_entry(lun, &cmnd->conn->session->target->lun_list, list) {
			*data++ = cpu_to_be32(lun->lun << 16);
			*data++ = 0;
		}
		kunmap(tcmnd->u.pg.io_pages[0]);

		tcmnd->u.pg.offset = 0;
		tcmnd->u.pg.size = len;

		iscsi_cmnd_prepare_send(cmnd);
		break;
	}
	case START_STOP:
	{
		struct iscsi_cmnd *rsp_cmnd;
		struct iscsi_scsi_rsp_hdr *rsp;

		rsp_cmnd = iscsi_cmnd_scsi_rsp(cmnd);
		rsp = (struct iscsi_scsi_rsp_hdr *)&rsp_cmnd->pdu.bhs;

		size = iscsi_cmnd_read_size(cmnd);
		if (size) {
			rsp->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
			rsp->residual_count = cpu_to_be32(size);
		}

		iscsi_cmnd_init_write(rsp_cmnd);
		break;
	}
	case READ_CAPACITY:
	{
		u32 *data;

		target_alloc_pages(tcmnd, 1);
		// move this?
		data = kmap(tcmnd->u.pg.io_pages[0]);
		data[0] = cpu_to_be32(dev->blk_cnt - 1);
		data[1] = cpu_to_be32(1 << dev->blk_shift);
		kunmap(tcmnd->u.pg.io_pages[0]);

		tcmnd->u.pg.offset = 0;
		tcmnd->u.pg.size = 8;

		iscsi_cmnd_prepare_send(cmnd);
		break;
	}
	case MODE_SENSE:
	{
		u8 *data;
		int len = 4;

		switch (req->scb[2] & 0x3f) {
		case 0:
		case 0x3f:
			break;
		default:
			iscsi_cmnd_init_write(iscsi_cmnd_sense_rsp(cmnd, ILLEGAL_REQUEST, 0x24, 0x0));
			return;
		}
		target_alloc_pages(tcmnd, 1);
		data = kmap(tcmnd->u.pg.io_pages[0]);
		data[1] = 0;
		data[2] = 0; /* 0x80 for WP */
		if (!(req->scb[1] & 4)) {
			data[3] = 8;
			len += 8;
			*(u32 *)(data + 4) = cpu_to_be32(dev->blk_cnt);
			*(u32 *)(data + 8) = cpu_to_be32(1 << dev->blk_shift);
		} else
			data[3] = 0;
		data[0] = len;
		kunmap(tcmnd->u.pg.io_pages[0]);
		tcmnd->u.pg.offset = 0;
		tcmnd->u.pg.size = len;

		iscsi_cmnd_prepare_send(cmnd);
		break;
	}
	case READ_6:
		offset = ((req->scb[1] & 0x1f) << 16) +
			 (req->scb[2] << 8) +
			 req->scb[3];
		size = req->scb[4];
		if (!size)
			size = 256;
		goto do_read;
	case READ_10:
		offset = be32_to_cpu(*(u32 *)&req->scb[2]);
		size = (req->scb[7] << 8) + req->scb[8];
		//if (!size) send rsp;
	do_read:
		target_init_read(dev, tcmnd, offset << dev->blk_shift, size << dev->blk_shift);
		if (target_get_read_pages(dev, tcmnd)) {
			cmnd->state = ISCSI_STATE_START_READ;
			if (!list_empty(&cmnd->list))
				BUG();
			list_add_tail(&cmnd->list, &dev->io_list);
			break;
		}
		if (target_wait_pages(dev, tcmnd)) {
			cmnd->state = ISCSI_STATE_WAIT_READ;
			if (!list_empty(&cmnd->list))
				BUG();
			list_add_tail(&cmnd->list, &dev->io_list);
			break;
		}
		iscsi_cmnd_prepare_send(cmnd);
		break;
	case WRITE_6:
	case WRITE_10:
	{
		struct iscsi_cmnd *rsp_cmnd;
		u32 length;

		if (!(req->flags & ISCSI_CMD_FINAL)) {
			printk("warning nonfinal cmnd %p executed!\n", cmnd);
			break;
		}

		if (target_get_write_pages(dev, tcmnd)) {
			cmnd->state = ISCSI_STATE_WAIT_WRITE_PAGES;
			if (!list_empty(&cmnd->list))
				BUG();
			list_add(&cmnd->list, &dev->io_list);
		}

		length = be32_to_cpu(req->data_length) - cmnd->pdu.datasize;
		if (length) {
			struct iscsi_r2t_hdr *rsp;
			struct list_head *entry;
			u32 offset, burst;
			int sn = 0;

			burst = cmnd->conn->session->param.max_burst_length;
			offset = cmnd->pdu.datasize;
			do {
				rsp_cmnd = iscsi_cmnd_create_rsp_cmnd(cmnd);
				iscsi_session_insert_ttt(rsp_cmnd);
				rsp_cmnd->data = cmnd;

				rsp = (struct iscsi_r2t_hdr *)&rsp_cmnd->pdu.bhs;
				rsp->opcode = ISCSI_OP_RTT_RSP;
				rsp->flags = ISCSI_FLG_FINAL;
				rsp->itt = req->itt;
				rsp->r2t_sn = cpu_to_be32(sn++);
				rsp->buffer_offset = cpu_to_be32(offset);
				if (length > burst) {
					rsp->data_length = cpu_to_be32(burst);
					length -= burst;
					offset += burst;
				} else {
					rsp->data_length = cpu_to_be32(length);
					length = 0;
				}
			} while (length);

			if (cmnd->state != ISCSI_STATE_WAIT_WRITE_PAGES) {
				cmnd->state = ISCSI_STATE_SEND_RTT;
				list_for_each(entry, &cmnd->pdu_list) {
					rsp_cmnd = list_entry(entry, struct iscsi_cmnd, pdu_list);
					iscsi_cmnd_init_write(rsp_cmnd);
				}
			}
		} else {
			struct iscsi_scsi_rsp_hdr *rsp;
			u32 size;

			rsp_cmnd = iscsi_cmnd_scsi_rsp(cmnd);
			rsp = (struct iscsi_scsi_rsp_hdr *)&rsp_cmnd->pdu.bhs;

			// NOTE code duplication...
			list_del_init(&cmnd->list);
			size = iscsi_cmnd_read_size(cmnd);
			if (size) {
				rsp->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
				rsp->residual_count = cpu_to_be32(size);
			}

			dev = cmnd->lun->device;
			if (cmnd->state == ISCSI_STATE_WAIT_WRITE_PAGES)
				;
			else if (target_commit_pages(dev, cmnd->data)) {
				cmnd->state = ISCSI_STATE_WAIT_COMMIT;
				if (!list_empty(&cmnd->list))
					BUG();
				list_add_tail(&cmnd->list, &dev->io_list);
			} else if (target_sync_pages(dev, cmnd->data)) {
				cmnd->state = ISCSI_STATE_WAIT_WRITE;
				if (!list_empty(&cmnd->list))
					BUG();
				list_add_tail(&cmnd->list, &dev->io_list);
			} else {
				iscsi_cmnd_init_write(rsp_cmnd);
				cmnd->state = ISCSI_STATE_SEND_RSP;
				//list_add_tail(&cmnd->list, &conn->wait_list);
			}
		}

		break;
	}
	case TEST_UNIT_READY:
	case VERIFY:
	{
		struct iscsi_cmnd *rsp_cmnd;
		struct iscsi_scsi_rsp_hdr *rsp;
		u32 size;

		rsp_cmnd = iscsi_cmnd_scsi_rsp(cmnd);
		rsp = (struct iscsi_scsi_rsp_hdr *)&rsp_cmnd->pdu.bhs;

		size = iscsi_cmnd_read_size(cmnd);
		if (size) {
			rsp->flags |= ISCSI_FLG_RESIDUAL_UNDERFLOW;
			rsp->residual_count = cpu_to_be32(size);
		}

		iscsi_cmnd_init_write(rsp_cmnd);
		break;
	}
	default:
		//panic?
		break;
	}
}


/*****************************************************************************/
/*                                   DEVICE                                  */
/*****************************************************************************/

/**
 * Create a new scsi device.
 *
 * iscsi_device_create - 
 * @id: id of device
 * @name: path to device or file name
 *
 * @return    -errno
 */

int iscsi_device_create(u32 id, const char *name)
{
	struct target_device *dev = NULL;
	struct file *file;
	struct inode *inode;
	mm_segment_t fs = get_fs();
	int err, tid;

	dprintk(D_SETUP, "iscsi_device_create: %u %s\n", id, name);
	set_fs(KERNEL_DS);
	file = filp_open(name, O_RDWR|O_LARGEFILE, 0);
	set_fs(fs);
	if (IS_ERR(file))
		return PTR_ERR(file);

	inode = file->f_dentry->d_inode;
	if (S_ISBLK(inode->i_mode)) {
		dev = target_bdev_attach(file);
	} else {
		err = -EINVAL;
		goto err;
	}

	if (!dev) {
		err = -ENODEV;
		goto err;
	}

	spin_lock_init(&dev->ready_list_lock);
	INIT_LIST_HEAD(&dev->ready_list);
	init_MUTEX(&dev->io_sem);
	INIT_LIST_HEAD(&dev->io_list);
	init_waitqueue_head(&dev->thread_wait);
	dev->id = id;
	dev->file = file;

	list_add(&dev->list, &target_device_list);

	tid = kernel_thread(iscsi_device_thread, dev, CLONE_FS | CLONE_FILES);
	if (tid < 0)
		err = tid;
	wait_event(dev->thread_wait, dev->poll_flags & POLL_INITIALIZED);

	iscsi_device_proc_init(dev);

	return 0;

 err:
	filp_close(file, NULL);
	return err;
}

/**
 * Remove a device.
 *
 * iscsi_device_remove - 
 * @dev: ptr to device
 *
 * @return    -errno
 */

int iscsi_device_remove(struct target_device *dev)
{
	struct file *file;
	struct inode *inode;

	dprintk(D_SETUP, "iscsi_device_remove: %u\n", dev->id);
	if (dev->usage)
		return -EBUSY;

	iscsi_device_proc_exit(dev);

	dev->poll_flags |= POLL_EXIT;
	wake_up(&dev->thread_wait);
	wait_event(dev->thread_wait, !(dev->poll_flags & POLL_EXIT));

	list_del(&dev->list);

	file = dev->file;
	inode = file->f_dentry->d_inode;
	if (S_ISBLK(inode->i_mode)) {
		target_bdev_detach(dev);
	}

	filp_close(file, NULL);

	return 0;
}

/**
 * Link a device to a target.
 * After this the device is available from the target under the specified lun id.
 *
 * iscsi_device_attach - 
 * @target: ptr to target
 * @dev: ptr to target
 * @id: lun id
 *
 * @return    -errno
 */

int iscsi_device_attach(struct iscsi_target *target, struct target_device *dev, u32 id)
{
	struct iscsi_lun *lun;

	dprintk(D_SETUP, "iscsi_device_attach: %u %u %u\n", target->target.id, dev->id, id);
	lun = kmalloc(sizeof(*lun), GFP_KERNEL);
	if (!lun)
		return -ENOMEM;
	memset(lun, 0, sizeof(*lun));

	lun->target = target;
	lun->lun = id;
	lun->device = dev;
	dev->usage++;

	// -> iscsi_queue_init?
	INIT_LIST_HEAD(&lun->queue.wait_list);
	spin_lock_init(&lun->queue.queue_lock);

	list_add_tail(&lun->list, &target->lun_list);
	target->lun_cnt++;

	iscsi_lun_proc_init(lun);

	return 0;
}

/**
 * Detach a device from a target.
 *
 * iscsi_device_detach - 
 * @lun: ptr to lun
 *
 * @return    -errno
 */

int iscsi_device_detach(struct iscsi_lun *lun)
{
	dprintk(D_SETUP, "iscsi_device_detach: %u\n", lun->lun);
	iscsi_lun_proc_exit(lun);

	lun->device->usage--;
	list_del(&lun->list);
	lun->target->lun_cnt--;

	kfree(lun);

	return 0;
}

/**
 * Lookup a device by id.
 *
 * iscsi_device_lookup_devid - 
 * @id: id of device
 *
 * @return    ptr to device
 */

struct target_device *iscsi_device_lookup_devid(u32 id)
{
	struct list_head *entry;
	struct target_device *dev;

	list_for_each(entry, &target_device_list) {
		dev = list_entry(entry, struct target_device, list);
		if (dev->id == id)
			return dev;
	}

	return NULL;
}

/**
 * Insert a scsi command into device queue for immediate execution.
 *
 * iscsi_device_queue_cmnd - 
 * @cmnd: ptr to command
 */

void iscsi_device_queue_cmnd(struct iscsi_cmnd *cmnd)
{
	struct target_device *dev = cmnd->lun->device;

	spin_lock(&dev->ready_list_lock);
	cmnd->state = ISCSI_STATE_QUEUED;
	if (!list_empty(&cmnd->list))
		BUG();
	list_add_tail(&cmnd->list, &dev->ready_list);
	spin_unlock(&dev->ready_list_lock);
	wake_up_process(cmnd->lun->device->dev_thread);
}

/**
 * Device thread.
 * Handles all communication to the device.
 *
 * iscsi_device_thread - 
 * @arg: ptr to device
 *
 * @return    ignored
 */

static int iscsi_device_thread(void *arg)
{
	struct target_device *dev = arg;
	struct list_head *io_entry;
	struct iscsi_cmnd *cmnd;
	struct target_cmnd *tcmnd;
	DECLARE_WAITQUEUE(wq, current);

	daemonize();
	reparent_to_init();

	/* block signals */
	siginitsetinv(&current->blocked, 0);

	/* Set the name of this process. */
	sprintf(current->comm, "idevice%d", dev->id);

	dev->dev_thread = current;

	dprintk(D_THREAD, "dev_thread(%u): initialized\n", dev->id);
	dev->poll_flags = POLL_INITIALIZED;
	wake_up(&dev->thread_wait);

	add_wait_queue(&dev->thread_wait, &wq);

	while (!(dev->poll_flags & POLL_EXIT)) {
		IE1(IE_DEV_LOOP, NULL);
		dprintk(D_THREAD, "iscsi_device_thread(%u): wakeup\n", dev->id);
		down(&dev->io_sem);
		set_current_state(TASK_INTERRUPTIBLE);

		for (io_entry = dev->io_list.next; io_entry != &dev->io_list;) {
			cmnd = list_entry(io_entry, struct iscsi_cmnd, list);
			tcmnd = cmnd->data;

			io_entry = cmnd->list.next;
			switch (cmnd->state) {
			case ISCSI_STATE_START_READ:
				if (target_get_read_pages(dev, tcmnd))
					break;
				cmnd->state = ISCSI_STATE_WAIT_READ;
			case ISCSI_STATE_WAIT_READ:
				if (target_wait_pages(dev, tcmnd))
					break;
				list_del_init(&cmnd->list);
				iscsi_cmnd_prepare_send(cmnd);
				break;
			case ISCSI_STATE_WAIT_WRITE_PAGES:
				if (target_get_write_pages(dev, tcmnd))
					break;

				if (cmnd->pdu.bhs.opcode != ISCSI_OP_SCSI_ABORT &&
				    !list_empty(&cmnd->pdu_list)) {
					struct iscsi_cmnd *r2t_cmnd;
					struct list_head *entry;

					list_del_init(&cmnd->list);
					cmnd->state = ISCSI_STATE_SEND_RTT;
					list_for_each(entry, &cmnd->pdu_list) {
						r2t_cmnd = list_entry(entry, struct iscsi_cmnd, pdu_list);
						iscsi_cmnd_init_write(r2t_cmnd);
					}
					break;
				}
				/* fall through */
			case ISCSI_STATE_WAIT_COMMIT:
				if (target_commit_pages(dev, tcmnd))
					break;
				cmnd->state = ISCSI_STATE_WAIT_WRITE;
			case ISCSI_STATE_WAIT_WRITE:
				if (target_sync_pages(dev, tcmnd))
					break;
				list_del_init(&cmnd->list);
				cmnd->state = ISCSI_STATE_SEND_RSP;

				if (!list_empty(&cmnd->pdu_list))
					iscsi_cmnd_init_write(iscsi_cmnd_get_rsp_cmnd(cmnd));
				else {
					cmnd->pdu.bhs.opcode = ISCSI_OP_SCSI_ABORT;
					iscsi_cmnd_release(cmnd);
				}
				break;
			default:
				printk("unknown state %d\n", cmnd->state);
				list_del_init(&cmnd->list);
				break;
			}
		}
		if (!list_empty(&dev->ready_list)) {
			struct list_head list;
			spin_lock(&dev->ready_list_lock);
			list_add(&list, &dev->ready_list);
			list_del_init(&dev->ready_list);
			spin_unlock(&dev->ready_list_lock);
			while (!list_empty(&list)) {
				cmnd = list_entry(list.next, struct iscsi_cmnd, list);
				list_del_init(list.next);
				iscsi_scsi_execute(cmnd);
			}
		}

		up(&dev->io_sem);
		dprintk(D_THREAD, "iscsi_device_thread(%u): sleep\n", dev->id);
		schedule();
	}

	current->state = TASK_RUNNING;
	remove_wait_queue(&dev->thread_wait, &wq);

	dprintk(D_THREAD, "dev_thread(%u): exit\n", dev->id);
	dev->poll_flags &= ~POLL_EXIT;
	wake_up(&dev->thread_wait);

	return 0;
}

/*****************************************************************************/
/*                                   SESSION                                 */
/*****************************************************************************/

/**
 * Create a new session to a target.
 *
 * iscsi_session_create - 
 * @target: ptr to target
 * @tsid: target session id
 *
 * @return    -errno
 */

int iscsi_session_create(struct iscsi_target *target, u64 sid)
{
	struct iscsi_session *session;

	dprintk(D_SETUP, "iscsi_session_create: %u %#Lx\n", target->target.id, sid);
	session = kmalloc(sizeof(*session), GFP_KERNEL);
	if (!session)
		return -ENOMEM;
	memset(session, 0, sizeof(*session));

	session->target = target;
	session->sid = sid;
	memcpy(&session->param, &target->default_param, sizeof(session->param));
	INIT_LIST_HEAD(&session->conn_list);
	INIT_LIST_HEAD(&session->pending_list);
	spin_lock_init(&session->cmnd_tt_lock);
	session->next_ttt = 1;

	list_add(&session->list, &target->session_list);

	iscsi_session_proc_init(session);

	return 0;
}

/**
 * Remove a session.
 *
 * iscsi_session_remove - 
 * @session: ptr to session.
 *
 * @return    -errno
 */

int iscsi_session_remove(struct iscsi_session *session)
{
	struct iscsi_cmnd *cmnd;
	int i;

	dprintk(D_SETUP, "iscsi_session_remove: %#Lx\n", session->sid);

	if (!list_empty(&session->conn_list))
		return -EBUSY;

	// check for commands
	for (i = 0; i < ISCSI_TT_HASHSIZE; i++) {
		while ((cmnd = session->cmnd_itt_hash[i])) {
			printk("remove cmnd %p (%d)\n", cmnd, cmnd->state);
			iscsi_session_remove_cmnd(cmnd);
		}
	}

	list_del(&session->list);

	iscsi_session_proc_exit(session);

	kfree(session);

	return 0;
}

/**
 * Look up a connection of a session.
 *
 * iscsi_session_lookup_conn - 
 * @session: ptr to session
 * @cid: connection id
 *
 * @return    ptr to connection
 */

struct iscsi_conn *iscsi_session_lookup_conn(struct iscsi_session *session, u16 cid)
{
	struct list_head *entry;
	struct iscsi_conn *conn;

	list_for_each(entry, &session->conn_list) {
		conn = list_entry(entry, struct iscsi_conn, list);
		if (conn->cid == cid)
			return conn;
	}

	return NULL;
}

/**
 * Called as soon as the first connection is acccepted on this session.
 *
 * iscsi_session_activate - 
 * @session:
 */

void iscsi_session_activate(struct iscsi_session *session)
{
}

/**
 * Set some session defaults.
 *
 * iscsi_session_defaults - 
 * @param:
 */

static void iscsi_session_defaults(struct iscsi_param *param)
{
	param->flags = (SESSION_FLG_INITIAL_RTT | SESSION_FLG_IMMEDIATEDATA
			| SESSION_FLG_DATAPDUINORDER | SESSION_FLG_DATASEQUENCEINORDER);
	param->max_connections = 1;
	param->max_data_pdu_length = 8192;
	param->max_burst_length = 262144;
	param->first_burst_length = 65536;
	param->default_wait_time = 2;
	param->default_retain_time = 20;
	param->max_outstanding_rtt = 1;
	param->error_recovery_level = 0;
}

/**
 * Insert a command into the session.
 * After this the command is known under this ITT
 *
 * iscsi_session_insert_cmnd - 
 * @cmnd: ptr to command
 *
 * @return    1 -> command successfully accepted
 *	    otherwise 0.
 */

int iscsi_session_insert_cmnd(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;
	u32 itt = cmnd->pdu.bhs.itt;
	int hash = ISCSI_TT_HASH(itt);
	struct iscsi_cmnd *hash_cmnd;

	dprintk(D_GENERIC, "iscsi_session_insert_cmnd: %p:%x\n", cmnd, itt);
	IE1(IE_SESSION_INSERT, cmnd);
	if (itt == cpu_to_be32(ISCSI_RESERVED_TAG)) {
		iscsi_cmnd_reject(cmnd, ISCSI_REASON_PROTOCOL_ERROR);
		return 0;
	}

	spin_lock(&session->cmnd_tt_lock);
	for (hash_cmnd = session->cmnd_itt_hash[hash]; hash_cmnd;
	     hash_cmnd = hash_cmnd->hash_next) {
		if (hash_cmnd->pdu.bhs.itt == itt) {
			spin_unlock(&session->cmnd_tt_lock);
			iscsi_cmnd_reject(cmnd, ISCSI_REASON_TASK_IN_PROGRESS);
			return 0;
		}
	}
	cmnd->hash_next = session->cmnd_itt_hash[hash];
	session->cmnd_itt_hash[hash] = cmnd;
	spin_unlock(&session->cmnd_tt_lock);

	iscsi_conn_update_stat_sn(cmnd);
	return iscsi_session_check_cmd_sn(cmnd);
}

/**
 * Find a command with a specific ITT.
 * FIXME: command might be removed by the write thread.
 *
 * iscsi_session_find_cmnd - 
 * @session: ptr to session
 * @itt: ITT
 *
 * @return    ptr to command or NULL
 */

struct iscsi_cmnd *iscsi_session_find_cmnd(struct iscsi_session *session, u32 itt)
{
	struct iscsi_cmnd *cmnd;
	int hash;

	hash = ISCSI_TT_HASH(itt);
	spin_lock(&session->cmnd_tt_lock);
	for (cmnd = session->cmnd_itt_hash[hash]; cmnd; cmnd = cmnd->hash_next) {
		if (cmnd->pdu.bhs.itt == itt)
			break;
	}
	spin_unlock(&session->cmnd_tt_lock);
	return cmnd;
}

/**
 * Remove the command from the session.
 * This removes also all commands (responses) attached to this command
 *
 * iscsi_session_remove_cmnd - 
 * @cmnd: ptr to command
 */

void iscsi_session_remove_cmnd(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;
	struct iscsi_cmnd *hash_cmnd, **prev_cmnd;
	struct list_head *entry;
	int hash;

	dprintk(D_GENERIC, "iscsi_session_remove_cmnd: %p:%x\n", cmnd, cmnd->pdu.bhs.itt);
	IE1(IE_SESSION_REMOVE, cmnd);
	spin_lock(&session->cmnd_tt_lock);
	hash = ISCSI_TT_HASH(cmnd->pdu.bhs.itt);
	for (prev_cmnd = &session->cmnd_itt_hash[hash];
	     (hash_cmnd = *prev_cmnd); prev_cmnd = &hash_cmnd->hash_next) {
		if (cmnd == hash_cmnd)
			break;
	}
	if (hash_cmnd)
		*prev_cmnd = cmnd->hash_next;
	else
		printk("iscsi_session_remove_cmnd: %p:%x not found\n", cmnd, cmnd->pdu.bhs.itt);
	spin_unlock(&session->cmnd_tt_lock);

	while (!list_empty(&cmnd->pdu_list)) {
		entry = cmnd->pdu_list.next;
		list_del(entry);
		iscsi_cmnd_remove(list_entry(entry, struct iscsi_cmnd, pdu_list));
	}

	iscsi_cmnd_remove(cmnd);
}

void iscsi_session_insert_ttt(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;
	u32 ttt;
	int hash;

	spin_lock(&session->cmnd_tt_lock);
	cmnd->pdu.bhs.ttt = ttt = session->next_ttt++;
	if (!session->next_ttt) {
		cmnd->pdu.bhs.ttt = ttt = 1;
		session->next_ttt = 2;
	}
	hash = ISCSI_TT_HASH(ttt);
	cmnd->hash_next = session->cmnd_ttt_hash[hash];
	session->cmnd_ttt_hash[hash] = cmnd;
	spin_unlock(&session->cmnd_tt_lock);
	dprintk(D_GENERIC, "iscsi_session_insert_ttt: %p:%x\n", cmnd, ttt);
	IE1(IE_SESSION_INSERT_TTT, cmnd);
}

struct iscsi_cmnd *iscsi_session_find_ttt(struct iscsi_session *session, u32 ttt)
{
	struct iscsi_cmnd *cmnd;
	int hash;

	hash = ISCSI_TT_HASH(ttt);
	spin_lock(&session->cmnd_tt_lock);
	for (cmnd = session->cmnd_ttt_hash[hash]; cmnd; cmnd = cmnd->hash_next) {
		if (cmnd->pdu.bhs.ttt == ttt)
			break;
	}
	spin_unlock(&session->cmnd_tt_lock);
	return cmnd;
}

void iscsi_session_remove_ttt(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;
	struct iscsi_cmnd *hash_cmnd, **prev_cmnd;
	int hash;

	dprintk(D_GENERIC, "iscsi_session_remove_ttt: %p:%x\n", cmnd, cmnd->pdu.bhs.ttt);
	IE1(IE_SESSION_REMOVE_TTT, cmnd);
	spin_lock(&session->cmnd_tt_lock);
	hash = ISCSI_TT_HASH(cmnd->pdu.bhs.ttt);
	for (prev_cmnd = &session->cmnd_ttt_hash[hash];
	     (hash_cmnd = *prev_cmnd); prev_cmnd = &hash_cmnd->hash_next) {
		if (cmnd == hash_cmnd) {
			*prev_cmnd = cmnd->hash_next;
			break;
		}
	}
	spin_unlock(&session->cmnd_tt_lock);
	if (!hash_cmnd)
		printk("iscsi_session_remove_ttt: %p:%x not found\n", cmnd, cmnd->pdu.bhs.ttt);
	list_del_init(&cmnd->pdu_list);
	iscsi_cmnd_remove(cmnd);
}

/**
 * Check whether the command will be executed immediatly.
 *
 * iscsi_session_pushstate - 
 * @cmnd: ptr to command
 *
 * @return    1 -> command will be executed immediatly
 *	    0 -> command will be put on wait queue
 */

static inline int iscsi_session_pushstate(struct iscsi_cmnd *cmnd)
{
	return (cmnd->pdu.bhs.opcode & ISCSI_OP_IMMEDIATE) ||
		(cmnd->pdu.bhs.sn == cmnd->conn->session->exp_cmd_sn);
}

/**
 * Push the command for execution.
 * This functions reorders the commands.
 * Called from the read thread.
 *
 * iscsi_session_push_cmnd - 
 * @cmnd: ptr to command
 */

void iscsi_session_push_cmnd(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;

	dprintk(D_GENERIC, "iscsi_session_push_cmnd: %p:%x %u,%u\n", cmnd, cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK,
	       cmnd->pdu.bhs.sn, session->exp_cmd_sn);
	IE3(IE_SESSION_PUSH, cmnd, cmnd->pdu.bhs.opcode);
	if (cmnd->state != ISCSI_STATE_READ)
		printk("iscsi_session_push_cmnd: unexpected state %d of cmnd %p\n", cmnd->state, cmnd);

	if (cmnd->pdu.bhs.opcode & ISCSI_OP_IMMEDIATE) {
		//list_add_tail(&cmnd->list, &session->immediate_list);
		//if (!session->immediate_cmnd)
		//	session->immediate_cmnd = cmnd;
		iscsi_cmnd_execute(cmnd);
	} else {
		struct list_head *entry;
		u32 cmd_sn = cmnd->pdu.bhs.sn;

		if (cmd_sn == session->exp_cmd_sn) {
			while (1) {
				session->exp_cmd_sn = ++cmd_sn;
				iscsi_cmnd_execute(cmnd);

				if (list_empty(&session->pending_list))
					break;
				cmnd = list_entry(session->pending_list.next, struct iscsi_cmnd, list);
				if (cmnd->pdu.bhs.sn != cmd_sn)
					break;
				list_del_init(&cmnd->list);
			}
		} else {
			if ((s32)(cmd_sn - session->exp_cmd_sn) < 0)
				printk("iscsi_session_push_cmnd: oops, unexpected cmd_sn (%u,%u)\n",
				       cmd_sn, session->exp_cmd_sn);

			list_for_each(entry, &session->pending_list) {
				struct iscsi_cmnd *tmp = list_entry(entry, struct iscsi_cmnd, list);
				if (cmd_sn < tmp->pdu.bhs.sn)
					break;
			}
			cmnd->state = ISCSI_STATE_PUSHED;
			if (!list_empty(&cmnd->list))
				BUG();
			list_add_tail(&cmnd->list, entry);
		}
	}
}

/**
 * Check the SN of the incoming command and reject if necessary.
 *
 * iscsi_session_check_cmd_sn - 
 * @cmnd: ptr to command
 *
 * @return  1 -> command ok
 *	    0 -> otherwise
 */

static int inline iscsi_session_check_cmd_sn(struct iscsi_cmnd *cmnd)
{
	struct iscsi_session *session = cmnd->conn->session;
	u32 cmd_sn;

	cmnd->pdu.bhs.sn = cmd_sn = be32_to_cpu(cmnd->pdu.bhs.sn);
	dprintk(D_GENERIC, "check_cmd_sn: %d(%d)\n", cmd_sn, session->exp_cmd_sn);
	IE3(IE_SESSION_CHECK_CMDSN, cmnd, cmd_sn);
	if ((s32)(cmd_sn - session->exp_cmd_sn) >= 0)
		return 1;
	printk("check_cmd_sn: cmd sequence error (%x,%x)\n", cmd_sn, session->exp_cmd_sn);
	iscsi_cmnd_reject(cmnd, ISCSI_REASON_PROTOCOL_ERROR);
	return 0;
}

/*****************************************************************************/
/*                                 CONNECTION                                */
/*****************************************************************************/

/**
 * Create a new iscsi connection for a specific session.
 * The caller is responsible that not another connection with this cid exits.
 * Caller must hold iscsi_sem.
 *
 * iscsi_conn_create - 
 * @session: ptr to session
 * @cid: connection id
 *
 * @return    -errno
 */

int iscsi_conn_create(struct iscsi_session *session, u16 cid)
{
	struct iscsi_conn *conn;

	dprintk(D_SETUP, "iscsi_conn_create: %#Lx:%u\n", session->sid, cid);
	conn = kmalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn)
		return -ENOMEM;
	memset(conn, 0, sizeof(*conn));

	conn->state = ISCSI_CONN_NEW;
	conn->session = session;
	conn->cid = cid;
	spin_lock_init(&conn->list_lock);
	conn->cmnd_cnt = 0;
	INIT_LIST_HEAD(&conn->pdu_list);
	INIT_LIST_HEAD(&conn->write_list);
	INIT_LIST_HEAD(&conn->poll_list);

	list_add(&conn->list, &session->conn_list);

	iscsi_conn_proc_init(conn);

	return 0;
}

/**
 * Remove a connection.
 * Any commands still pending on this connection are lost after this for recovery.
 * Caller must hold iscsi_sem.
 *
 * iscsi_conn_remove - 
 * @conn: ptr to connection
 */

int iscsi_conn_remove(struct iscsi_conn *conn)
{
	struct iscsi_cmnd *cmnd, *scsi_cmnd;

	dprintk(D_SETUP, "iscsi_conn_remove: %#Lx:%u\n", conn->session->sid, conn->cid);
	list_del(&conn->list);

	iscsi_conn_close(conn);

	if (!list_empty(&conn->poll_list))
		list_del(&conn->poll_list);

	// move this later into session for recovery
	while (!list_empty(&conn->write_list)) {
		cmnd = list_entry(conn->write_list.next, struct iscsi_cmnd, list);
		list_del_init(&cmnd->list);
		iscsi_cmnd_release(cmnd);
	}

	if (conn->cmnd_cnt) {
		struct iscsi_target *target = conn->session->target;

		printk("iscsi_conn_remove: %u cmnds MIA\n", conn->cmnd_cnt);
		target_print_events();
		printk("lw: %lu lww: %lu now: %lu\n", target->poll.last_write, target->poll.last_write_wake, iscsi_jiffies);
		list_for_each_entry(cmnd, &conn->pdu_list, conn_list)
			printk("cmnd: %p,%d,%x,%x\n", cmnd, cmnd->state, cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK, be32_to_cpu(cmnd->pdu.bhs.sn));
	restart:
		printk("cleanup:\n");
		list_for_each_entry(cmnd, &conn->pdu_list, conn_list) {
			int opcode = cmnd->pdu.bhs.opcode & ISCSI_OPCODE_MASK;
			printk("cmnd: %p,%d,%x\n", cmnd, cmnd->state, opcode);
			switch (opcode) {
			case ISCSI_OP_RTT_RSP: {
				struct iscsi_r2t_hdr *rsp = rsp = (struct iscsi_r2t_hdr *)&cmnd->pdu.bhs;
				scsi_cmnd = cmnd->data;
				target_clear_pages(scsi_cmnd->data, be32_to_cpu(rsp->buffer_offset), be32_to_cpu(rsp->data_length));
				iscsi_session_remove_ttt(cmnd);
				goto restart;
			}
			case ISCSI_OP_SCSI_CMD:
			case ISCSI_OP_SCSI_ABORT:
				switch (cmnd->state) {
				case ISCSI_STATE_SEND_RTT: {
					struct target_device *dev;
					if (!list_empty(&cmnd->pdu_list))
						break;

					cmnd->pdu.bhs.opcode = ISCSI_OP_SCSI_ABORT;
					// more code duplication
					dev = cmnd->lun->device;
					if (target_commit_pages(dev, cmnd->data)) {
						cmnd->state = ISCSI_STATE_WAIT_COMMIT;
						if (!list_empty(&cmnd->list))
							BUG();
						list_add_tail(&cmnd->list, &dev->io_list);
					} else if (target_sync_pages(dev, cmnd->data)) {
						cmnd->state = ISCSI_STATE_WAIT_WRITE;
						if (!list_empty(&cmnd->list))
							BUG();
						list_add_tail(&cmnd->list, &dev->io_list);
					} else
						iscsi_cmnd_release(cmnd);
					goto restart;
				}
				case ISCSI_STATE_WAIT_WRITE: {
					struct target_device *dev;
					dev = cmnd->lun->device;
					if (!target_sync_pages(dev, cmnd->data)) {
						list_del_init(&cmnd->list);
						iscsi_cmnd_release(cmnd);
					}
					goto restart;
				}
				case ISCSI_STATE_WAIT_WRITE_PAGES:
					cmnd->pdu.bhs.opcode = ISCSI_OP_SCSI_ABORT;
					break;
				default:
					printk("fix me (%p)\n", cmnd);
					break;
				}
				break;
			default:
				printk("fix me (%p)\n", cmnd);
				break;
			}
		}
		printk("iscsi_conn_remove: %u cmnds still MIA\n", conn->cmnd_cnt);
	}
	wait_event(iscsi_wq, !conn->cmnd_cnt);

	iscsi_conn_proc_exit(conn);

	kfree(conn);
	return 0;
}

/**
 * Attach a socket to this connection.
 *
 * iscsi_conn_takefd - 
 * @conn: ptr to connection
 * @fd: fd of socket from the current user process
 *
 * @return    -errno
 */

int iscsi_conn_takefd(struct iscsi_conn *conn, int fd)
{
	struct iscsi_session *session = conn->session;
	int res = 0;

	dprintk(D_SETUP, "iscsi_conn_takefd: %d\n", fd);

	down_write(&session->target->poll.sem);
	if (conn->state != ISCSI_CONN_NEW) {
		res = -EINVAL;
		goto out;
	}

	conn->file = fget(fd);
	conn->sock = &conn->file->f_dentry->d_inode->u.socket_i;

	if (list_empty(&session->target->poll.list))
		iscsi_session_activate(session);
	list_add(&conn->poll_list, &session->target->poll.list);
	wake_up_process(session->target->poll.write_thread);
	session->target->poll.last_write_wake = iscsi_jiffies++;
out:
	up_write(&session->target->poll.sem);

	if (!res)
		wake_up_process(session->target->poll.read_thread);

	return 0;
}

/**
 * Close connection.
 * Caller must hold poll write lock
 *
 * iscsi_conn_closefd_nolock - 
 * @conn: ptr to connection
 */

static inline void iscsi_conn_closefd_nolock(struct iscsi_conn *conn)
{
	if (conn->state == ISCSI_CONN_ACTIVE) {
		conn->sock->ops->shutdown(conn->sock, 2);
		conn->state = ISCSI_CONN_CLOSING;
	}
}

/**
 * Close connection.
 *
 * iscsi_conn_closefd - 
 * @conn: ptr to connection
 */

void iscsi_conn_closefd(struct iscsi_conn *conn)
{
	down_write(&conn->session->target->poll.sem);
	if (conn->file)
		iscsi_conn_closefd_nolock(conn);
	up_write(&conn->session->target->poll.sem);
}

/**
 * Close connection and detach from read/write thread.
 *
 * iscsi_conn_close - 
 * @conn: ptr to connection
 */

void iscsi_conn_close(struct iscsi_conn *conn)
{
	struct iscsi_session *session = conn->session;

	dprintk(D_SETUP, "iscsi_conn_close(%#Lx:%u): %d\n", conn->session->sid, conn->cid, conn->state);
	down_write(&session->target->poll.sem);

	iscsi_conn_closefd_nolock(conn);
	if (conn->state != ISCSI_CONN_CLOSING)
		goto out;

	if (conn->read_cmnd) {
		iscsi_cmnd_remove(conn->read_cmnd);
		conn->read_cmnd = NULL;
	}
	if (conn->write_cmnd) {
		iscsi_cmnd_finish_write(conn->write_cmnd);
		conn->write_cmnd = NULL;
	}

	list_del(&conn->poll_list);
	list_add_tail(&conn->poll_list, &iscsi_conn_closed_list);
	wake_up_interruptible(&iscsi_ctl_wait);

	fput(conn->file);
	conn->file = NULL;
	conn->sock = NULL;

	session->target->poll.read_flags |= POLL_REINIT_TABLE;
	wake_up_process(session->target->poll.read_thread);
	session->target->poll.write_flags |= POLL_REINIT_TABLE;
	wake_up_process(session->target->poll.write_thread);

	conn->state = ISCSI_CONN_EXIT;
	wake_up(&session->target->poll.wq);

out:
	up_write(&session->target->poll.sem);
}

/**
 * Send asynchronous logout event.
 *
 * iscsi_conn_logout - 
 * @conn: ptr to connection
 * @timeout:
 *
 * @return    -errno
 */

int iscsi_conn_logout(struct iscsi_conn *conn, u32 timeout)
{
	struct iscsi_cmnd *cmnd;
	struct iscsi_async_msg_hdr *msg;

	cmnd = iscsi_cmnd_create(conn);
	if (!cmnd)
		return -ENOMEM;

	msg = (struct iscsi_async_msg_hdr *)&cmnd->pdu.bhs;

	msg->opcode = ISCSI_OP_ASYNC_EVENT;
	msg->ffffffff = ISCSI_RESERVED_TAG;
	msg->flags = ISCSI_FLG_FINAL;
	msg->async_event = ISCSI_ASYNC_LOGOUT;
	msg->param3 = cpu_to_be16(timeout);
	iscsi_cmnd_init_write(cmnd);
	wake_up_process(conn->session->target->poll.write_thread);
	conn->session->target->poll.last_write_wake = iscsi_jiffies++;
	return 0;
}

/**
 * Allocate a new read command.
 *
 * iscsi_conn_create_read_cmnd - 
 * @conn: ptr to connection
 */

void iscsi_conn_create_read_cmnd(struct iscsi_conn *conn)
{
	struct iscsi_cmnd *cmnd = iscsi_cmnd_create(conn);

	if (!cmnd)
		/* close connection */;

	cmnd->state = ISCSI_STATE_READ;

	iscsi_conn_init_read(conn, &cmnd->pdu.bhs, sizeof(cmnd->pdu.bhs));

	conn->read_cmnd = cmnd;
	conn->read_state = IOSTATE_READ_BHS;
}

/**
 * Write out data.
 *
 * iscsi_conn_write_data - 
 * @conn: ptr to connection
 *
 * @return    
 */

int iscsi_conn_write_data(struct iscsi_conn *conn)
{
	struct file *file;
	struct socket *sock;
	ssize_t (*sendpage)(struct socket *, struct page *, int, size_t, int);
	struct target_cmnd *tcmnd;
	struct iovec *iop;
	int size, sendsize;
	int offset, idx;
	int flags, res;

	file = conn->file;
	size = conn->write_size;
	iop = conn->write_iop;

	if (iop) while (1) {
		res = file->f_op->write(file, iop->iov_base,
					iop->iov_len, &file->f_pos);
		dprintk(D_THREAD, "write %#Lx:%u: %d(%d)\n",
			conn->session->sid, conn->cid,
			res, iop->iov_len);
		if (unlikely(res <= 0)) {
			if (res == -EAGAIN || res == -EINTR) {
				conn->write_iop = iop;
				goto out_iov;
			}
			goto err;
		}
		size -= res;
		iop->iov_len -= res;
		if (!iop->iov_len) {
			iop++;
			if (!iop->iov_len) {
				conn->write_iop = NULL;
				/* more data to be written? continue with tcmnd,
				 * otherwise exit
				 */
				if (size)
					break;
				goto out_iov;
			}
		} else
			iop->iov_base += res;
	}

	tcmnd = conn->write_tcmnd;
	if (!tcmnd) {
		printk("warning data missing!\n");
		return 0;
	}
	offset = conn->write_offset;
	idx = offset >> PAGE_CACHE_SHIFT;
	offset &= ~PAGE_CACHE_MASK;

	sock = conn->sock;
	sendpage = sock->ops->sendpage ? : sock_no_sendpage;
	flags = MSG_DONTWAIT;

	while (1) {
		sendsize = PAGE_CACHE_SIZE - offset;
		if (size <= sendsize) {
			res = sendpage(sock, tcmnd->u.pg.io_pages[idx], offset, size, flags);
			dprintk(D_THREAD, "%s %#Lx:%u: %d(%lu,%u,%u)\n",
				sock->ops->sendpage ? "sendpage" : "writepage",
				conn->session->sid, conn->cid,
				res, tcmnd->u.pg.io_pages[idx]->index, offset, size);
			if (unlikely(res <= 0)) {
				if (res == -EAGAIN || res == -EINTR)
					goto out;
				goto err;
			}
			if (res == size) {
				conn->write_tcmnd = NULL;
				conn->write_size = 0;
				return 0;
			}
			offset += res;
			size -= res;
			continue;
		}

		res = sendpage(sock, tcmnd->u.pg.io_pages[idx], offset,
				sendsize, flags | MSG_MORE);
		dprintk(D_THREAD, "%s %#Lx:%u: %d(%lu,%u,%u)\n",
			sock->ops->sendpage ? "sendpage" : "writepage",
			conn->session->sid, conn->cid,
			res, tcmnd->u.pg.io_pages[idx]->index, offset, sendsize);
		if (unlikely(res <= 0)) {
			if (res == -EAGAIN || res == -EINTR)
				goto out;
			goto err;
		}
		if (res == sendsize) {
			offset = 0;
			if (++idx == TARGET_CMND_MAX_PAGES) {
				tcmnd = tcmnd->next;
				idx = 0;
			}
		} else
			offset += res;
		size -= res;
	}
 out:
	conn->write_tcmnd = tcmnd;
	conn->write_offset = (idx << PAGE_CACHE_SHIFT) + offset;
 out_iov:
	conn->write_size = size;
	return size;

 err:
	if (res)
		printk("write error %d at %#Lx:%u\n", -res, conn->session->sid, conn->cid);
	if (conn->state == ISCSI_CONN_ACTIVE) {
		conn->state = ISCSI_CONN_CLOSING;
		wake_up_process(conn->session->target->poll.read_thread);
	}
	conn->write_size = 0;
	return 0;
}

/**
 * Update SN of connection.
 *
 * iscsi_conn_update_stat_sn - 
 * @cmnd: ptr to command
 */

void iscsi_conn_update_stat_sn(struct iscsi_cmnd *cmnd)
{
	struct iscsi_conn *conn = cmnd->conn;
	u32 exp_stat_sn;

	cmnd->pdu.bhs.exp_sn = exp_stat_sn = be32_to_cpu(cmnd->pdu.bhs.exp_sn);
	dprintk(D_GENERIC, "update_stat_sn: %x,%x\n", cmnd->pdu.bhs.opcode, exp_stat_sn);
	IE3(IE_SESSION_UPDATE_STATSN, cmnd, exp_stat_sn);
	if ((int)(exp_stat_sn - conn->exp_stat_sn) > 0 &&
	    (int)(exp_stat_sn - conn->stat_sn) <= 0) {
		// free pdu resources
		cmnd->conn->exp_stat_sn = exp_stat_sn;
	} else if ((int)(exp_stat_sn - conn->exp_stat_sn) != 0) {
		printk("update_stat_sn: stat sequence number error (%x,%x)\n",
		       exp_stat_sn, conn->exp_stat_sn);
	}
}

/**
 * Prepare connection to read into data buffer.
 *
 * iscsi_conn_init_read - 
 * @conn: ptr to connection
 * @data: ptr to read buffer
 * @len: size of read buffer
 */

static inline void iscsi_conn_init_read(struct iscsi_conn *conn, void *data, size_t len)
{
	len = (len + 3) & -4; // XXX ???
	conn->read_iov[0].iov_base = data;
	conn->read_iov[0].iov_len = len;
	conn->read_msg.msg_iov = conn->read_iov;
	conn->read_msg.msg_iovlen = 1;
	conn->read_size = (len + 3) & -4;
}

static int iscsi_init(void)
{
//	int res;

	init_MUTEX(&iscsi_sem);
	INIT_LIST_HEAD(&target_list);
	INIT_LIST_HEAD(&target_device_list);

	init_waitqueue_head(&iscsi_wq);
	iscsi_cmnd_cache = kmem_cache_create("iscsi_cmnd", sizeof(struct iscsi_cmnd), 0, 0, NULL, NULL);

#if 0
	res = register_chrdev(0, "iscsictl", &iscsi_ctl_fops);
	if (res < 0) {
		printk("iSCSI failed to register the control device\n");
		return res;
	}
	iscsi_ctl_major = res;
#endif

	target_init();
	iscsi_proc_init();

	trace_read_cmnd = trace_create_event("iscsi_read_cmnd", "%u", CUSTOM_EVENT_FORMAT_TYPE_STR, NULL);
	trace_execute_cmnd = trace_create_event("iscsi_execute_cmnd", "%u", CUSTOM_EVENT_FORMAT_TYPE_STR, NULL);
	trace_write_cmnd = trace_create_event("iscsi_write_cmnd", "%u", CUSTOM_EVENT_FORMAT_TYPE_STR, NULL);
	trace_execute_scsi = trace_create_event("iscsi_execute_scsi", "%x", CUSTOM_EVENT_FORMAT_TYPE_STR, NULL);

	return 0;
}

static void iscsi_exit(void)
{
	iscsi_proc_exit();
	target_exit();

	kmem_cache_destroy(iscsi_cmnd_cache);
#if 0
	unregister_chrdev(iscsi_ctl_major, "iscsictl");
#endif

	trace_destroy_event(trace_read_cmnd);
	trace_destroy_event(trace_execute_cmnd);
	trace_destroy_event(trace_write_cmnd);
	trace_destroy_event(trace_execute_scsi);
}

module_init(iscsi_init);
module_exit(iscsi_exit);

MODULE_LICENSE("GPL");
