/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef __ISCSI_H__
#define __ISCSI_H__

#include <linux/poll.h>
#include <linux/rwsem.h>

#include "target.h"
#include "iscsi_hdr.h"

struct target_device;

struct iscsi_param {
	u32 flags;
	int max_connections;
	int max_data_pdu_length;
	int max_burst_length;
	int first_burst_length;
	int default_wait_time;
	int default_retain_time;
	int max_outstanding_rtt;
	int error_recovery_level;
};

#define SESSION_FLG_INITIAL_RTT		0x0001
#define SESSION_FLG_IMMEDIATEDATA	0x0002
#define SESSION_FLG_DATAPDUINORDER	0x0004
#define SESSION_FLG_DATASEQUENCEINORDER	0x0008

struct iscsi_poll {
	struct rw_semaphore sem;
	struct list_head list;
	poll_table read_poll, write_poll;
	unsigned short read_flags, write_flags;

	wait_queue_head_t wq;
	struct task_struct *read_thread, *write_thread;
	long last_write, last_write_wake;
};

struct iscsi_target {
	struct target target;

	char *name, *alias;
	struct iscsi_param default_param;

	struct list_head session_list;
	struct list_head lun_list;
	int lun_cnt;

	struct iscsi_poll poll;

	struct proc_dir_entry *proc_param_dir;
	struct proc_dir_entry *proc_session_dir;
	struct proc_dir_entry *proc_lun_dir;
};

#define POLL_INITIALIZED	0x0001
#define POLL_REINIT_TABLE	0x0002
#define POLL_EXIT		0x0004

// just scsi_queue?
struct iscsi_queue {
	spinlock_t queue_lock;
	struct iscsi_cmnd *ordered_cmnd;			    /* active ordered command */
	struct list_head wait_list;				    /* waiting commands */
	int active_cnt;						    /* # of active i/o commands */
};

struct iscsi_lun {
	struct list_head list;
	struct iscsi_target *target;
	u32 lun;
	struct target_device *device;

	struct iscsi_queue queue;

	struct proc_dir_entry *proc_dir;
};

#define ISCSI_TT_HASHSHIFT	8
#define ISCSI_TT_HASHSIZE	(1<<ISCSI_TT_HASHSHIFT)
#define ISCSI_TT_HASHMASK	(ISCSI_TT_HASHSIZE-1)
#define ISCSI_TT_HASH(itt) ({					\
	u32 __hash = (itt) ^ ((itt)>>16);			\
	(__hash ^ (__hash >> 8)) & ISCSI_TT_HASHMASK;		\
})

struct iscsi_session {
	struct list_head list;
	struct iscsi_target *target;

	char *initiator;
	u64 sid;

	u32 exp_cmd_sn;
	u32 max_cmd_sn;

	struct iscsi_param param;

	struct list_head conn_list;

	struct list_head pending_list;

	spinlock_t cmnd_tt_lock;
	struct iscsi_cmnd *cmnd_itt_hash[ISCSI_TT_HASHSIZE];
	struct iscsi_cmnd *cmnd_ttt_hash[ISCSI_TT_HASHSIZE];
	u32 next_ttt;

	struct proc_dir_entry *proc_dir;
	struct proc_dir_entry *proc_param_dir;
	struct proc_dir_entry *proc_conn_dir;
};

#define ISCSI_CONN_IOV_MAX	16

#define ISCSI_CONN_ACTIVE	0
#define ISCSI_CONN_NEW		1
//#define ISCSI_CONN_EXIT_READ	2
//#define ISCSI_CONN_EXIT_WRITE	3
#define ISCSI_CONN_CLOSING	4
#define ISCSI_CONN_EXIT		5

struct iscsi_conn {
	struct list_head list;			/* list entry in session list */
	struct iscsi_session *session;		/* owning session */

	struct proc_dir_entry *proc_dir;

	u16 cid;
	u16 state;

	u32 stat_sn;
	u32 exp_stat_sn;

	int header_digest;
	int data_digest;

	struct list_head poll_list;		/* list entry in poll list */

	struct file *file;
	struct socket *sock;
	spinlock_t list_lock;
	int cmnd_cnt;
	struct list_head pdu_list;		/* in/outcoming pdus */
	struct list_head write_list;		/* list of data pdus to be sent */

	struct iscsi_cmnd *read_cmnd;
	struct msghdr read_msg;
	struct iovec read_iov[ISCSI_CONN_IOV_MAX];
	u32 read_size;
	u32 read_overflow;
	int read_state;

	struct iscsi_cmnd *write_cmnd;
	struct iovec write_iov[ISCSI_CONN_IOV_MAX];
	struct iovec *write_iop;
	struct target_cmnd *write_tcmnd;
	u32 write_size;
	u32 write_offset;
	int write_state;
};


#define IOSTATE_NEW		0
#define IOSTATE_FREE		1
#define IOSTATE_READ_BHS	2
#define IOSTATE_READ_AHS	3
#define IOSTATE_READ_DATA	4
#define IOSTATE_WRITE_BHS	5
#define IOSTATE_WRITE_AHS	6
#define IOSTATE_WRITE_DATA	7

#define DIGEST_NONE		0


struct iscsi_pdu {
	struct iscsi_hdr bhs;
	void *ahs;
	unsigned int ahssize;
	unsigned int datasize;
};

struct iscsi_cmnd {
	struct list_head list;
	struct list_head conn_list;
	int state;
	struct iscsi_conn *conn;
	struct iscsi_cmnd *hash_next;
	struct iscsi_lun *lun;

	struct iscsi_pdu pdu;
	struct list_head pdu_list;

	void *data;
};


#define ISCSI_OP_SCSI_REJECT	ISCSI_OP_VENDOR1_CMD
#define ISCSI_OP_PDU_REJECT	ISCSI_OP_VENDOR2_CMD
#define ISCSI_OP_DATA_REJECT	ISCSI_OP_VENDOR3_CMD
#define ISCSI_OP_SCSI_ABORT	ISCSI_OP_VENDOR4_CMD

#define ISCSI_STATE_NEW			0
#define ISCSI_STATE_READ		1
#define ISCSI_STATE_WRITE		2
#define ISCSI_STATE_WRITE_DONE		3
#define ISCSI_STATE_PUSHED		4
#define ISCSI_STATE_QUEUED		5
#define ISCSI_STATE_PENDING		6
#define ISCSI_STATE_HOQ_MARKER		7
#define ISCSI_STATE_ACTIVE		8
#define ISCSI_STATE_START_READ		9
#define ISCSI_STATE_WAIT_READ		10
#define ISCSI_STATE_SEND_DATA		11
#define ISCSI_STATE_SEND_RSP		12
#define ISCSI_STATE_SEND_RTT		13
#define ISCSI_STATE_WAIT_RECEIVE	14
#define ISCSI_STATE_WAIT_ASYNC		15
#define ISCSI_STATE_WAIT_WRITE_PAGES	16
#define ISCSI_STATE_WAIT_COMMIT		17
#define ISCSI_STATE_WAIT_WRITE		18

extern struct semaphore iscsi_sem;

extern int iscsi_target_create(u32 id, const char *name);
extern int iscsi_target_remove(struct iscsi_target *target);
extern struct iscsi_target *iscsi_target_lookup(u32 id);
extern struct iscsi_session *iscsi_target_lookup_session(struct iscsi_target *target, u64 sid);
extern struct iscsi_lun *iscsi_target_lookup_lun(struct iscsi_target *target, u32 id);

extern int iscsi_device_create(u32 id, const char *name);
extern int iscsi_device_remove(struct target_device *dev);
extern int iscsi_device_attach(struct iscsi_target *target, struct target_device *dev, u32 id);
extern int iscsi_device_detach(struct iscsi_lun *lun);
extern struct target_device *iscsi_device_lookup_devid(u32 id);
extern void iscsi_device_queue_cmnd(struct iscsi_cmnd *cmnd);

extern int iscsi_session_create(struct iscsi_target *target, u64 sid);
extern int iscsi_session_remove(struct iscsi_session *session);
extern struct iscsi_conn *iscsi_session_lookup_conn(struct iscsi_session *session, u16 cid);
extern void iscsi_session_activate(struct iscsi_session *session);
extern int iscsi_session_insert_cmnd(struct iscsi_cmnd *cmnd);
extern struct iscsi_cmnd *iscsi_session_find_cmnd(struct iscsi_session *session, u32 itt);
extern void iscsi_session_remove_cmnd(struct iscsi_cmnd *cmnd);
extern void iscsi_session_insert_ttt(struct iscsi_cmnd *cmnd);
extern struct iscsi_cmnd *iscsi_session_find_ttt(struct iscsi_session *session, u32 ttt);
extern void iscsi_session_remove_ttt(struct iscsi_cmnd *cmnd);
extern void iscsi_session_push_cmnd(struct iscsi_cmnd *cmnd);
extern void iscsi_session_pop_next_cmnd(struct iscsi_cmnd *cmnd);

extern int iscsi_conn_create(struct iscsi_session *session, u16 cid);
extern int iscsi_conn_remove(struct iscsi_conn *conn);
extern int iscsi_conn_takefd(struct iscsi_conn *conn, int fd);
extern int iscsi_conn_logout(struct iscsi_conn *conn, u32 timeout);
extern void iscsi_conn_closefd(struct iscsi_conn *conn);
extern void iscsi_conn_close(struct iscsi_conn *conn);
extern void iscsi_conn_create_read_cmnd(struct iscsi_conn *conn);
extern int iscsi_conn_write_data(struct iscsi_conn *conn);
extern void iscsi_conn_update_stat_sn(struct iscsi_cmnd *cmnd);

extern struct iscsi_cmnd *iscsi_cmnd_create(struct iscsi_conn *conn);
extern struct iscsi_cmnd *iscsi_cmnd_create_rsp_cmnd(struct iscsi_cmnd *cmnd);
extern void iscsi_cmnd_remove(struct iscsi_cmnd *cmnd);
extern void iscsi_cmnd_start_read(struct iscsi_cmnd *cmnd);
extern void iscsi_cmnd_finish_read(struct iscsi_cmnd *cmnd);
extern void iscsi_cmnd_execute(struct iscsi_cmnd *cmnd);
extern void iscsi_cmnd_init_write(struct iscsi_cmnd *cmnd);
extern void iscsi_cmnd_start_write(struct iscsi_cmnd *cmnd);
extern void iscsi_cmnd_finish_write(struct iscsi_cmnd *cmnd);
extern void iscsi_cmnd_release(struct iscsi_cmnd *cmnd);
extern void iscsi_cmnd_reject(struct iscsi_cmnd *cmnd, int reason);
extern struct iscsi_cmnd *iscsi_cmnd_scsi_rsp(struct iscsi_cmnd *scsi_cmnd);
extern struct iscsi_cmnd *iscsi_cmnd_sense_rsp(struct iscsi_cmnd *scsi_cmnd, u8 sense_key, u8 asc, u8 ascq);
extern void iscsi_cmnd_skip_pdu(struct iscsi_cmnd *cmnd);
extern void iscsi_cmnd_ignore_data(struct iscsi_cmnd *scsi_cmnd);
extern void iscsi_cmnd_prepare_send(struct iscsi_cmnd *cmnd);
extern void iscsi_cmnd_send_pdu(struct iscsi_conn *conn, struct target_cmnd *tcmnd, u32 offset, u32 size);
extern void iscsi_cmnd_receive_pdu(struct iscsi_conn *conn, struct target_cmnd *tcmnd, u32 offset, u32 size);
extern void iscsi_cmnd_unmap_pdu(struct iscsi_conn *conn, struct target_cmnd *tcmnd, u32 offset, u32 size);
extern void iscsi_cmnd_set_sn(struct iscsi_cmnd *cmnd, int set_stat_sn);
extern u32 iscsi_cmnd_write_size(struct iscsi_cmnd *cmnd);
extern u32 iscsi_cmnd_read_size(struct iscsi_cmnd *cmnd);
extern void iscsi_dump_pdu( struct iscsi_pdu *pdu );

extern int iscsi_scsi_queuestate(struct iscsi_cmnd *cmnd);
extern void iscsi_scsi_queuecmnd(struct iscsi_cmnd *cmnd);
extern void iscsi_scsi_dequeuecmnd(struct iscsi_cmnd *cmnd);
extern void iscsi_scsi_execute(struct iscsi_cmnd *cmnd);

extern struct list_head iscsi_conn_closed_list;
extern wait_queue_head_t iscsi_ctl_wait;

extern int iscsi_target_proc_init(struct iscsi_target *target);
extern void iscsi_target_proc_exit(struct iscsi_target *target);
extern int iscsi_device_proc_init(struct target_device *device);
extern void iscsi_device_proc_exit(struct target_device *device);
extern int iscsi_lun_proc_init(struct iscsi_lun *lun);
extern void iscsi_lun_proc_exit(struct iscsi_lun *lun);
extern int iscsi_session_proc_init(struct iscsi_session *session);
extern void iscsi_session_proc_exit(struct iscsi_session *session);
extern int iscsi_conn_proc_init(struct iscsi_conn *conn);
extern void iscsi_conn_proc_exit(struct iscsi_conn *conn);
extern int iscsi_proc_init(void);
extern void iscsi_proc_exit(void);

#endif	/* __ISCSI_H__ */
