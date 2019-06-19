/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef ISCSID_H
#define ISCSID_H

#include <sys/types.h>

#include "config.h"
#include "iscsi_hdr.h"

struct PDU {
	struct iscsi_hdr bhs;
	void *ahs;
	unsigned int ahssize;
	void *data;
	unsigned int datasize;
};

struct session_param {
	u32 flags;
	u32 max_connections;
	u32 max_data_pdu_length;
	u32 max_burst_length;
	u32 first_burst_length;
	u32 default_wait_time;
	u32 default_retain_time;
	u32 max_outstanding_r2t;
	u32 error_recovery_level;
};

#define SESSION_FLG_INITIAL_R2T		0x0001
#define SESSION_FLG_IMMEDIATE_DATA	0x0002
#define SESSION_FLG_DATA_PDU_INORDER	0x0004
#define SESSION_FLG_DATA_SEQUENCE_INORDER 0x0008

enum {
	key_max_connections,
	key_initial_r2t,
	key_immediate_data,
	key_max_data_pdu_length,
	key_max_burst_length,
	key_first_burst_length,
	key_default_wait_time,
	key_default_retain_time,
	key_max_outstanding_r2t,
	key_data_pdu_inorder,
	key_data_sequence_inorder,
	key_error_recovery_level,
	key_last
};

#define KEY_STATE_START		0
#define KEY_STATE_REQUEST	1
#define KEY_STATE_DONE		2

struct session {
	struct session *next;
	struct target *target;

	char *initiator;
	union iscsi_sid sid;

	int conn_cnt;
};

#define CHAP_CHALLENGE_MAX	50

struct connection {
	int state;
	int iostate;
	int fd;

	//struct connection *next;
	struct session *session;

	struct target *target;
	struct session_param param;

	char *initiator;
	union iscsi_sid sid;
	u16 cid;
	u16 pad;
	int session_type;
	int auth_method;
	int header_digest;
	int data_digest;

	u32 stat_sn;
	u32 exp_stat_sn;

	u32 cmd_sn;
	u32 exp_cmd_sn;
	u32 max_cmd_sn;

	struct PDU req;
	void *req_buffer;
	struct PDU rsp;
	void *rsp_buffer;
	unsigned char *buffer;
	int rwsize;

	int key_state[key_last];

	int auth_state;
	int chap_id;
	int chap_challenge_size;
	char chap_challenge[CHAP_CHALLENGE_MAX];
};

#define IOSTATE_FREE		0
#define IOSTATE_READ_BHS	1
#define IOSTATE_READ_AHS_DATA	2
#define IOSTATE_WRITE_BHS	3
#define IOSTATE_WRITE_AHS	4
#define IOSTATE_WRITE_DATA	5

#define STATE_FREE		0
#define STATE_SECURITY		1
#define STATE_SECURITY_AUTH	2
#define STATE_SECURITY_DONE	3
#define STATE_SECURITY_LOGIN	4
#define STATE_SECURITY_FULL	5
#define STATE_LOGIN		6
#define STATE_LOGIN_FULL	7
#define STATE_FULL		8
#define STATE_KERNEL		9
#define STATE_CLOSE		10
#define STATE_EXIT		11

#define AUTH_STATE_START	0
#define AUTH_STATE_CHALLENGE	1

#define SESSION_NORMAL		0
#define SESSION_DISCOVERY	1
#define AUTH_UNKNOWN		-1
#define AUTH_NONE		0
#define AUTH_CHAP		1
#define DIGEST_UNKNOWN		-1
#define DIGEST_NONE		0

#define BHS_SIZE		48

#define INCOMING_BUFSIZE	8192

struct target {
	struct target *next;

	struct session *sessions;
	int session_cnt;

	struct target_lun *luns;

	u32 id;
	char *name;
	char *alias;
	struct user *users;

	struct session_param default_param;
};

struct device {
	struct device *next;

	int id;
	char *path;
	dev_t dev;
	ino_t ino;
};

struct target_lun {
	struct target_lun *next;
	struct device *device;
	int lun;
};

struct user {
	struct user *next;
	char *name;
	char *password;
};

/* conn.c */
extern void conn_scan(struct session *session);
extern struct connection *conn_alloc(void);
extern void conn_free(struct connection *conn);
extern int conn_test(struct connection *conn);
extern void conn_set_path(struct connection *conn);
extern void conn_take_fd(struct connection *conn, int fd);
extern void conn_read_pdu(struct connection *conn);
extern void conn_write_pdu(struct connection *conn);
extern void conn_free_pdu(struct connection *conn);

/* iscsid.c */
extern struct user *iscsi_discover_users;
extern int iscsi_debug;

extern int cmnd_execute(struct connection *conn);
extern void cmnd_finish(struct connection *conn);

/* log.c */
extern int log_daemon;
extern int log_level;

extern void log_init(void);
extern void log_warning(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));
extern void log_error(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));
extern void log_debug(int level, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));
extern void log_pdu(int level, struct PDU *pdu);

/* param.c */
extern void param_set_default(struct session_param *param);
extern void param_set_linux_default(struct session_param *param);
extern void param_read(struct session_param *param);

/* proc.c */
extern char procPath[4096];
extern char procData[4096];
extern int proc_read_data(void);
extern int proc_read_string(const char *name, char **result);
extern int proc_read_u64(const char *name, u64 *result);
extern int proc_read_u32(const char *name, u32 *result);
extern int proc_read_u16(const char *name, u16 *result);
extern int proc_read_bool(const char *name, int *result, int mask);
extern void proc_write(const char *name, const char *fmt, ...);
extern void proc_write_u64(const char *name, u64 val);
extern void proc_write_u32(const char *name, u32 val);
extern void proc_write_u16(const char *name, u16 val);

/* session.c */
extern struct session *session_alloc(struct target *target);
extern struct session *session_find_name(struct target *target, const char *iname, union iscsi_sid sid);
extern struct session *session_find_id(struct target *target, u64 sid);
extern void session_scan(struct target *target);
extern void session_create(struct connection *conn);
extern void session_close(struct session *session);
extern void session_remove(struct session *session);
extern void session_set_path(struct session *session);

/* target.c */
extern struct target *targets;
extern void target_scan(void);
extern struct target *target_find_name(const char *name);
extern struct target *target_find_id(u32 id);
extern int target_remove(struct target *target);
extern void target_set_path(struct target *target);

/* main.c */
void *xmalloc(size_t);

#endif	/* ISCSID_H */
