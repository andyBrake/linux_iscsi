/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <asm/uaccess.h>

#include "iscsi.h"
#include "target.h"
#include "target_dbg.h"
#include "target_device.h"

#define iscsi_skip_space(ptr) ({				\
	while (isspace(*(ptr)))					\
		(ptr)++;					\
})

#define iscsi_strcmp(ptr, str) ({				\
	int __res = memcmp((ptr), str, sizeof(str)-1);		\
	if (!__res) {						\
		(ptr) += sizeof(str) - 1;			\
		iscsi_skip_space(ptr);				\
	}							\
	__res;							\
})

#define iscsi_strtoul(ptr) ({					\
	unsigned long __res;					\
	__res = simple_strtoul((ptr), &(ptr), 0);		\
	iscsi_skip_space(ptr);					\
	__res;							\
})

#define iscsi_strtoull(ptr) ({					\
	unsigned long long __res;				\
	__res = simple_strtoull((ptr), &(ptr), 0);		\
	iscsi_skip_space(ptr);					\
	__res;							\
})

#define iscsi_proc_int_read(name, type, arg)			\
static int name##_read(char *page, char **start, off_t off,	\
		       int count, int *eof, void *data)		\
{								\
	if (off)						\
		return 0;					\
								\
	return sprintf(page, "%u\n", ((type *)data)->arg);	\
}

#define iscsi_proc_int_write(name, type, arg)			\
static int name##_write(struct file *file, const char *buffer,	\
			unsigned long count, void *data)	\
{								\
	char str[32];						\
								\
	if (count > sizeof(str) - 1)				\
		count = sizeof(str) - 1;			\
	if (copy_from_user(str, buffer, count))			\
		return -EFAULT;					\
	str[count] = 0;						\
								\
	((type *)data)->arg = simple_strtoul(str, NULL, 0);	\
	return count;						\
}

#define iscsi_proc_int(name, type, arg)				\
iscsi_proc_int_read(name, type, arg)				\
iscsi_proc_int_write(name, type, arg)

#define iscsi_proc_int64_read(name, type, arg)			\
static int name##_read(char *page, char **start, off_t off,	\
		       int count, int *eof, void *data)		\
{								\
	if (off)						\
		return 0;					\
								\
	return sprintf(page, "%#Lx\n", ((type *)data)->arg);	\
}

#define iscsi_proc_int64_write(name, type, arg)			\
static int name##_write(struct file *file, const char *buffer,	\
			unsigned long count, void *data)	\
{								\
	char str[32];						\
								\
	if (count > sizeof(str) - 1)				\
		count = sizeof(str) - 1;			\
	if (copy_from_user(str, buffer, count))			\
		return -EFAULT;					\
	str[count] = 0;						\
								\
	((type *)data)->arg = simple_strtoull(str, NULL, 0);	\
	return count;						\
}

#define iscsi_proc_int64(name, type, arg)			\
iscsi_proc_int64_read(name, type, arg)				\
iscsi_proc_int64_write(name, type, arg)

#define iscsi_proc_string_read(name, type, arg)			\
static int name##_read(char *page, char **start, off_t off,	\
		       int count, int *eof, void *data)		\
{								\
	char *str = ((type *)data)->arg;			\
								\
	if (off)						\
		return 0;					\
								\
	if (!str)						\
		str = "";					\
	return sprintf(page, "%s\n", str);			\
}

#define iscsi_proc_string_write(name, type, arg)		\
static int name##_write(struct file *file, const char *buffer,	\
			unsigned long count, void *data)	\
{								\
	char buf[512], *ptr;					\
	int len;						\
								\
	if (count > sizeof(buf) - 1)				\
		count = sizeof(buf) - 1;			\
	if (copy_from_user(buf, buffer, count))			\
		return -EFAULT;					\
	buf[count] = 0;						\
	ptr = strchr(buf, '\n');				\
	len = ptr ? ptr - buf : strlen(buf);			\
								\
	if (len) {						\
		ptr = kmalloc(len + 1, GFP_KERNEL);		\
		if (!ptr)					\
			return -ENOMEM;				\
								\
		memcpy(ptr, buf, len);				\
		ptr[len] = 0;					\
	} else							\
		ptr = NULL;					\
								\
	kfree(((type *)data)->arg);				\
	((type *)data)->arg = ptr;				\
	return count;						\
}

#define iscsi_proc_string(name, type, arg)			\
iscsi_proc_string_read(name, type, arg)				\
iscsi_proc_string_write(name, type, arg)

#define iscsi_proc_bool_read(name, type, arg, mask)		\
static int name##_read(char *page, char **start, off_t off,	\
		       int count, int *eof, void *data)		\
{								\
	if (off)						\
		return 0;					\
								\
	return sprintf(page, (((type *)data)->arg & mask ?	\
			      "yes\n" : "no\n"));		\
}

#define iscsi_proc_bool_write(name, type, arg, mask)		\
static int name##_write(struct file *file, const char *buffer,	\
			unsigned long count, void *data)	\
{								\
	char str[4], *ptr = str;				\
								\
	if (count > sizeof(str) - 1)				\
		count = sizeof(str) - 1;			\
	if (copy_from_user(str, buffer, count))			\
		return -EFAULT;					\
	str[count] = 0;						\
								\
	if (!iscsi_strcmp(ptr, "yes"))				\
		((type *)data)->arg |= mask;			\
	else if (!iscsi_strcmp(ptr, "no"))			\
		((type *)data)->arg &= ~mask;			\
	else if (str[0] == '1')					\
		((type *)data)->arg |= mask;			\
	else if (str[0] == '0')					\
		((type *)data)->arg &= ~mask;			\
	return count;						\
}

#define iscsi_proc_bool(name, type, arg, mask)			\
iscsi_proc_bool_read(name, type, arg, mask)			\
iscsi_proc_bool_write(name, type, arg, mask)

static struct proc_dir_entry *iscsi_dir;
static struct proc_dir_entry *iscsi_target_dir;
static struct proc_dir_entry *iscsi_device_dir;

static struct proc_dir_entry *iscsi_proc_create(const char *name, struct proc_dir_entry *parent,
		read_proc_t *read_proc, write_proc_t *write_proc, void *data)
{
	struct proc_dir_entry *res = create_proc_entry(name, 0, parent);
	if (res) {
		res->owner = THIS_MODULE;
		res->read_proc = read_proc;
		res->write_proc = write_proc;
		res->data = data;
	}
	return res;
}

static struct proc_dir_entry *iscsi_proc_link(const char *name,
		struct proc_dir_entry *parent, struct inode_operations *iops, void *data)
{
	struct proc_dir_entry *res = create_proc_entry(name, S_IFLNK, parent);
	if (res) { 
		res->owner = THIS_MODULE;
		res->proc_iops = iops;
		res->data = data;
	}
	return res;
}

static void iscsi_proc_rmdir(struct proc_dir_entry *dir)
{
	struct proc_dir_entry *de;

	if (!dir) {
		printk("iscsi_proc_rmdir: no dir?\n");
		return;
	}

	while ((de = dir->subdir)) {
		de->data = NULL;
		remove_proc_entry(de->name, dir);
	}
	dir->data = NULL;
	remove_proc_entry(dir->name, dir->parent);
}


/***************************************************************************************/
/*                                       PARAMETER                                     */
/***************************************************************************************/

iscsi_proc_int(iscsi_param_max_connections, struct iscsi_param, max_connections)
iscsi_proc_bool(iscsi_param_initial_rtt, struct iscsi_param, flags, SESSION_FLG_INITIAL_RTT)
iscsi_proc_bool(iscsi_param_immediate_data, struct iscsi_param, flags, SESSION_FLG_IMMEDIATEDATA)
iscsi_proc_int(iscsi_param_data_pdu_length, struct iscsi_param, max_data_pdu_length)
iscsi_proc_int(iscsi_param_max_burst_size, struct iscsi_param, max_burst_length)
iscsi_proc_int(iscsi_param_first_burst_size, struct iscsi_param, first_burst_length)
iscsi_proc_int(iscsi_param_default_wait_time, struct iscsi_param, default_wait_time)
iscsi_proc_int(iscsi_param_default_retain_time, struct iscsi_param, default_retain_time)
iscsi_proc_int(iscsi_param_max_outstanding_rtt, struct iscsi_param, max_outstanding_rtt)
iscsi_proc_bool(iscsi_param_data_pdu_inorder, struct iscsi_param, flags, SESSION_FLG_DATAPDUINORDER)
iscsi_proc_bool(iscsi_param_data_sequence_inorder, struct iscsi_param, flags, SESSION_FLG_DATASEQUENCEINORDER)
iscsi_proc_int(iscsi_param_error_recovery_level, struct iscsi_param, error_recovery_level)

int iscsi_param_proc_init(struct proc_dir_entry *dir, struct iscsi_param *param)
{
	iscsi_proc_create("max_connections", dir, iscsi_param_max_connections_read,
			iscsi_param_max_connections_write, param);
	iscsi_proc_create("initial_rtt", dir, iscsi_param_initial_rtt_read,
			iscsi_param_initial_rtt_write, param);
	iscsi_proc_create("immediate_data", dir, iscsi_param_immediate_data_read,
			iscsi_param_immediate_data_write, param);
	iscsi_proc_create("max_data_pdu_length", dir, iscsi_param_data_pdu_length_read,
			iscsi_param_data_pdu_length_write, param);
	iscsi_proc_create("max_burst_length", dir, iscsi_param_max_burst_size_read,
			iscsi_param_max_burst_size_write, param);
	iscsi_proc_create("first_burst_length", dir, iscsi_param_first_burst_size_read,
			iscsi_param_first_burst_size_write, param);
	iscsi_proc_create("default_wait_time", dir, iscsi_param_default_wait_time_read,
			iscsi_param_default_wait_time_write, param);
	iscsi_proc_create("default_retain_time", dir, iscsi_param_default_retain_time_read,
			iscsi_param_default_retain_time_write, param);
	iscsi_proc_create("max_outstanding_rtt", dir, iscsi_param_max_outstanding_rtt_read,
			iscsi_param_max_outstanding_rtt_write, param);
	iscsi_proc_create("data_pdu_inorder", dir, iscsi_param_data_pdu_inorder_read,
			iscsi_param_data_pdu_inorder_write, param);
	iscsi_proc_create("data_sequence_inorder", dir, iscsi_param_data_sequence_inorder_read,
			iscsi_param_data_sequence_inorder_write, param);
	iscsi_proc_create("error_recovery_level", dir, iscsi_param_error_recovery_level_read,
			iscsi_param_error_recovery_level_write, param);

	return 0;
}

/***************************************************************************************/
/*                                        TARGET                                       */
/***************************************************************************************/

static int iscsi_target_target_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	return 0;
}

static int iscsi_target_target_write(struct file *file, const char *buffer, unsigned long count, void *data)
{
	struct iscsi_target *target = data;
	char buf[512], *ptr = buf;
	int res = 0;

	if (count > 511)
		count = 511;
	copy_from_user(buf, buffer, count);
	buf[count] = 0;
	ptr = buf;

	if (!iscsi_strcmp(ptr, "session ")) {
		if (!iscsi_strcmp(ptr, "add ")) {
			struct iscsi_session *session;
			u64 sid = iscsi_strtoull(ptr);

			session = iscsi_target_lookup_session(target, sid);
			res = -EEXIST;
			if (!session)
				res = iscsi_session_create(target, sid);
		} else if (!iscsi_strcmp(ptr, "remove ")) {
			struct iscsi_session *session;
			u64 sid = iscsi_strtoull(ptr);

			session = iscsi_target_lookup_session(target, sid);
			if (session)
				res = iscsi_session_remove(session);
		}
	} else if (!iscsi_strcmp(ptr, "device ")) {
		if (!iscsi_strcmp(ptr, "attach ")) {
			struct iscsi_lun *lun;
			struct target_device *dev;
			u32 dev_id, lun_id = iscsi_strtoul(ptr);

			lun = iscsi_target_lookup_lun(target, lun_id);
			res = -EEXIST;
			if (!lun) {
				dev_id = iscsi_strtoul(ptr);
				dev = iscsi_device_lookup_devid(dev_id);
				res = -ENXIO;
				if (dev)
					res = iscsi_device_attach(target, dev, lun_id);
			}
		} else if (!iscsi_strcmp(ptr, "detach ")) {
			struct iscsi_lun *lun;
			u32 id = iscsi_strtoul(ptr);

			lun = iscsi_target_lookup_lun(target, id);
			if (lun)
				res = iscsi_device_detach(lun);
		}
	} else if (!iscsi_strcmp(ptr, "remove")) {
		res = iscsi_target_remove(target);
	}

	if (res)
		printk("failed with %d\n", res);

	return count;
}

iscsi_proc_string(iscsi_target_name, struct iscsi_target, name)
iscsi_proc_string(iscsi_target_alias, struct iscsi_target, alias)


int iscsi_target_proc_init(struct iscsi_target *target)
{
	char str[16];

	sprintf(str, "%u", target->target.id);
	target->target.proc_dir = proc_mkdir(str, iscsi_target_dir);
	target->proc_param_dir = proc_mkdir("param", target->target.proc_dir);
	target->proc_lun_dir = proc_mkdir("lun", target->target.proc_dir);
	target->proc_session_dir = proc_mkdir("session", target->target.proc_dir);

	iscsi_param_proc_init(target->proc_param_dir, &target->default_param);

	iscsi_proc_create("target", target->target.proc_dir, iscsi_target_target_read,
			iscsi_target_target_write, target);
	iscsi_proc_create("name", target->target.proc_dir, iscsi_target_name_read,
			iscsi_target_name_write, target);
	iscsi_proc_create("alias", target->target.proc_dir, iscsi_target_alias_read,
			iscsi_target_alias_write, target);

	return 0;
}

void iscsi_target_proc_exit(struct iscsi_target *target)
{
	iscsi_proc_rmdir(target->proc_param_dir);
	//iscsi_proc_rmdir(target->proc_lun_dir);
	//iscsi_proc_rmdir(target->proc_session_dir);
	iscsi_proc_rmdir(target->target.proc_dir);
}

/***************************************************************************************/
/*                                        DEVICE                                       */
/***************************************************************************************/

static int iscsi_device_device_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	return 0;
}

static int iscsi_device_device_write(struct file *file, const char *buffer, unsigned long count, void *data)
{
	struct target_device *dev = data;
	char buf[512], *ptr = buf;
	int res = 0;

	if (count > 511)
		count = 511;
	copy_from_user(buf, buffer, count);
	buf[count] = 0;
	ptr = buf;

	if (!iscsi_strcmp(ptr, "close")) {
		res = iscsi_device_remove(dev);
	} else if (!iscsi_strcmp(ptr, "remove")) {
		res = iscsi_device_remove(dev);
	}

	if (res)
		printk("failed with %d\n", res);

	return count;
}

static int iscsi_device_fd_readlink(struct dentry *dentry,
				    char *buffer, int buflen)
{
	struct proc_dir_entry *proc = dentry->d_inode->u.generic_ip;
	struct target_device *dev = proc->data;
	char *path = __getname();
	int res;

	res = vfs_readlink(dentry, buffer, buflen,
			   d_path(dev->file->f_dentry, dev->file->f_vfsmnt,
				  path, PATH_MAX));
	putname(path);
	return res;
}

static int iscsi_device_fd_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct proc_dir_entry *proc = dentry->d_inode->u.generic_ip;
	struct target_device *dev = proc->data;
	char *path = __getname();
	int res;

	res = vfs_follow_link(nd, d_path(dev->file->f_dentry, dev->file->f_vfsmnt,
					 path, PATH_MAX));
	putname(path);
	return res;
}

static struct inode_operations iscsi_device_fd_iops = {
	.readlink	= iscsi_device_fd_readlink,
	.follow_link	= iscsi_device_fd_follow_link,
};

int iscsi_device_proc_init(struct target_device *dev)
{
	char str[16];

	sprintf(str, "%u", dev->id);
	dev->proc_dir = proc_mkdir(str, iscsi_device_dir);

	iscsi_proc_create("device", dev->proc_dir, iscsi_device_device_read,
			iscsi_device_device_write, dev);

	iscsi_proc_link("fd", dev->proc_dir, &iscsi_device_fd_iops, dev);

	return 0;
}

void iscsi_device_proc_exit(struct target_device *dev)
{
	iscsi_proc_rmdir(dev->proc_dir);
}

/***************************************************************************************/
/*                                          LUN                                        */
/***************************************************************************************/

static int iscsi_lun_lun_read(char *page, char **start, off_t off, int count, int *eof, void *data)
{
	return 0;
}

static int iscsi_lun_lun_write(struct file *file, const char *buffer, unsigned long count, void *data)
{
	struct iscsi_lun *lun = data;
	char buf[512], *ptr = buf;
	int res = 0;

	if (count > 511)
		count = 511;
	copy_from_user(buf, buffer, count);
	buf[count] = 0;
	ptr = buf;

	if (!iscsi_strcmp(ptr, "detach")) {
		res = iscsi_device_detach(lun);
	} else if (!iscsi_strcmp(ptr, "remove")) {
		res = iscsi_device_detach(lun);
	}

	if (res)
		printk("failed with %d\n", res);

	return count;
}

static int iscsi_lun_device_readlink(struct dentry *dentry,
				    char *buffer, int buflen)
{
	struct proc_dir_entry *proc = dentry->d_inode->u.generic_ip;
	struct iscsi_lun *lun = proc->data;
	char buf[32];

	sprintf(buf, "../../../../device/%u", lun->device->id);
	return vfs_readlink(dentry, buffer, buflen, buf);
}

static int iscsi_lun_device_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	struct proc_dir_entry *proc = dentry->d_inode->u.generic_ip;
	struct iscsi_lun *lun = proc->data;
	char buf[32];

	sprintf(buf, "../../../../device/%u", lun->device->id);
	return vfs_follow_link(nd, buf);
}

static struct inode_operations iscsi_lun_device_iops = {
	.readlink	= iscsi_lun_device_readlink,
	.follow_link	= iscsi_lun_device_follow_link,
};

int iscsi_lun_proc_init(struct iscsi_lun *lun)
{
	char str[16];

	sprintf(str, "%u", lun->lun);
	lun->proc_dir = proc_mkdir(str, lun->target->proc_lun_dir);

	iscsi_proc_create("lun", lun->proc_dir, iscsi_lun_lun_read,
			iscsi_lun_lun_write, lun);

	iscsi_proc_link("device", lun->proc_dir, &iscsi_lun_device_iops, lun);

	return 0;
}

void iscsi_lun_proc_exit(struct iscsi_lun *lun)
{
	iscsi_proc_rmdir(lun->proc_dir);
}

/***************************************************************************************/
/*                                        SESSION                                      */
/***************************************************************************************/

static int iscsi_session_session_read(char *page, char **start, off_t off,
				      int count, int *eof, void *data)
{
	return 0;
}

static int iscsi_session_session_write(struct file *file, const char *buffer,
				       unsigned long count, void *data)
{
	struct iscsi_session *session = data;
	char buf[512], *ptr = buf;
	int res = 0;

	if (count > 511)
		count = 511;
	copy_from_user(buf, buffer, count);
	buf[count] = 0;
	ptr = buf;

	if (!iscsi_strcmp(ptr, "conn ")) {
		if (!iscsi_strcmp(ptr, "add ")) {
			struct iscsi_conn *conn;
			u16 cid = iscsi_strtoul(ptr);

			down(&iscsi_sem);
			conn = iscsi_session_lookup_conn(session, cid);
			res = -EEXIST;
			if (!conn)
				res = iscsi_conn_create(session, cid);
			up(&iscsi_sem);
		} else if (!iscsi_strcmp(ptr, "remove ")) {
			struct iscsi_conn *conn;
			u16 cid = iscsi_strtoul(ptr);

			down(&iscsi_sem);
			conn = iscsi_session_lookup_conn(session, cid);
			res = -ENOENT;
			if (conn)
				res = iscsi_conn_remove(conn);
			up(&iscsi_sem);
		}
	} else if (!iscsi_strcmp(ptr, "terminate")) {
		//iscsi_
	} else if (!iscsi_strcmp(ptr, "remove")) {
		res = iscsi_session_remove(session);
	}

	if (res)
		printk("failed with %d\n", res);

	return count;
}

iscsi_proc_int64_read(iscsi_session_sid, struct iscsi_session, sid)
iscsi_proc_string(iscsi_session_initiator, struct iscsi_session, initiator)
iscsi_proc_int(iscsi_session_exp_cmd_sn, struct iscsi_session, exp_cmd_sn)
iscsi_proc_int(iscsi_session_max_cmd_sn, struct iscsi_session, max_cmd_sn)

int iscsi_session_proc_init(struct iscsi_session *session)
{
	char str[16];

	sprintf(str, "%#Lx", session->sid);
	session->proc_dir = proc_mkdir(str, session->target->proc_session_dir);
	session->proc_param_dir = proc_mkdir("param", session->proc_dir);
	session->proc_conn_dir = proc_mkdir("conn", session->proc_dir);

	iscsi_proc_create("session", session->proc_dir, iscsi_session_session_read,
			iscsi_session_session_write, session);
	iscsi_proc_create("sid", session->proc_dir, iscsi_session_sid_read, NULL, session);
	iscsi_proc_create("initiator", session->proc_dir, iscsi_session_initiator_read,
			iscsi_session_initiator_write, session);
	iscsi_proc_create("exp_cmd_sn", session->proc_dir, iscsi_session_exp_cmd_sn_read,
			iscsi_session_exp_cmd_sn_write, session);
	iscsi_proc_create("max_cmd_sn", session->proc_dir, iscsi_session_max_cmd_sn_read,
			iscsi_session_max_cmd_sn_write, session);

	iscsi_param_proc_init(session->proc_param_dir, &session->param);

	return 0;
}

void iscsi_session_proc_exit(struct iscsi_session *session)
{
	//iscsi_proc_rmdir(session->proc_conn_dir);
	iscsi_proc_rmdir(session->proc_param_dir);
	iscsi_proc_rmdir(session->proc_dir);
}

/***************************************************************************************/
/*                                      CONNECTION                                     */
/***************************************************************************************/

static int iscsi_conn_conn_read(char *page, char **start, off_t off,
				int count, int *eof, void *data)
{
	return 0;
}

static int iscsi_conn_conn_write(struct file *file, const char *buffer,
				 unsigned long count, void *data)
{
	struct iscsi_conn *conn = data;
	char buf[512], *ptr = buf;
	int res = 0;

	if (count > 511)
		count = 511;
	copy_from_user(buf, buffer, count);
	buf[count] = 0;
	ptr = buf;

	if (!iscsi_strcmp(ptr, "takefd ")) {
		int fd = simple_strtoul(ptr, NULL, 0);
		down(&iscsi_sem);
		res = iscsi_conn_takefd(conn, fd);
		up(&iscsi_sem);
	} else if (!iscsi_strcmp(ptr, "logout ")) {
		int timeout = iscsi_strtoul(ptr);

		iscsi_conn_logout(conn, timeout);
	} else if (!iscsi_strcmp(ptr, "shutdown ")) {
		//res = iscsi_conn
	} else if (!iscsi_strcmp(ptr, "close")) {
		down(&iscsi_sem);
		iscsi_conn_closefd(conn);
		up(&iscsi_sem);
	} else if (!iscsi_strcmp(ptr, "remove")) {
		down(&iscsi_sem);
		iscsi_conn_remove(conn);
		up(&iscsi_sem);
	}

	if (res)
		printk("failed with %d\n", res);

	return count;
}

iscsi_proc_int_read(iscsi_conn_cid, struct iscsi_conn, cid)
iscsi_proc_int_read(iscsi_conn_state, struct iscsi_conn, state)
iscsi_proc_int(iscsi_conn_stat_sn, struct iscsi_conn, stat_sn)
iscsi_proc_int(iscsi_conn_exp_stat_sn, struct iscsi_conn, exp_stat_sn)

int iscsi_conn_proc_init(struct iscsi_conn *conn)
{
	char str[16];

	sprintf(str, "%u", conn->cid);
	conn->proc_dir = proc_mkdir(str, conn->session->proc_conn_dir);

	iscsi_proc_create("conn", conn->proc_dir, iscsi_conn_conn_read,
			iscsi_conn_conn_write, conn);
	iscsi_proc_create("cid", conn->proc_dir, iscsi_conn_cid_read, NULL, conn);
	iscsi_proc_create("state", conn->proc_dir, iscsi_conn_state_read, NULL, conn);
	iscsi_proc_create("stat_sn", conn->proc_dir, iscsi_conn_stat_sn_read,
			iscsi_conn_stat_sn_write, conn);
	iscsi_proc_create("exp_stat_sn", conn->proc_dir, iscsi_conn_exp_stat_sn_read,
			iscsi_conn_exp_stat_sn_write, conn);

	return 0;
}

void iscsi_conn_proc_exit(struct iscsi_conn *conn)
{
	iscsi_proc_rmdir(conn->proc_dir);
}

/***************************************************************************************/
/*                                         MAIN                                        */
/***************************************************************************************/

struct list_head iscsi_conn_closed_list;
DECLARE_WAIT_QUEUE_HEAD(iscsi_ctl_wait);

static void *iscsi_ctl_start(struct seq_file *seq, loff_t *pos)
{
	struct iscsi_conn *conn;

	if (list_empty(&iscsi_conn_closed_list))
		return ERR_PTR(-EAGAIN);
	conn = list_entry(iscsi_conn_closed_list.next, struct iscsi_conn, poll_list);
	list_del_init(&conn->poll_list);
	return conn;
}

static void *iscsi_ctl_next(struct seq_file *seq, void *p, loff_t *pos)
{
	return iscsi_ctl_start(seq, pos);
}

static void iscsi_ctl_stop(struct seq_file *seq, void *p)
{
}

static int iscsi_ctl_show(struct seq_file *seq, void *p)
{
	struct iscsi_conn *conn = p;
	seq_printf(seq, "target %u session %#Lx conn %u closed\n", conn->session->target->target.id, conn->session->sid, conn->cid);
	return 0;
}

static ssize_t iscsi_ctl_write(struct file *file, const char *buffer,
			       size_t count, loff_t *pos)
{
	char buf[512], *ptr = buf;
	int res = 0;

	if (count > 511)
		count = 511;
	copy_from_user(buf, buffer, count);
	buf[count] = 0;
	ptr = buf;

	if (!iscsi_strcmp(ptr, "target ")) {
		if (!iscsi_strcmp(ptr, "add ")) {
			struct iscsi_target *target;
			u32 id = iscsi_strtoul(ptr);

			down(&iscsi_sem);
			target = iscsi_target_lookup(id);
			res = -EEXIST;
			if (!target)
				res = iscsi_target_create(id, ptr);
			up(&iscsi_sem);
		} else if (!iscsi_strcmp(ptr, "remove ")) {
			struct iscsi_target *target;
			u32 id = iscsi_strtoul(ptr);

			down(&iscsi_sem);
			target = iscsi_target_lookup(id);
			res = -ENOENT;
			if (target)
				res = iscsi_target_remove(target);
			up(&iscsi_sem);
		}
	} else if (!iscsi_strcmp(ptr, "device ")) {
		if (!iscsi_strcmp(ptr, "add ")) {
			struct target_device *dev;
			u32 id = iscsi_strtoul(ptr);

			down(&iscsi_sem);
			dev = iscsi_device_lookup_devid(id);
			res = -EEXIST;
			if (!dev)
				res = iscsi_device_create(id, ptr);
			up(&iscsi_sem);
		} else if (!iscsi_strcmp(ptr, "remove ")) {
			struct target_device *dev;
			u32 id = iscsi_strtoul(ptr);

			down(&iscsi_sem);
			dev = iscsi_device_lookup_devid(id);
			res = -ENOENT;
			if (dev)
				res = iscsi_device_remove(dev);
			up(&iscsi_sem);
		}
	}

	if (res)
		printk("failed with %d\n", res);

	return count;
}

static struct seq_operations iscsi_seq_op = {
	.start	= iscsi_ctl_start,
	.next	= iscsi_ctl_next,
	.stop	= iscsi_ctl_stop,
	.show	= iscsi_ctl_show,
};

static unsigned int iscsi_ctl_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &iscsi_ctl_wait, wait);
	return list_empty(&iscsi_conn_closed_list) ? 0 : POLLIN | POLLRDNORM;
}

static int iscsi_ctl_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &iscsi_seq_op);
}

static int iscsi_ctl_close(struct inode *inode, struct file *file)
{
	return seq_release(inode, file);
}

static struct file_operations iscsi_ctl_fops = {
	.open		= iscsi_ctl_open,
	.poll		= iscsi_ctl_poll,
	.write		= iscsi_ctl_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= iscsi_ctl_close,
};

#if TARGET_EVENTS
static int iscsi_proc_debug(struct file *file, const char *buffer, unsigned long count, void *data)
{
	if (count == 1)
		target_print_events();
	return count;
}
#endif

int iscsi_proc_init(void)
{
	struct proc_dir_entry *iscsi_ctl;

	INIT_LIST_HEAD(&iscsi_conn_closed_list);

	iscsi_dir = proc_mkdir("iscsi", 0);
	iscsi_target_dir = proc_mkdir("target", iscsi_dir);
	iscsi_device_dir = proc_mkdir("device", iscsi_dir);

	iscsi_ctl = create_proc_entry("iscsi", 0, iscsi_dir);
	if (iscsi_ctl) {
		iscsi_ctl->owner = THIS_MODULE;
		iscsi_ctl->proc_fops = &iscsi_ctl_fops;
	}
#if TARGET_EVENTS
	iscsi_proc_create("debug", iscsi_dir, NULL, iscsi_proc_debug, NULL);
#endif

	return 0;
}

void iscsi_proc_exit(void)
{
	iscsi_proc_rmdir(iscsi_dir);	
}
