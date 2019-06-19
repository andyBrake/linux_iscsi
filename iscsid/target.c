/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "iscsid.h"

struct target *targets;
struct device *devices;

int target_next_id = 0;
int device_next_id = 0;

static struct device *device_get(char *path);
static void device_set_path(struct device *device);

static char *target_sep_string(char **pp)
{
	char *p = *pp;
	char *q;

	for (p = *pp; isspace(*p); p++)
		;
	for (q = p; *q && !isspace(*q); q++)
		;
	if (*q)
		*q++ = 0;
	else
		p = NULL;
	*pp = q;
	return p;
}

static void target_sep_bool(char **pp, u32 *flags, int mask)
{
	char *p;

	p = target_sep_string(pp);
	if (!p)
		return;
	switch (*p) {
	case 'y': case 'Y':
		*flags |= mask;
		break;
	case 'n': case 'N':
		*flags &= ~mask;
		break;
	}
}

#define BUFSIZE 4096

void target_scan(void)
{
	DIR *dir;
	FILE *config;
	struct stat info;
	struct dirent *dirent;
	struct target *target;
	struct target_lun *tlun;
	struct device *device;
	char buf[BUFSIZE];
	char *p, *q;
	int lun, skip;

	dir = opendir(PROC_DEVICEDIR);
	if (!dir) {
		log_error("unable to open %s! (%s)", PROC_DEVICEDIR, strerror(errno));
		exit(1);
	}

	while ((dirent = readdir(dir))) {
		if (!isdigit(dirent->d_name[0]))
			continue;

		device = xmalloc(sizeof(*device));
		memset(device, 0, sizeof(*device));

		device->id = atoi(dirent->d_name);
		if (device_next_id <= device->id)
			device_next_id = device->id + 1;

		device_set_path(device);
		strcat(procPath, "/fd");
		if (stat(procPath, &info))
			;

		device->dev = info.st_dev;
		device->ino = info.st_ino;

		device->next = devices;
		devices = device;
	}
	closedir(dir);

	dir = opendir(PROC_TARGETDIR);
	if (!dir) {
		log_error("unable to open %s! (%s)", PROC_TARGETDIR, strerror(errno));
		exit(1);
	}

	while ((dirent = readdir(dir))) {
		u32 id;
		char *name;

		if (!isdigit(dirent->d_name[0]))
			continue;

		id = atoi(dirent->d_name);
		sprintf(procPath, "%s/%u", PROC_TARGETDIR, id);
		proc_read_string("name", &name);
		log_debug(1, "active target %d: %s", id, name);
		target = target_find_name(name);
		if (!target) {
			target = xmalloc(sizeof(*target));
			memset(target, 0, sizeof(*target));
			target->next = targets;
			targets = target;
			target->name = name;
			param_set_linux_default(&target->default_param);
		}
		target->id = id;
		session_scan(target);
		if (!target->session_cnt) {
			log_debug(1, "removing target %d", id);
			target_remove(target);
			continue;
		}

		if (target_next_id <= target->id)
			target_next_id = target->id + 1;
	}
	closedir(dir);

	config = fopen("/etc/iscsid.config", "r");
	if (!config)
		return;

	target = NULL;
	skip = 1;
	while (fgets(buf, BUFSIZE, config)) {
		q = buf;
		p = target_sep_string(&q);
		if (!p || *p == '#')
			continue;

		if (!strcmp(p, "Target")) {
			p = target_sep_string(&q);
			if (!p) {
				skip = 1;
				continue;
			}
			skip = 0;
			target = target_find_name(p);
			if (!target) {
				log_debug(1, "creaing target %u: %s", target_next_id, p);
				target = xmalloc(sizeof(*target));
				memset(target, 0, sizeof(*target));
				target->id = target_next_id++;
				target->name = strdup(p);
				param_set_linux_default(&target->default_param);

				target->next = targets;
				targets = target;

				strcpy(procPath, "/proc/iscsi");
				proc_write("iscsi", "target add %u", target->id);
			}
			target_set_path(target);
			proc_write("name", "%s", target->name);
		} else if (!strcmp(p, "Alias")) {
			if (skip)
				continue;
			p = target_sep_string(&q);
			target->alias = strdup(p);
			target_set_path(target);
			proc_write("alias", "%s", target->alias);
		} else if (!strcmp(p, "MaxConnections")) {
			if (skip)
				continue;
			target->default_param.max_connections = strtol(q, &q, 0);
		} else if (!strcmp(p, "InitialR2T")) {
			if (skip)
				continue;
			target_sep_bool(&q, &target->default_param.flags,
					SESSION_FLG_INITIAL_R2T);
		} else if (!strcmp(p, "ImmediateData")) {
			if (skip)
				continue;
			target_sep_bool(&q, &target->default_param.flags,
					SESSION_FLG_IMMEDIATE_DATA);
		} else if (!strcmp(p, "MaxRecvDataSegmentLength")) {
			if (skip)
				continue;
			target->default_param.max_data_pdu_length = strtol(q, &q, 0);
		} else if (!strcmp(p, "MaxBurstLength")) {
			if (skip)
				continue;
			target->default_param.max_burst_length = strtol(q, &q, 0);
		} else if (!strcmp(p, "FirstBurstLength")) {
			if (skip)
				continue;
			target->default_param.first_burst_length = strtol(q, &q, 0);
		} else if (!strcmp(p, "DefaultTime2Wait")) {
			if (skip)
				continue;
			target->default_param.default_wait_time = strtol(q, &q, 0);
		} else if (!strcmp(p, "DefaultTime2Retain")) {
			if (skip)
				continue;
			target->default_param.default_retain_time = strtol(q, &q, 0);
		} else if (!strcmp(p, "MaxOutstandingR2T")) {
			if (skip)
				continue;
			target->default_param.max_outstanding_r2t = strtol(q, &q, 0);
		} else if (!strcmp(p, "DataPDUInOrder")) {
			if (skip)
				continue;
			target_sep_bool(&q, &target->default_param.flags,
					SESSION_FLG_DATA_PDU_INORDER);
		} else if (!strcmp(p, "DataSequenceInOrder")) {
			if (skip)
				continue;
			target_sep_bool(&q, &target->default_param.flags,
					SESSION_FLG_DATA_SEQUENCE_INORDER);
		} else if (!strcmp(p, "ErrorRecoveryLevel")) {
			if (skip)
				continue;
		} else if (!strcmp(p, "Lun")) {
			if (skip)
				continue;
			lun = strtol(q, &q, 10);

			p = target_sep_string(&q);
			if (!p)
				;
			device = device_get(p);
			if (!device)
				continue;
			tlun = xmalloc(sizeof(*tlun));
			tlun->device = device;
			tlun->lun = lun;
			tlun->next = target->luns;
			target->luns = tlun;
		} else if (!strcmp(p, "User")) {
			struct user *user;
			char *name, *pass;

			name = target_sep_string(&q);
			pass = target_sep_string(&q);
			if (!name || !pass)
				continue;

			user = xmalloc(sizeof(*user) + strlen(name) + strlen(pass) + 2);
			user->name = (char *)user + sizeof(*user);
			user->password = user->name + strlen(name) + 1;
			strcpy(user->name, name);
			strcpy(user->password, pass);

			if (target) {
				user->next = target->users;
				target->users = user;
			} else {
				user->next = iscsi_discover_users;
				iscsi_discover_users = user;
			}
		}
	}
	fclose(config);

	for (target = targets; target; target = target->next) {
		char *ptr;

		if (!target->luns) {
			log_warning("need to shutdown target %s", target->name);
			/* close all sessions */
			continue;
		}
		target_set_path(target);
		ptr = procPath + strlen(procPath);
		for (tlun = target->luns; tlun; tlun = tlun->next) {
			sprintf(ptr, "/lun/%u", tlun->lun);
			if (!stat(procPath, &info)) {
				log_debug(0, "lun %u:%u already configured", target->id, tlun->lun);
				/* reconfigure lun */
				continue;
			}
			*ptr = 0;
			log_debug(1, "attaching %u to %u:%u", tlun->device->id, target->id, tlun->lun);
			proc_write("target", "device attach %u %u", tlun->lun, tlun->device->id);
		}
	}
}

struct target *target_find_name(const char *name)
{
	struct target *target;

	log_debug(1, "target_find_name: %s", name);
	for (target = targets; target; target = target->next) {
		if (!strcmp(target->name, name))
			break;
	}
	return target;
}

struct target *target_find_id(u32 id)
{
	struct target *target;

	log_debug(1, "target_find_id: %u", id);
	for (target = targets; target; target = target->next) {
		if (target->id == id)
			break;
	}
	return target;
}

int target_remove(struct target *target)
{
	struct target **tp;
	DIR *dir;
	struct dirent *dirent;
	struct stat info;

	log_debug(1, "target_remove: %u,%s", target->id, target->name);
	target_set_path(target);
	strcat(procPath, "/lun");
	dir = opendir(procPath);
	if (!dir)
		goto out;

	while ((dirent = readdir(dir))) {
		if (!isdigit(dirent->d_name[0]))
			continue;
		target_set_path(target);
		proc_write("target", "device detach %u", atoi(dirent->d_name));
	}
	closedir(dir);

	strcpy(procPath, "/proc/iscsi");
	proc_write("iscsi", "target remove %u", target->id);

out:
	for (tp = &targets; *tp; tp = &(*tp)->next) {
		if (*tp == target) {
			*tp = target->next;
			break;
		}
	}
	target_set_path(target);
	free(target->name);
	free(target->alias);
	free(target);
	return stat(procPath, &info) ? 0 : -1;
}

void target_set_path(struct target *target)
{
	sprintf(procPath, "%s/%u", PROC_TARGETDIR, target->id);
}

static struct device *device_get(char *path)
{
	struct device *device;
	struct stat info;

	if (stat(path, &info))
		return NULL;

	for (device = devices; device; device = device->next) {
		if (device->dev == info.st_dev && device->ino == info.st_ino) {
			if (!device->path)
				device->path = strdup(path);
			return device;
		}
	}
	device = xmalloc(sizeof(*device));
	memset(device, 0, sizeof(*device));
	device->id = device_next_id++;
	device->path = strdup(path);
	device->dev = info.st_dev;
	device->ino = info.st_ino;

	strcpy(procPath, "/proc/iscsi");
	proc_write("iscsi", "device add %u %s", device->id, device->path);

	device->next = devices;
	devices = device;

	return device;
}

static void device_set_path(struct device *device)
{
	sprintf(procPath, "%s/%u", PROC_DEVICEDIR, device->id);
}
