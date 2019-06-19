/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>

#include "iscsid.h"

struct session *session_alloc(struct target *target)
{
	struct session *session;

	session = xmalloc(sizeof(*session));
	memset(session, 0, sizeof(*session));
	session->target = target;
	if (target) {
		session->next = target->sessions;
		target->sessions = session;
	}

	return session;
}

static int session_test(struct session *session)
{
	struct stat statbuf;

	session_set_path(session);

	if (stat(procPath, &statbuf))
		return 0;
	else
		return 1;
}

struct session *session_find_name(struct target *target, const char *iname, union iscsi_sid sid)
{
	struct session *session;

	log_debug(1, "session_find_name: %s,%#Lx", iname, sid.id64);
	for (session = target->sessions; session; session = session->next) {
		if (!memcmp(sid.id.isid, session->sid.id.isid, 6) &&
		    !strcmp(iname, session->initiator))
			break;
	}
	return session;
}

struct session *session_find_id(struct target *target, u64 sid)
{
	struct session *session;

	log_debug(1, "session_find_id: %#Lx", sid);
	for (session = target->sessions; session; session = session->next) {
		if (session->sid.id64 == sid)
			break;
	}
	return session;
}

void session_scan(struct target *target)
{
	DIR *dir;
	struct dirent *dirent;
	struct session *session;

	target_set_path(target);
	strcat(procPath, "/session");
	dir = opendir(procPath);
	if (!dir)
		return;

	while ((dirent = readdir(dir))) {
		if (!isdigit(dirent->d_name[0]))
			continue;

		session = session_alloc(target);
		session->sid.id64 = strtoull(dirent->d_name, NULL, 0);
		conn_scan(session);

		target_set_path(target);
		if (!session->conn_cnt) {
			proc_write("target", "session remove %#Lx", session->sid.id64);
			session_remove(session);
		} else {
			session_set_path(session);
			proc_read_string("initiator", &session->initiator);
			session->next = target->sessions;
			target->sessions = session;
			target->session_cnt++;
		}
	}
	closedir(dir);
}

void session_create(struct connection *conn)
{
	struct session *session = session_alloc(conn->target);

	session->sid = conn->sid;
	for (session->sid.id.tsih = 1; session_test(session); session->sid.id.tsih++)
		;
	conn->session = session;

	log_debug(1, "session_create: %#Lx", session->sid.id64);
	target_set_path(session->target);
	proc_write("target", "session add %#Lx", session->sid.id64);

	conn->session->initiator = strdup(conn->initiator);
	session_set_path(conn->session);
	proc_write("initiator", conn->session->initiator);
	proc_write_u32("exp_cmd_sn", conn->exp_cmd_sn);
	proc_write_u32("max_cmd_sn", conn->max_cmd_sn);
}

void session_close(struct session *session)
{
	DIR *dir;
	struct dirent *dirent;
	struct connection conn;

	log_debug(1, "session_close: %#Lx", session->sid.id64);
	session_set_path(session);
	strcat(procPath, "/conn");
	dir = opendir(procPath);
	if (!dir)
		return;

	conn.sid = session->sid;
	conn.session = session;
	conn.target = session->target;
	while ((dirent = readdir(dir))) {
		if (!isdigit(dirent->d_name[0]))
			continue;

		conn.cid = atoi(dirent->d_name);
		conn_set_path(&conn);
		proc_write("conn", "close", conn.cid);
	}
	closedir(dir);
}

void session_remove(struct session *session)
{
	log_debug(1, "session_remove: %#Lx", session->sid.id64);
	if (!session->sid.id.tsih) {
		target_set_path(session->target);
		proc_write("target", "session remove %#Lx", session->sid.id64);
	}

	if (session->target) {
		struct session **sp;

		for (sp = &session->target->sessions; *sp; sp = &(*sp)->next) {
			if (*sp == session)
				break;
		}
		if (*sp)
			*sp = session->next;
		else
			log_warning("session_remove: session %#Lx not found?", session->sid.id64);
	}

	free(session->initiator);
	free(session);
}

void session_set_path(struct session *session)
{
	target_set_path(session->target);
	sprintf(procPath + strlen(procPath), "/session/%#Lx", session->sid.id64);
}
