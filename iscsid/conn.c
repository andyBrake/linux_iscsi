/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <ctype.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/stat.h>

#include "iscsid.h"

#define ISCSI_CONN_NEW		1
#define ISCSI_CONN_EXIT		5

void conn_scan(struct session *session)
{
	DIR *dir;
	struct dirent *dirent;
	struct connection conn;
	u16 state;

	session_set_path(session);
	strcat(procPath, "/conn");
	dir = opendir(procPath);
	if (!dir)
		return;

	conn.session = session;
	while ((dirent = readdir(dir))) {
		if (!isdigit(dirent->d_name[0]))
			continue;

		conn.cid = atoi(dirent->d_name);

		conn_set_path(&conn);
		proc_read_u16("state", &state);
		switch (state) {
		case ISCSI_CONN_NEW:
		case ISCSI_CONN_EXIT:
			session_set_path(session);
			proc_write("session", "conn remove %u", conn.cid);
			break;
		default:
			session->conn_cnt++;
			if (!session->target->name)
				proc_write("conn", "logout");
			break;
		}
	}
	closedir(dir);
}

struct connection *conn_alloc(void)
{
	struct connection *conn;

	conn = xmalloc(sizeof(*conn));
	memset(conn, 0, sizeof(*conn));

	conn->state = STATE_FREE;
	param_set_default(&conn->param);

	return conn;
}

void conn_free(struct connection *conn)
{
	free(conn->initiator);
	free(conn);
}

int conn_test(struct connection *conn)
{
	struct stat statbuf;

	conn_set_path(conn);

	if (stat(procPath, &statbuf))
		return 0;
	else
		return 1;
}

void conn_take_fd(struct connection *conn, int fd)
{
	log_debug(1, "conn_take_fd: %u %u %u %Lx %d", conn->cid, conn->stat_sn, conn->exp_stat_sn, conn->sid.id64, fd);
	session_set_path(conn->session);
	proc_write("session", "conn add %u", conn->cid);
	conn->session->conn_cnt++;

	conn_set_path(conn);
	proc_write_u32("stat_sn", conn->stat_sn);
	proc_write_u32("exp_stat_sn", conn->exp_stat_sn);

	proc_write("conn", "takefd %u", fd);
}

void conn_read_pdu(struct connection *conn)
{
	conn->iostate = IOSTATE_READ_BHS;
	conn->buffer = (void *)&conn->req.bhs;
	conn->rwsize = BHS_SIZE;
}

void conn_write_pdu(struct connection *conn)
{
	conn->iostate = IOSTATE_WRITE_BHS;
	memset(&conn->rsp, 0, sizeof(conn->rsp));
	conn->buffer = (void *)&conn->rsp.bhs;
	conn->rwsize = BHS_SIZE;
}

void conn_free_pdu(struct connection *conn)
{
	conn->iostate = IOSTATE_FREE;
	if (conn->req.ahs) {
		free(conn->req.ahs);
		conn->req.ahs = NULL;
	}
	if (conn->rsp.ahs) {
		free(conn->rsp.ahs);
		conn->rsp.ahs = NULL;
	}
	if (conn->rsp.data) {
		free(conn->rsp.data);
		conn->rsp.data = NULL;
	}
}

void conn_set_path(struct connection *conn)
{
	session_set_path(conn->session);
	sprintf(procPath + strlen(procPath), "/conn/%u", conn->cid);
}
