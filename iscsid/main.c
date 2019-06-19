/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/poll.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include "iscsid.h"

#define INCOMING_MAX		32

#define POLL_MAX		(INCOMING_MAX + 2)
#define POLL_LISTEN		0
#define POLL_CTRL		1
#define POLL_INCOMING		2

static struct pollfd poll_array[POLL_MAX];
static struct connection *incoming[INCOMING_MAX];
static int incoming_socket, incoming_cnt;
static int iscsi_ctrl_fd;

static void set_non_blocking(int fd)
{
	int res = fcntl(fd, F_GETFL);
	//int opt;

	if (res != -1) {
		res = fcntl(fd, F_SETFL, res | O_NONBLOCK);
		if (res)
			log_warning("unable to set fd flags (%s)!", strerror(errno));
	} else
		log_warning("unable to get fd flags (%s)!", strerror(errno));

	//opt = IPTOS_LOWDELAY;
	//if (setsockopt(fd, SOL_IP, IP_TOS, &opt, sizeof(int)) < 0)
	//	log_warning("unable to set socket tos (%s)!", strerror(errno));
}

static int create_listen_socket(void)
{
	struct sockaddr_in name;
	int sock;
	int opt;

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock == -1) {
		log_error("unable to create server socket (%s)!", strerror(errno));
		exit(1);
	}

	opt = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)))
		log_warning("unable to set SO_REUSEADDR on server socket (%s)!", strerror(errno));

	//opt = 0;
	//if (setsockopt(sock, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt)))
	//	log_warning("unable to set TCP_NODELAY on server socket (%s)!", strerror(errno));

	name.sin_family = AF_INET;
	name.sin_port = htons(3260);
	name.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sock, (struct sockaddr *)&name, sizeof(name))) {
		log_error("unable to bind server socket (%s)!", strerror(errno));
		exit(1);
	}

	if (listen(sock, INCOMING_MAX)) {
		log_error("unable to listen to server socket (%s)!", strerror(errno));
		exit(1);
	}

	set_non_blocking(sock);

	return sock;
}

static void accept_connection(void)
{
	struct sockaddr_in name;
	socklen_t namesize;
	struct pollfd *pollfd;
	struct connection *conn;
	int fd, i;

	namesize = sizeof(name);
	fd = accept(incoming_socket, (struct sockaddr *)&name, &namesize);
	if (fd < 0) {
		if (errno != EINTR && errno != EAGAIN) {
			perror("accept(incoming_socket)");
			exit(1);
		}
		return;
	}

	log_debug(0, "connection request from %s", inet_ntoa(name.sin_addr));
	for (i = 0; i < INCOMING_MAX; i++) {
		if (!incoming[i])
			break;
	}
	if (i >= INCOMING_MAX) {
		fprintf(stderr, "unable to find incoming slot?\n");
		exit(1);
	}

	conn = conn_alloc();
	conn->fd = fd;
	incoming[i] = conn;
	conn_read_pdu(conn);

	set_non_blocking(fd);
	pollfd = &poll_array[POLL_INCOMING + i];
	pollfd->fd = fd;
	pollfd->events = POLLIN;
	pollfd->revents = 0;

	incoming_cnt++;
	if (incoming_cnt >= INCOMING_MAX)
		poll_array[POLL_LISTEN].events = 0;
}

void handle_iscsi_events(void)
{
	struct target *target;
	struct session *session;
	char *p, *q;
	int res;

	while (1) {
		res = read(iscsi_ctrl_fd, procData, sizeof(procData) - 1);
		if (res < 0) {
			if (errno == EAGAIN)
				return;
			if (errno == EINTR)
				continue;
			log_error("error reading /proc/iscsi/iscsi (%d)", errno);
			exit(1);
		}
		procData[res] = 0;
		q = procData;
		while ((p = strsep(&q, "\n"))) {
			u32 target_id, conn_id;
			u64 session_id;

			if (!*p)
				continue;
			res = sscanf(p, "target %u session %Lx conn %u closed", &target_id, &session_id, &conn_id);
			if (res < 3) {
				log_warning("iscsi_ctrl: failed to scan '%s'", p);
				continue;
			}
			log_debug(1, "close conn %u session %Lx target %u", conn_id, session_id, target_id);
			target = target_find_id(target_id);
			if (!target) {
				log_warning("target %u not found?", target_id);
				continue;
			}
			session = session_find_id(target, session_id);
			if (!session) {
				log_warning("session %#Lx not found?", session_id);
				continue;
			}
			session_set_path(session);
			proc_write("session", "conn remove %u", conn_id);
			session->conn_cnt--;
			if (!session->conn_cnt)
				session_remove(session);
		}
	}
}

void event_loop(void)
{
	int res, i, opt;
	struct connection *conn;
	struct pollfd *pollfd;

	incoming_socket = create_listen_socket();
	iscsi_ctrl_fd = open("/proc/iscsi/iscsi", O_RDONLY | O_NONBLOCK);

	poll_array[POLL_LISTEN].fd = incoming_socket;
	poll_array[POLL_LISTEN].events = POLLIN;
	poll_array[POLL_CTRL].fd = iscsi_ctrl_fd;
	poll_array[POLL_CTRL].events = POLLIN;
	for (i = 0; i < INCOMING_MAX; i++) {
		poll_array[POLL_INCOMING + i].fd = -1;
		poll_array[POLL_INCOMING + i].events = 0;
		incoming[i] = NULL;
	}

	while (1) {
		res = poll(poll_array, POLL_MAX, -1);
		if (res <= 0) {
			if (res < 0 && errno != EINTR) {
				perror("poll()");
				exit(1);
			}
			continue;
		}

		if (poll_array[POLL_LISTEN].revents && incoming_cnt < INCOMING_MAX)
			accept_connection();

		if (poll_array[POLL_CTRL].revents)
			handle_iscsi_events();
			
		for (i = 0; i < INCOMING_MAX; i++) {
			conn = incoming[i];
			pollfd = &poll_array[POLL_INCOMING + i];
			if (!conn || !pollfd->revents)
				continue;

			pollfd->revents = 0;

			switch (conn->iostate) {
			case IOSTATE_READ_BHS: 
			case IOSTATE_READ_AHS_DATA: 
			read_again: 
				res = read(pollfd->fd, conn->buffer, conn->rwsize);
				if (res <= 0) {
					if (res == 0 || (errno != EINTR && errno != EAGAIN))
						conn->state = STATE_CLOSE;
					else if (errno == EINTR)
						goto read_again;
					break;
				}
				conn->rwsize -= res;
				conn->buffer += res;
				if (conn->rwsize)
					break;

				switch (conn->iostate) {
				case IOSTATE_READ_BHS: 
					conn->iostate = IOSTATE_READ_AHS_DATA;
					conn->req.ahssize = conn->req.bhs.ahslength * 4;
					conn->req.datasize = ((conn->req.bhs.datalength[0] << 16) + 
							      (conn->req.bhs.datalength[1] << 8) + 
							      conn->req.bhs.datalength[2]);
					conn->rwsize = (conn->req.ahssize + conn->req.datasize + 3) & -4;
					if (conn->rwsize) {
						if (!conn->req_buffer)
							conn->req_buffer = malloc(INCOMING_BUFSIZE);
						conn->buffer = conn->req_buffer;
						conn->req.ahs = conn->buffer;
						conn->req.data = conn->buffer + conn->req.ahssize;
						goto read_again;
					}

				case IOSTATE_READ_AHS_DATA: 
					conn_write_pdu(conn);
					pollfd->events = POLLOUT;

					log_pdu(2, &conn->req);
					if (!cmnd_execute(conn))
						conn->state = STATE_CLOSE;
					break;
				}
				break;

			case IOSTATE_WRITE_BHS: 
			case IOSTATE_WRITE_AHS: 
			case IOSTATE_WRITE_DATA: 
			write_again: 
				opt = 1;
				setsockopt(pollfd->fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
				res = write(pollfd->fd, conn->buffer, conn->rwsize);
				if (res < 0) {
					if (errno != EINTR && errno != EAGAIN)
						conn->state = STATE_CLOSE;
					else if (errno == EINTR)
						goto write_again;
					break;
				}

				conn->rwsize -= res;
				conn->buffer += res;
				if (conn->rwsize)
					goto write_again;

				switch (conn->iostate) {
				case IOSTATE_WRITE_BHS: 
					if (conn->rsp.ahssize) {
						conn->iostate = IOSTATE_WRITE_AHS;
						conn->buffer = conn->rsp.ahs;
						conn->rwsize = conn->rsp.ahssize;
						goto write_again;
					}
				case IOSTATE_WRITE_AHS: 
					if (conn->rsp.datasize) {
						int o;

						conn->iostate = IOSTATE_WRITE_DATA;
						conn->buffer = conn->rsp.data;
						conn->rwsize = conn->rsp.datasize;
						o = conn->rwsize & 3;
						if (o) {
							for (o = 4 - o; o; o--)
								*((u8 *)conn->buffer + conn->rwsize++) = 0;
						}
						goto write_again;
					}
				case IOSTATE_WRITE_DATA: 
					opt = 0;
					setsockopt(pollfd->fd, SOL_TCP, TCP_CORK, &opt, sizeof(opt));
					cmnd_finish(conn);

					switch (conn->state) {
					case STATE_KERNEL:
						conn_take_fd(conn, pollfd->fd);
						conn->state = STATE_CLOSE;
						break;
					case STATE_EXIT:
					case STATE_CLOSE:
						break;
					default:
						conn_read_pdu(conn);
						pollfd->events = POLLIN;
						break;
					}
					break;
				}

				break;
			default: 
				fprintf(stderr, "illegal iostate %d for port %d!\n", conn->iostate, i);
				exit(1);
			}

			if (conn->state == STATE_CLOSE) {
				log_debug(0, "connection closed");
				conn_free_pdu(conn);
				conn_free(conn);
				close(pollfd->fd);
				pollfd->fd = -1;
				incoming[i] = NULL;
				incoming_cnt--;
				poll_array[POLL_LISTEN].events = POLLIN;
			}
		}
	}
}

void *xmalloc(size_t size)
{
	if (!size)
		return NULL;
	return malloc(size);
}

int main(int ac, char **av)
{
	int ch;

	while ((ch = getopt(ac, av, "bdf")) >= 0) {
		switch (ch) {
		case 'd':
			log_level++;
			break;
		case 'b':
			log_daemon = 1;
			break;
		case 'f':
			log_daemon = 0;
			break;
		}
	}

	log_init();
	if (log_daemon) {
		char buf[64];
		pid_t pid;
		int fd;

		fd = open("/var/run/iscsi_trgt.pid", O_WRONLY|O_CREAT, 0644);
		if (fd < 0) {
			log_error("unable to create pid file");
			exit(1);
		}
		pid = fork();
		if (pid < 0) {
			log_error("starting daemon failed");
			exit(1);
		} else if (pid)
			exit(0);

		chdir("/");
		if (lockf(fd, F_TLOCK, 0) < 0) {
			log_error("unable to lock pid file");
			exit(1);
		}
		ftruncate(fd, 0);
		sprintf(buf, "%d\n", getpid());
		write(fd, buf, strlen(buf));

		close(0);
		open("/dev/null", O_RDWR);
		dup2(0, 1);
		dup2(0, 2);
		setsid();
	}
	target_scan();

	event_loop();

	return 0;
}
