/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "iscsid.h"
#include "md5.h"

struct user *iscsi_discover_users;

char *text_key_find(struct connection *conn, char *searchKey)
{
	char *data, *key, *value;
	int keylen, datasize;

	keylen = strlen(searchKey);
	data = conn->req.data;
	datasize = conn->req.datasize;

	while (1) {
		for (key = data; datasize > 0 && *data != '='; data++, datasize--)
			;
		if (!datasize)
			return NULL;
		data++;

		for (value = data; datasize > 0 && *data != 0; data++, datasize--)
			;
		if (!datasize)
			return NULL;
		data++;

		if (keylen == value - key - 1
		     && !strncmp(key, searchKey, keylen))
			return value;
	}
}

void text_key_add(struct connection *conn, char *key, char *value)
{
	int keylen = strlen(key);
	int valuelen = strlen(value);
	int len = keylen + valuelen + 2;
	char *buffer;

	if (!conn->rsp.datasize) {
		if (!conn->rsp_buffer)
			conn->rsp_buffer = malloc(INCOMING_BUFSIZE);
		conn->rsp.data = conn->rsp_buffer;
	}
	if (conn->rwsize + len > INCOMING_BUFSIZE) {
		log_warning("Dropping key (%s=%s)", key, value);
		return;
	}

	buffer = conn->rsp_buffer;
	buffer += conn->rsp.datasize;
	conn->rsp.datasize += len;

	strcpy(buffer, key);
	buffer += keylen;
	*buffer++ = '=';
	strcpy(buffer, value);
}

void text_scan_security(struct connection *conn)
{
	struct iscsi_login_rsp_hdr *rsp = (struct iscsi_login_rsp_hdr *)&conn->rsp.bhs;
	char *key, *value, *data, *nextValue;
	int datasize;

	data = conn->req.data;
	datasize = conn->req.datasize;

	while (1) {
		for (key = data; datasize > 0 && *data != '='; data++, datasize--)
			;
		if (!datasize)
			break;
		*data++ = 0;

		for (value = data; datasize > 0 && *data != 0; data++, datasize--)
			;
		if (!datasize)
			break;
		data++;

		if (!strcmp(key, "InitiatorName"))
			/*skip*/;
		else if (!strcmp(key, "InitiatorAlias"))
			/*skip*/;
		else if (!strcmp(key, "SessionType"))
			/*skip*/;
		else if (!strcmp(key, "TargetName"))
			/*skip*/;
		else if (!strcmp(key, "AuthMethod")) {
			do {
				nextValue = strchr(value, ',');
				if (nextValue)
					*nextValue++ = 0;

				if (!strcmp(value, "None")) {
					if (conn->target ? conn->target->users : iscsi_discover_users)
						continue;
					conn->auth_method = AUTH_NONE;
					text_key_add(conn, key, "None");
					break;
				} else if (!strcmp(value, "CHAP")) {
					if (!(conn->target ? conn->target->users : iscsi_discover_users))
						continue;
					conn->auth_method = AUTH_CHAP;
					text_key_add(conn, key, "CHAP");
					break;
				}
			} while ((value = nextValue));

			if (conn->auth_method == AUTH_UNKNOWN)
				text_key_add(conn, key, "reject");
		} else
			text_key_add(conn, key, "NotUnderstood");
	}
	if (conn->auth_method == AUTH_UNKNOWN) {
		rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
		rsp->status_detail = ISCSI_STATUS_AUTH_FAILED;
		conn->state = STATE_EXIT;
	}
}

void login_security_done(struct connection *conn)
{
	struct iscsi_login_req_hdr *req = (struct iscsi_login_req_hdr *)&conn->req.bhs;
	struct iscsi_login_rsp_hdr *rsp = (struct iscsi_login_rsp_hdr *)&conn->rsp.bhs;
	struct session *session;

	if (!conn->target)
		return;

	session = session_find_name(conn->target, conn->initiator, req->sid);
	if (session) {
		if (!req->sid.id.tsih) {
			/* do session reinstatement */
			session_close(session);
			session = NULL;
		} else if (req->sid.id.tsih != session->sid.id.tsih) {
			/* fail the login */
			rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
			rsp->status_detail = ISCSI_STATUS_SESSION_NOT_FOUND;
			conn->state = STATE_EXIT;
			return;
		} else if (conn_test(conn)) {
			/* do connection reinstatement */
		}
		/* add a new connection to the session */
		conn->session = session;
	} else {
		if (req->sid.id.tsih) {
			/* fail the login */
			rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
			rsp->status_detail = ISCSI_STATUS_SESSION_NOT_FOUND;
			conn->state = STATE_EXIT;
			return;
		}
		/* instantiate a new session */
	}
}

void text_scan_login(struct connection *conn)
{
	char *key, *value, *data, *nextValue;
	int datasize;

	data = conn->req.data;
	datasize = conn->req.datasize;

	while (1) {
		for (key = data; datasize > 0 && *data != '='; data++, datasize--)
			;
		if (!datasize)
			break;
		*data++ = 0;

		for (value = data; datasize > 0 && *data != 0; data++, datasize--)
			;
		if (!datasize)
			break;
		data++;

		if (!strcmp(key, "InitiatorName"))
			/*skip*/;
		else if (!strcmp(key, "InitiatorAlias"))
			/*skip*/;
		else if (!strcmp(key, "SessionType"))
			/*skip*/;
		else if (!strcmp(key, "TargetName"))
			/*skip*/;
		else if (!strcmp(key, "AuthMethod"))
			/*skip*/;
		else if (!strcmp(key, "HeaderDigest")) {
			do {
				nextValue = strchr(value, ',');
				if (nextValue)
					*nextValue++ = 0;

				if (!strcmp(value, "None")) {
					conn->header_digest = DIGEST_NONE;
					text_key_add(conn, key, "None");
					break;
				}
			} while ((value = nextValue));

			if (conn->header_digest == DIGEST_UNKNOWN)
				text_key_add(conn, key, "reject");
		} else if (!strcmp(key, "DataDigest")) {
			do {
				nextValue = strchr(value, ',');
				if (nextValue)
					*nextValue++ = 0;

				if (!strcmp(value, "None")) {
					conn->data_digest = DIGEST_NONE;
					text_key_add(conn, key, "None");
					break;
				}
			} while ((value = nextValue));

			if (conn->data_digest == DIGEST_UNKNOWN)
				text_key_add(conn, key, "reject");
		} else if (!strcmp(key, "MaxConnections")) {
			int val = strtol(value, NULL, 0);
			char str[10];
			if (val > 0 && val < conn->param.max_connections)
				conn->param.max_connections = val;
			sprintf(str, "%d", conn->param.max_connections);
			text_key_add(conn, key, str);
			conn->key_state[key_max_connections] = KEY_STATE_DONE;
		} else if (!strcmp(key, "OFMarker")) {
			text_key_add(conn, key, "No");
		} else if (!strcmp(key, "IFMarker")) {
			text_key_add(conn, key, "No");
		} else if (!strcmp(key, "OFMarkInt")) {
			text_key_add(conn, key, "reject");
		} else if (!strcmp(key, "IFMarkInt")) {
			text_key_add(conn, key, "reject");
		} else if (!strcmp(key, "InitialR2T")) {
			int flg = 0;
			if (!strcmp(value, "Yes")) {
				flg = SESSION_FLG_INITIAL_R2T;
			} else if (strcmp(value, "No")) {
				text_key_add(conn, key, "reject");
				continue;
			}
			conn->param.flags |= flg;
			text_key_add(conn, key, conn->param.flags & SESSION_FLG_INITIAL_R2T ? "Yes" : "No");
			conn->key_state[key_initial_r2t] = KEY_STATE_DONE;
		} else if (!strcmp(key, "ImmediateData")) {
			int flg = ~0;
			if (!strcmp(value, "No")) {
				flg = ~SESSION_FLG_IMMEDIATE_DATA;
			} else if (strcmp(value, "Yes")) {
				text_key_add(conn, key, "reject");
				continue;
			}
			conn->param.flags &= flg;
			text_key_add(conn, key, conn->param.flags & SESSION_FLG_IMMEDIATE_DATA ? "Yes" : "No");
			conn->key_state[key_immediate_data] = KEY_STATE_DONE;
		} else if (!strcmp(key, "MaxRecvDataSegmentLength")) {
			int val = strtol(value, NULL, 0);
			char str[10];
			if (val > 0 && val < conn->param.max_data_pdu_length)
				conn->param.max_data_pdu_length = val;
			sprintf(str, "%d", conn->param.max_data_pdu_length);
			text_key_add(conn, key, str);
			conn->key_state[key_max_data_pdu_length] = KEY_STATE_DONE;
		} else if (!strcmp(key, "MaxBurstLength")) {
			int val = strtol(value, NULL, 0);
			char str[10];
			if (val > 0 && val < conn->param.max_burst_length)
				conn->param.max_burst_length = val;
			sprintf(str, "%d", conn->param.max_burst_length);
			text_key_add(conn, key, str);
			conn->key_state[key_max_burst_length] = KEY_STATE_DONE;
		} else if (!strcmp(key, "FirstBurstLength")) {
			int val = strtol(value, NULL, 0);
			char str[10];
			if (val > 0 && val < conn->param.first_burst_length)
				conn->param.first_burst_length = val;
			sprintf(str, "%d", conn->param.first_burst_length);
			text_key_add(conn, key, str);
			conn->key_state[key_first_burst_length] = KEY_STATE_DONE;
		} else if (!strcmp(key, "DefaultTime2Wait")) {
			int val = strtol(value, NULL, 0);
			char str[10];
			if (val > conn->param.default_wait_time)
				conn->param.default_wait_time = val;
			sprintf(str, "%d", conn->param.default_wait_time);
			text_key_add(conn, key, str);
			conn->key_state[key_default_wait_time] = KEY_STATE_DONE;
		} else if (!strcmp(key, "DefaultTime2Retain")) {
			int val = strtol(value, NULL, 0);
			char str[10];
			if (val < conn->param.default_retain_time)
				conn->param.default_retain_time = val;
			sprintf(str, "%d", conn->param.default_retain_time);
			text_key_add(conn, key, str);
			conn->key_state[key_default_retain_time] = KEY_STATE_DONE;
		} else if (!strcmp(key, "MaxOutstandingR2T")) {
			int val = strtol(value, NULL, 0);
			char str[10];
			if (val >= 0 &&  val < conn->param.max_outstanding_r2t)
				conn->param.max_outstanding_r2t = val;
			sprintf(str, "%d", conn->param.max_outstanding_r2t);
			text_key_add(conn, key, str);
			conn->key_state[key_max_outstanding_r2t] = KEY_STATE_DONE;
		} else if (!strcmp(key, "DataPDUInOrder")) {
			int flg = 0;
			if (!strcmp(value, "Yes")) {
				flg = SESSION_FLG_DATA_PDU_INORDER;
			} else if (strcmp(value, "No")) {
				text_key_add(conn, key, "reject");
				continue;
			}
			conn->param.flags |= flg;
			text_key_add(conn, key, conn->param.flags & SESSION_FLG_DATA_PDU_INORDER ? "Yes" : "No");
			conn->key_state[key_data_pdu_inorder] = KEY_STATE_DONE;
		} else if (!strcmp(key, "DataSequenceInOrder")) {
			int flg = 0;
			if (!strcmp(value, "Yes")) {
				flg = SESSION_FLG_DATA_SEQUENCE_INORDER;
			} else if (strcmp(value, "No")) {
				text_key_add(conn, key, "reject");
				continue;
			}
			conn->param.flags |= flg;
			text_key_add(conn, key, conn->param.flags & SESSION_FLG_DATA_SEQUENCE_INORDER ? "Yes" : "No");
			conn->key_state[key_data_sequence_inorder] = KEY_STATE_DONE;
		} else if (!strcmp(key, "ErrorRecoveryLevel")) {
			int val = strtol(value, NULL, 0);
			char str[10];
			if (val >= 0 &&  val < conn->param.error_recovery_level)
				conn->param.error_recovery_level = val;
			sprintf(str, "%d", conn->param.error_recovery_level);
			text_key_add(conn, key, str);
			conn->key_state[key_error_recovery_level] = KEY_STATE_DONE;
		} else
			text_key_add(conn, key, "NotUnderstood");
	}
}

static int text_check_param(struct connection *conn)
{
	struct session_param param;
	char str[32];
	int cnt = 0;

	param_set_default(&param);
	if (conn->key_state[key_initial_r2t] == KEY_STATE_START &&
	    (param.flags ^ conn->param.flags) & SESSION_FLG_INITIAL_R2T) {
		text_key_add(conn, "InitialR2T", conn->param.flags & SESSION_FLG_INITIAL_R2T ? "Yes" : "No");
		cnt++;
	}
	if (conn->key_state[key_immediate_data] == KEY_STATE_START &&
	    (param.flags ^ conn->param.flags) & SESSION_FLG_IMMEDIATE_DATA) {
		text_key_add(conn, "ImmediateData", conn->param.flags & SESSION_FLG_IMMEDIATE_DATA ? "Yes" : "No");
		cnt++;
	}
	if (conn->key_state[key_data_pdu_inorder] == KEY_STATE_START &&
	    (param.flags ^ conn->param.flags) & SESSION_FLG_DATA_PDU_INORDER) {
		text_key_add(conn, "DataPDUInOrder", conn->param.flags & SESSION_FLG_DATA_PDU_INORDER ? "Yes" : "No");
		cnt++;
	}
	if (conn->key_state[key_data_sequence_inorder] == KEY_STATE_START &&
	    (param.flags ^ conn->param.flags) & SESSION_FLG_DATA_SEQUENCE_INORDER) {
		text_key_add(conn, "DataSequenceInOrder", conn->param.flags & SESSION_FLG_DATA_SEQUENCE_INORDER ? "Yes" : "No");
		cnt++;
	}
	if (conn->key_state[key_max_connections] == KEY_STATE_START &&
	    param.max_connections != conn->param.max_connections) {
		sprintf(str, "%u", conn->param.max_connections);
		text_key_add(conn, "MaxConnections", str);
		cnt++;
	}
	if (conn->key_state[key_max_data_pdu_length] == KEY_STATE_START &&
	    param.max_data_pdu_length != conn->param.max_data_pdu_length) {
		sprintf(str, "%u", conn->param.max_data_pdu_length);
		text_key_add(conn, "MaxRecvDataSegmentLength", str);
		cnt++;
	}
	if (conn->key_state[key_max_burst_length] == KEY_STATE_START &&
	    param.max_burst_length != conn->param.max_burst_length) {
		sprintf(str, "%u", conn->param.max_burst_length);
		text_key_add(conn, "MaxBurstLength", str);
		cnt++;
	}
	if (conn->key_state[key_first_burst_length] == KEY_STATE_START &&
	    param.first_burst_length != conn->param.first_burst_length) {
		sprintf(str, "%u", conn->param.first_burst_length);
		text_key_add(conn, "FirstBurstLength", str);
		cnt++;
	}
	if (conn->key_state[key_default_wait_time] == KEY_STATE_START &&
	    param.default_wait_time != conn->param.default_wait_time) {
		sprintf(str, "%u", conn->param.default_wait_time);
		text_key_add(conn, "DefaultTime2Wait", str);
		cnt++;
	}
	if (conn->key_state[key_default_retain_time] == KEY_STATE_START &&
	    param.default_retain_time != conn->param.default_retain_time) {
		sprintf(str, "%u", conn->param.default_retain_time);
		text_key_add(conn, "DefaultTime2Retain", str);
		cnt++;
	}
	if (conn->key_state[key_max_outstanding_r2t] == KEY_STATE_START &&
	    param.max_outstanding_r2t != conn->param.max_outstanding_r2t) {
		sprintf(str, "%u", conn->param.max_outstanding_r2t);
		text_key_add(conn, "MaxOutstandingR2T", str);
		cnt++;
	}
	if (conn->key_state[key_error_recovery_level] == KEY_STATE_START &&
	    param.error_recovery_level != conn->param.error_recovery_level) {
		sprintf(str, "%u", conn->param.error_recovery_level);
		text_key_add(conn, "ErrorRecoveryLevel", str);
		cnt++;
	}
	return cnt;
}

void login_start(struct connection *conn)
{
	struct iscsi_login_req_hdr *req = (struct iscsi_login_req_hdr *)&conn->req.bhs;
	struct iscsi_login_rsp_hdr *rsp = (struct iscsi_login_rsp_hdr *)&conn->rsp.bhs;
	char *name, *alias, *session_type, *target_name;

	conn->cid = be16_to_cpu(req->cid);
	conn->sid.id64 = req->sid.id64;
	if (!conn->sid.id64) {
		rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
		rsp->status_detail = ISCSI_STATUS_MISSING_FIELDS;
		conn->state = STATE_EXIT;
		return;
	}

	name = text_key_find(conn, "InitiatorName");
	if (!name) {
		rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
		rsp->status_detail = ISCSI_STATUS_MISSING_FIELDS;
		conn->state = STATE_EXIT;
		return;
	}
	conn->initiator = strdup(name);
	alias = text_key_find(conn, "InitiatorAlias");
	session_type = text_key_find(conn, "SessionType");
	target_name = text_key_find(conn, "TargetName");

	conn->auth_method = -1;
	conn->header_digest = -1;
	conn->data_digest = -1;
	conn->session_type = SESSION_NORMAL;

	if (session_type) {
		if (!strcmp(session_type, "Discovery"))
			conn->session_type = SESSION_DISCOVERY;
		else if (strcmp(session_type, "Normal")) {
			rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
			rsp->status_detail = ISCSI_STATUS_INV_SESSION_TYPE;
			conn->state = STATE_EXIT;
			return;
		}
	}

	if (conn->session_type == SESSION_NORMAL) {
		if (!target_name) {
			rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
			rsp->status_detail = ISCSI_STATUS_MISSING_FIELDS;
			conn->state = STATE_EXIT;
			return;
		}

		conn->target = target_find_name(target_name);
		if (!conn->target) {
			rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
			rsp->status_detail = ISCSI_STATUS_TGT_NOT_FOUND;
			conn->state = STATE_EXIT;
			return;
		}

		conn->param = conn->target->default_param;

		conn->exp_cmd_sn = be32_to_cpu(req->cmd_sn);
		log_debug(1, "exp_cmd_sn: %d,%d", conn->exp_cmd_sn, req->cmd_sn);
		conn->max_cmd_sn = conn->exp_cmd_sn;
	}
	text_key_add(conn, "TargetPortalGroupTag", "1");
}

void login_finish(struct connection *conn)
{
	switch (conn->session_type) {
	case SESSION_NORMAL:
		if (!conn->session)
			session_create(conn);
		conn->sid = conn->session->sid;
		break;
	case SESSION_DISCOVERY:
		/* set a dummy tsih value */
		conn->sid.id.tsih = 1;
		break;
	}
}

static inline int hex2digit(char c)
{
	switch (c) {
	case '0' ... '9':
		return c - '0';
	case 'a' ... 'f':
		return c - 'a' + 10;
	case 'A' ... 'F':
		return c - 'A' + 10;
	}
	return 0;
}

int cmnd_exec_auth(struct connection *conn)
{
	struct MD5Context context;
	struct user *user;
	char *value, *p;
	char text[CHAP_CHALLENGE_MAX * 2 + 8];
	unsigned char digest1[16], digest2[16];
	static int chap_id;
	int i;

	switch (conn->auth_state) {
	case AUTH_STATE_START:
		value = text_key_find(conn, "CHAP_A");
		if (!value)
			return -1;
		while ((p = strsep(&value, ","))) {
			if (!strcmp(p, "5")) {
				conn->auth_state = AUTH_STATE_CHALLENGE;
				break;
			}
		}
		if (!p)
			return -1;
		text_key_add(conn, "CHAP_A", p);
		conn->chap_id = ++chap_id;
		sprintf(text, "%u", (unsigned char)conn->chap_id);
		text_key_add(conn, "CHAP_I", text);
		conn->chap_challenge_size = (rand() % (CHAP_CHALLENGE_MAX / 2)) + CHAP_CHALLENGE_MAX / 2;
		p = text;
		strcpy(p, "0x");
		p += 2;
		for (i = 0; i < conn->chap_challenge_size; i++) {
			conn->chap_challenge[i] = rand();
			sprintf(p, "%02x", (unsigned char)conn->chap_challenge[i]);
			p += 2;
		}
		text_key_add(conn, "CHAP_C", text);
		break;
	case AUTH_STATE_CHALLENGE:
		value = text_key_find(conn, "CHAP_N");
		if (!value)
			return -1;

		user = conn->target ? conn->target->users : iscsi_discover_users;
		if (!user) {
			conn->state = STATE_SECURITY_DONE;
			break;
		}
		for (; user; user = user->next) {
			if (!strcmp(user->name, value))
				break;
		}
		if (!user) {
			log_debug(0, "unknown user %s", value);
			return -2;
		}

		value = text_key_find(conn, "CHAP_R");
		if (!value || value[0] != '0' || (value[1] != 'x' && value[1] != 'X'))
			return -1;
		value[1] = '0';
		value += 2;
		i = strlen(value);
		if (i > 32)
			return -1;
		p = value + i;
		i = 15;
		do {
			digest2[i] = hex2digit(*--p);
			digest2[i] |= hex2digit(*--p) << 4;
			i--;
		} while (p > value);
		while (i >= 0)
			digest2[i--] = 0;

		MD5Init(&context);
		text[0] = conn->chap_id;
		MD5Update(&context, text, 1);
		MD5Update(&context, user->password, strlen(user->password));
		MD5Update(&context, conn->chap_challenge, conn->chap_challenge_size);
		MD5Final(digest1, &context);

		if (memcmp(digest1, digest2, 16)) {
			log_debug(0, "login by %s failed", user->name);
			return -2;
		}

		log_debug(0, "succesfull login by %s", user->name);
		conn->state = STATE_SECURITY_DONE;
		break;
	}

	return 0;
}

void cmnd_exec_login(struct connection *conn)
{
	struct iscsi_login_req_hdr *req = (struct iscsi_login_req_hdr *)&conn->req.bhs;
	struct iscsi_login_rsp_hdr *rsp = (struct iscsi_login_rsp_hdr *)&conn->rsp.bhs;

	memset(rsp, 0, BHS_SIZE);
	if ((req->opcode & ISCSI_OPCODE_MASK) != ISCSI_OP_LOGIN_CMD ||
	    !(req->opcode & ISCSI_OP_IMMEDIATE)) {
		//reject
	}

	rsp->opcode = ISCSI_OP_LOGIN_RSP;
	rsp->max_version = ISCSI_VERSION;
	rsp->active_version = ISCSI_VERSION;
	rsp->itt = req->itt;

	if (/*req->max_version < ISCSI_VERSION ||*/
	    req->min_version > ISCSI_VERSION) {
		rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
		rsp->status_detail = ISCSI_STATUS_NO_VERSION;
		conn->state = STATE_EXIT;
		return;
	}

	switch (req->flags & ISCSI_FLG_CSG_MASK) {
	case ISCSI_FLG_CSG_SECURITY:
		log_debug(1, "Login request (security negotiation): %d", conn->state);
		rsp->flags = ISCSI_FLG_CSG_SECURITY;

		switch (conn->state) {
		case STATE_FREE:
			conn->state = STATE_SECURITY;
			login_start(conn);
			if (rsp->status_class)
				return;
			//else fall through
		case STATE_SECURITY:
			text_scan_security(conn);
			if (rsp->status_class)
				return;
			if (conn->auth_method != AUTH_NONE) {
				conn->state = STATE_SECURITY_AUTH;
				conn->auth_state = AUTH_STATE_START;
			}
			break;
		case STATE_SECURITY_AUTH:
			switch (cmnd_exec_auth(conn)) {
			case 0:
				break;
			default:
			case -1:
				goto init_err;
			case -2:
				goto auth_err;
			}
			break;
		default:
			goto init_err;
		}

		break;
	case ISCSI_FLG_CSG_LOGIN:
		log_debug(1, "Login request (operational negotiation): %d", conn->state);
		rsp->flags = ISCSI_FLG_CSG_LOGIN;

		switch (conn->state) {
		case STATE_FREE:
			conn->state = STATE_LOGIN;
			if (conn->target ? conn->target->users : iscsi_discover_users)
				goto auth_err;
			login_start(conn);
			if (rsp->status_class)
				return;
			text_scan_login(conn);
			if (rsp->status_class)
				return;
			text_check_param(conn);
			break;
		case STATE_LOGIN:
			text_scan_login(conn);
			if (rsp->status_class)
				return;
			break;
		default:
			goto init_err;
		}
		break;
	default:
		goto init_err;
	}
	if (rsp->status_class)
		return;
	if (conn->state != STATE_SECURITY_AUTH && req->flags & ISCSI_FLG_TRANSIT) {
		int nsg = req->flags & ISCSI_FLG_NSG_MASK;

		switch (nsg) {
		case ISCSI_FLG_NSG_LOGIN:
			switch (conn->state) {
			case STATE_SECURITY:
			case STATE_SECURITY_DONE:
				conn->state = STATE_SECURITY_LOGIN;
				login_security_done(conn);
				break;
			default:
				goto init_err;
			}
			break;
		case ISCSI_FLG_NSG_FULL_FEATURE:
			switch (conn->state) {
			case STATE_SECURITY:
			case STATE_SECURITY_DONE:
				if (text_check_param(conn)) {
					nsg = ISCSI_FLG_NSG_LOGIN;
					break;
				}
				conn->state = STATE_SECURITY_FULL;
				login_security_done(conn);
				break;
			case STATE_LOGIN:
				conn->state = STATE_LOGIN_FULL;
				break;
			default:
				goto init_err;
			}
			login_finish(conn);
			break;
		default:
			goto init_err;
		}
		rsp->flags |= nsg | ISCSI_FLG_TRANSIT;
	}

	rsp->sid = conn->sid;
	rsp->stat_sn = cpu_to_be32(conn->stat_sn++);
	rsp->exp_cmd_sn = cpu_to_be32(conn->exp_cmd_sn);
	rsp->max_cmd_sn = cpu_to_be32(conn->max_cmd_sn);
	return;
init_err:
	rsp->flags = 0;
	rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
	rsp->status_detail = ISCSI_STATUS_INIT_ERR;
	conn->state = STATE_EXIT;
	return;
auth_err:
	rsp->flags = 0;
	rsp->status_class = ISCSI_STATUS_INITIATOR_ERR;
	rsp->status_detail = ISCSI_STATUS_AUTH_FAILED;
	conn->state = STATE_EXIT;
	return;
}

void text_scan_text(struct connection *conn)
{
	char *key, *value, *data;
	int datasize;

	data = conn->req.data;
	datasize = conn->req.datasize;

	while (1) {
		for (key = data; datasize > 0 && *data != '='; data++, datasize--)
			;
		if (!datasize)
			break;
		*data++ = 0;

		for (value = data; datasize > 0 && *data != 0; data++, datasize--)
			;
		if (!datasize)
			break;
		data++;

		if (!strcmp(key, "SendTargets")) {
			struct sockaddr_in name;
			socklen_t len;
			char addr[64];

			len = sizeof(name);
			getsockname(conn->fd, (struct sockaddr *)&name, &len);
			sprintf(addr, "%s:3260,1", inet_ntoa(name.sin_addr));

			if (!strcmp(value, "All")) {
				struct target *target;
				for (target = targets; target; target = target->next) {
					if (!target->name)
						continue;
					text_key_add(conn, "TargetName", target->name);

					text_key_add(conn, "TargetAddress", addr);
					//if (target->alias)
					//	text_key_add(conn, "TargetAlias", target->alias);
				}
			} else if (value[0] == 0) {
			} else {
				struct target *target = target_find_name(value);
				if (target) {
					text_key_add(conn, "TargetName", target->name);
					text_key_add(conn, "TargetAddress", addr);
					//if (target->alias)
					//	text_key_add(conn, "TargetAlias", target->alias);
				}
			}
		} else
			text_key_add(conn, key, "NotUnderstood");
	}
}

void cmnd_exec_text(struct connection *conn)
{
	struct iscsi_text_req_hdr *req = (struct iscsi_text_req_hdr *)&conn->req.bhs;
	struct iscsi_text_rsp_hdr *rsp = (struct iscsi_text_rsp_hdr *)&conn->rsp.bhs;

	memset(rsp, 0, BHS_SIZE);

	if (be32_to_cpu(req->ttt) != 0xffffffff) {
		/* reject */;
	}
	rsp->opcode = ISCSI_OP_TEXT_RSP;
	rsp->itt = req->itt;
	//rsp->ttt = rsp->ttt;
	rsp->ttt = 0xffffffff;
	conn->exp_cmd_sn = be32_to_cpu(req->cmd_sn);
	if (!(req->opcode & ISCSI_OP_IMMEDIATE))
		conn->exp_cmd_sn++;

	log_debug(1, "Text request: %d", conn->state);
	text_scan_text(conn);

	if (req->flags & ISCSI_FLG_FINAL)
		rsp->flags = ISCSI_FLG_FINAL;

	rsp->stat_sn = cpu_to_be32(conn->stat_sn++);
	rsp->exp_cmd_sn = cpu_to_be32(conn->exp_cmd_sn);
	rsp->max_cmd_sn = cpu_to_be32(conn->max_cmd_sn);
}

static void cmnd_exec_logout(struct connection *conn)
{
	struct iscsi_logout_req_hdr *req = (struct iscsi_logout_req_hdr *)&conn->req.bhs;
	struct iscsi_logout_rsp_hdr *rsp = (struct iscsi_logout_rsp_hdr *)&conn->rsp.bhs;

	memset(rsp, 0, BHS_SIZE);
	rsp->opcode = ISCSI_OP_LOGOUT_RSP;
	rsp->flags = ISCSI_FLG_FINAL;
	rsp->itt = req->itt;
	conn->exp_cmd_sn = be32_to_cpu(req->cmd_sn);
	if (!(req->opcode & ISCSI_OP_IMMEDIATE))
		conn->exp_cmd_sn++;

	rsp->stat_sn = cpu_to_be32(conn->stat_sn++);
	rsp->exp_cmd_sn = cpu_to_be32(conn->exp_cmd_sn);
	rsp->max_cmd_sn = cpu_to_be32(conn->max_cmd_sn);
}

int cmnd_execute(struct connection *conn)
{
	int res = 1;

	switch (conn->req.bhs.opcode & ISCSI_OPCODE_MASK) {
	case ISCSI_OP_LOGIN_CMD:
		//if conn->state == STATE_FULL -> reject
		cmnd_exec_login(conn);
		conn->rsp.bhs.ahslength = conn->rsp.ahssize / 4;
		conn->rsp.bhs.datalength[0] = conn->rsp.datasize >> 16;
		conn->rsp.bhs.datalength[1] = conn->rsp.datasize >> 8;
		conn->rsp.bhs.datalength[2] = conn->rsp.datasize;
		log_pdu(2, &conn->rsp);
		break;
	case ISCSI_OP_TEXT_CMD:
		//if conn->state != STATE_FULL -> reject
		cmnd_exec_text(conn);
		conn->rsp.bhs.ahslength = conn->rsp.ahssize / 4;
		conn->rsp.bhs.datalength[0] = conn->rsp.datasize >> 16;
		conn->rsp.bhs.datalength[1] = conn->rsp.datasize >> 8;
		conn->rsp.bhs.datalength[2] = conn->rsp.datasize;
		log_pdu(2, &conn->rsp);
		break;
	case ISCSI_OP_LOGOUT_CMD:
		//if conn->state != STATE_FULL -> reject
		cmnd_exec_logout(conn);
		conn->rsp.bhs.ahslength = conn->rsp.ahssize / 4;
		conn->rsp.bhs.datalength[0] = conn->rsp.datasize >> 16;
		conn->rsp.bhs.datalength[1] = conn->rsp.datasize >> 8;
		conn->rsp.bhs.datalength[2] = conn->rsp.datasize;
		log_pdu(2, &conn->rsp);
		break;
	default:
		//reject
		res = 0;
		break;
	}

	return res;
}

void cmnd_finish(struct connection *conn)
{
	switch (conn->state) {
	case STATE_EXIT:
		conn->state = STATE_CLOSE;
		break;
	case STATE_SECURITY_LOGIN:
		conn->state = STATE_LOGIN;
		break;
	case STATE_SECURITY_FULL:
		//fall through
	case STATE_LOGIN_FULL:
		if (conn->session_type == SESSION_NORMAL)
			conn->state = STATE_KERNEL;
		else
			conn->state = STATE_FULL;
		break;
	}
}
