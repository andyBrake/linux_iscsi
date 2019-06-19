/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <string.h>

#include "iscsid.h"

void param_set_default(struct session_param *param)
{
	/* set standard defaults */
	param->flags = SESSION_FLG_INITIAL_R2T | SESSION_FLG_IMMEDIATE_DATA |
		SESSION_FLG_DATA_PDU_INORDER | SESSION_FLG_DATA_SEQUENCE_INORDER;
	param->max_connections = 1;
	param->max_data_pdu_length = 8192;
	param->max_burst_length = 262144;
	param->first_burst_length = 65536;
	param->default_wait_time = 2;
	param->default_retain_time = 20;
	param->max_outstanding_r2t = 1;
	param->error_recovery_level = 0;
}

void param_set_linux_default(struct session_param *param)
{
	/* set driver defaults */
	param->flags = SESSION_FLG_INITIAL_R2T | SESSION_FLG_DATA_PDU_INORDER | SESSION_FLG_DATA_SEQUENCE_INORDER;
	param->max_connections = 4;
	param->max_data_pdu_length = 8192;
	param->max_burst_length = 262144;
	param->first_burst_length = 65536;
	param->default_wait_time = 2;
	param->default_retain_time = 20;
	param->max_outstanding_r2t = 8;
	param->error_recovery_level = 0;
}

void param_read(struct session_param *param)
{
	int len;

	len = strlen(procPath);
	strcpy(procPath + len, "/param");

	proc_read_u32("max_connections", &param->max_connections);
	proc_read_u32("max_data_pdu_length", &param->max_data_pdu_length);
	proc_read_u32("max_burst_length", &param->max_burst_length);
	proc_read_u32("first_burst_length", &param->first_burst_length);
	proc_read_u32("default_wait_time", &param->default_wait_time);
	proc_read_u32("default_retain_time", &param->default_retain_time);
	proc_read_u32("max_outstanding_r2t", &param->max_outstanding_r2t);
	proc_read_u32("error_recovery_level", &param->error_recovery_level);
	proc_read_bool("initial_r2t", &param->flags, SESSION_FLG_INITIAL_R2T);
	proc_read_bool("immediate_data", &param->flags, SESSION_FLG_IMMEDIATE_DATA);
	proc_read_bool("data_pdu_inorder", &param->flags, SESSION_FLG_DATA_PDU_INORDER);
	proc_read_bool("data_sequence_inorder", &param->flags, SESSION_FLG_DATA_SEQUENCE_INORDER);

	procPath[len] = 0;
}
