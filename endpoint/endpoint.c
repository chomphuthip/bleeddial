#include<stdio.h>

#include "../transport/transport.h"
#include "../common.h"
#include "../ctrl.h"

#include "endpoint.h"

#define MAX(X,Y) X > Y ? X : Y
#define MIN(X,Y) X > Y ? Y : X

int endpoint_db_init(struct endpoint_db_t* db) {
	memset(db, 0, sizeof(*db));
	for (int i = 0; i < 64; i++) {
		db->endpoints_by_id->state = NOTEXISTS;
	}
	return 0;
}

int endpoint_id_alias(char* output,
                      size_t max_len,
	                  endpoint_id_t id,
	                  struct endpoint_db_t* db) {
	size_t alias_len = 0;
	
	alias_len = strlen(db->alias_by_id[id]);
	if (alias_len == 0) return -1;
	
	size_t copy_len = MIN(alias_len, max_len);
	memcpy(output, db->alias_by_id[id], copy_len + 1);
	return 0;
}

int endpoint_alias_id(char* input,
                      size_t input_len,
	                  endpoint_id_t* output,
					  struct endpoint_db_t* db) {
	for (int i = 0; i < 64; i++) {
		if (strcmp(input, db->alias_by_id[i]) == 0) {
			*output = i;
			return 0;
		}
	}

	return -1;
}

int endpoint_exists(endpoint_id_t id, struct endpoint_db_t* db) {
	return db->endpoints_by_id[id].state == NOTEXISTS ? -1 : 0;
}

int endpoint_connected(endpoint_id_t id, struct endpoint_db_t* db) {
	return db->endpoints_by_id[id].state == NOTCONNECT ? -1 : 0;
}

int endpoint_get_ptr(endpoint_id_t id,
					 struct endpoint_t** ptr,
					 struct endpoint_db_t* db) {
	*ptr = &db->endpoints_by_id[id];
	return 0;
}

int endpoint_alias_set(char* input,
					   size_t input_len,
					   endpoint_id_t id,
					   struct endpoint_db_t* db) {
	memcpy(db->alias_by_id[id], input,  input_len);
	return 0;
}

int endpoint_alias_reset(
	endpoint_id_t id,
	struct endpoint_db_t* db) {
	memset(db->alias_by_id[id], 0, 64);
	return 0;
}

/* --- POINT OF NO RETURN --- */

struct _connect_cb_params {
	struct bleeddial_ctx_t* ctx;
	endpoint_id_t endpoint_id;
};

void _connect_cb_tremont(struct tremont_cb_param* param) {
	struct _connect_cb_params* cb_params = param->params;
	struct bleeddial_ctx_t* ctx = cb_params->ctx;

	struct endpoint_t* endpoint_ptr;
	EnterCriticalSection(&ctx->endpoint_db_cs);
	
	endpoint_get_ptr(
		cb_params->endpoint_id,
		&endpoint_ptr,
		ctx->endpoint_db
	);
	endpoint_ptr->state = CONNECT;

	char alias_buf[255];
	int res = 0;
	res = endpoint_id_alias(alias_buf,
		sizeof(alias_buf),
		cb_params->endpoint_id,
		ctx->endpoint_db);

	if (res == -1) {
		printf("\n%d status: connected!\n",
			cb_params->endpoint_id);
	}
	else {
		printf("\n%s (%d) connected!\n",
			alias_buf,
			cb_params->endpoint_id);
	}
	LeaveCriticalSection(&ctx->endpoint_db_cs);
	//tremont_rmcb_stream(param->stream_id, ctx->transport_pcb->nexus);
	//free(param);
}

int endpoint_register(
	endpoint_id_t id,
	tremont_stream_id ctrl_stream,
	struct bleeddial_ctx_t* ctx) {

	struct endpoint_db_t* db = ctx->endpoint_db;
	if (db->endpoints_by_id[id].state == CONNECT) return -1;

	db->endpoints_by_id[id].state = NOTCONNECT;
	db->endpoints_by_id[id].ctrl_stream_id = ctrl_stream;

	struct _connect_cb_params* cb_params;
	cb_params = malloc(sizeof(*cb_params));
	if (!cb_params) return -1;

	cb_params->endpoint_id = id;
	cb_params->ctx = ctx;

	tremont_desire_stream(ctrl_stream, ctx->transport_pcb->nexus);
	tremont_cb_stream(ctrl_stream,
		_connect_cb_tremont,
		cb_params,
		ctx->transport_pcb->nexus
	);

	db->endpoints_by_id[id].cb_params = cb_params;
	
	return 0;
}

int endpoint_unregister(
	endpoint_id_t id,
	struct bleeddial_ctx_t* ctx) {

	struct endpoint_db_t* db = ctx->endpoint_db;
	struct endpoint_t* endpoint = &db->endpoints_by_id[id];
	if (endpoint->state != NOTCONNECT) return -1;

	free(endpoint->cb_params);
	endpoint->state = NOTEXISTS;
	endpoint->ctrl_stream_id = 0;

	return 0;
}

DWORD WINAPI thread_endpoint(struct bleeddial_ctx_t* ctx) {
	struct endpoint_db_t* db = ctx->endpoint_db;
	Tremont_Nexus* nexus = ctx->transport_pcb->nexus;

	tremont_stream_id cur_ctrl_stream;
	struct endpoint_t* endpoint;
	struct ctrl_msg_t recv_msg;
	int poll = 0;

	while (1) {
		for (int i = 0; i < MAX_ENDPOINTS; i++) {
			if (endpoint_exists(i, db) == -1)
				continue;
			
			endpoint = &db->endpoints_by_id[i];
			cur_ctrl_stream = endpoint->ctrl_stream_id;

			if (endpoint->state == CONNECT)
				poll = tremont_poll_stream(cur_ctrl_stream,
					nexus);

			if (poll == 0) continue;

			tremont_recv(cur_ctrl_stream, &recv_msg,
				sizeof(recv_msg), nexus);
			
			if (recv_msg.msg_enum == DISCONNECT) {
				char alias_buf[ALIAS_MAX_LEN];
				int res = -1;

				res = endpoint_id_alias(alias_buf,
					sizeof(alias_buf),
					i,
					ctx->endpoint_db);
				if (res == -1)
					printf("%d disconnected!\n", i);
				else
					printf("%s (%d) disconnected!\n", alias_buf, i);
			}
				
		}
	}
	return 0;
}