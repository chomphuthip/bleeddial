#pragma once

#include "../common.h"

#define MAX_ENDPOINTS 16
#define ALIAS_MAX_LEN 64

enum endpoint_state_t {
	NOTEXISTS,
	NOTCONNECT,
	CONNECT
};

struct endpoint_t {
	tremont_stream_id ctrl_stream_id;
	char cur_path[255];
	enum endpoint_state_t state;
	void* cb_params;
};

struct endpoint_db_t {
	char alias_by_id[MAX_ENDPOINTS][ALIAS_MAX_LEN];
	struct endpoint_t endpoints_by_id[MAX_ENDPOINTS];
};

int endpoint_db_init(struct endpoint_db_t* db);

/*
	returns -1 if not exists, 0 if does
*/
int endpoint_id_alias(
	char* output,
	size_t max_len,
	endpoint_id_t id,
	struct endpoint_db_t* db
);

/*
	returns -1 if not exists, 0 if does
*/
int endpoint_alias_id(
	char* input,
	size_t input_len,
	endpoint_id_t* output,
	struct endpoint_db_t* db
);

/*
	returns -1 if not exists, 0 if does
*/
int endpoint_exists(endpoint_id_t id, struct endpoint_db_t* db);

int endpoint_connected(endpoint_id_t id, struct endpoint_db_t* db);

int endpoint_get_ptr(endpoint_id_t id, 
	struct endpoint_t** ptr,
	struct endpoint_db_t* db
);

int endpoint_alias_set(char* input,
	size_t input_len,
	endpoint_id_t id,
	struct endpoint_db_t* db
);

int endpoint_alias_reset(
	endpoint_id_t id,
	struct endpoint_db_t* db
);

/* --- POINT OF NO RETURN --- */

int endpoint_register(
	endpoint_id_t id,
	tremont_stream_id ctrl_stream,
	struct bleeddial_ctx_t* ctx
);

int endpoint_unregister(
	endpoint_id_t id,
	struct bleeddial_ctx_t* ctx
);

DWORD WINAPI thread_endpoint(struct bleeddial_ctx_t* ctx);