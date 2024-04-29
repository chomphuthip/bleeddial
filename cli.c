#pragma once

#include<stdio.h>
#include<string.h>
#include<ctype.h>

#include "transport.h"
#include "endpoint.h"
#include "common.h"
#include "jobs.h"
#include "cli.h"

void _print_prompt(struct cli_info_t* cli_info,
				   struct bleeddial_ctx_t* ctx) {
	if (cli_info->cli_state == TOP) {
		printf("BleedDial#");
	}
	else {
		char endpoint_alias[255];
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


int _handle_list_e(char* user_input,
	char** tok_ctx_ptr,
	struct cli_info_t* cli_info,
	struct bleeddial_ctx_t* ctx) {
	EnterCriticalSection(&ctx->endpoint_db_cs);

	char connect_msg[] = "Connected";
	char notconnect_msg[] = "Not Connected";
	char* msg_ptr;

	char alias_buf[64];
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
	if (strcmp(second_word, "set") == 0) {
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
	if (strcmp(second_word, "reset") == 0) {
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

int _handle_user_input(char* user_input, 
					   size_t user_input_len, 
					   struct cli_info_t* cli_info,
				       struct bleeddial_ctx_t* ctx) {

	char* tok_ctx = 0;
	char* first_word;
	
	if (user_input[0] == '\n') return 0;
	first_word = strtok_s(user_input, " ", &tok_ctx);
	
	if (cli_info->cli_state == TOP) {
		if (strcmp(first_word, "tone") == 0) {
			return _handle_tone(user_input, &tok_ctx, cli_info, ctx);
		}
		if (strcmp(first_word, "alias") == 0) {
			return _handle_alias(user_input, &tok_ctx, cli_info, ctx);
		}
		if (strcmp(first_word, "show_nexus_key\n") == 0) {
			return _handle_show_nexus_key(user_input, &tok_ctx, cli_info, ctx);
		}
		if (strcmp(first_word, "print_nexus_key\n") == 0) {
			return _handle_print_nexus_key(user_input, &tok_ctx, cli_info, ctx);
		}
		if (strcmp(first_word, "list_endpoints\n") == 0) {
			return _handle_list_e(user_input, &tok_ctx, cli_info, ctx);
		}
		if (strcmp(first_word, "register_endpoint") == 0) {
			return _handle_register(user_input, &tok_ctx, cli_info, ctx);
		}
		if (strcmp(first_word, "unregister_endpoint") == 0) {
			return _handle_unregister(user_input, &tok_ctx, cli_info, ctx);
		}
		if (strcmp(first_word, "exit\n") == 0) {
			return -1;
		}
	}
	if (cli_info->cli_state == TONE) {
		if (strcmp(first_word, "download") == 0) {
			//return _handle_download(user_input, &tok_ctx, cli_info, ctx
			printf("sim downloading....\n");
			return 0;
		}
		if (strcmp(first_word, "exit\n") == 0) {
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