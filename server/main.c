#include<stdio.h>
#include<conio.h>
#include<time.h>

#include "common.h"

#include "transport/transport.h"
#include "endpoint/endpoint.h"
#include "cli/cli.h"

int init_ctx_sync(struct bleeddial_ctx_t* ctx) {
	InitializeCriticalSection(&ctx->transport_pcb_cs);
	InitializeCriticalSection(&ctx->endpoint_db_cs);
	InitializeCriticalSection(&ctx->cli_info_cs);
	return 0;
}

int cleanup_ctx_sync(struct bleeddial_ctx_t* ctx) {
	DeleteCriticalSection(&ctx->transport_pcb_cs);
	DeleteCriticalSection(&ctx->endpoint_db_cs);
	DeleteCriticalSection(&ctx->cli_info_cs);
	return 0;
}

int main() {
	printf("BleedDial v0.0\n");
	srand((unsigned int)time(NULL));
	
	int res = -1;

	struct transport_pcb_t transport_pcb;
	res = transport_init(&transport_pcb);
	if (res == -1) {
		perror("Unable to init transport!\n");
		exit(-1);
	}

	struct endpoint_db_t endpoint_db;
	res = endpoint_db_init(&endpoint_db);
	if (res == -1) {
		perror("Unable to init endpoint db!\n");
		exit(-1);
	}

	struct bleeddial_ctx_t ctx;
	ctx.transport_pcb = &transport_pcb;
	ctx.endpoint_db = &endpoint_db;

	HANDLE endpoint_thread_handle;
	endpoint_thread_handle = CreateThread(
		NULL,
		0,
		thread_endpoint,
		&ctx,
		0,
		0
	);

	init_ctx_sync(&ctx);

	cli_main(&ctx);
	
	cleanup_ctx_sync(&ctx);

    return 0;
}