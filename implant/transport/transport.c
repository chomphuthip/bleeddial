#pragma once

#include<stdio.h>
#include<WS2tcpip.h>

#include "transport.h"

#pragma comment(lib, "Ws2_32.lib")

void _init_winsock() {
    WSADATA wsa_data;
    int startup_result = WSAStartup(MAKEWORD(2, 2), &wsa_data);

    if (startup_result != 0)
        exit(-1);
}


void _setup_socket(SOCKET* sock) {
    struct addrinfo* res = NULL;
    struct addrinfo hints;

    ZeroMemory(&hints, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    
    int addr_info_res;
    if (settings.use_me == 1)
        addr_info_res = getaddrinfo("127.0.0.1",
            settings.local_port, &hints, &res);
    else
        addr_info_res = getaddrinfo("127.0.0.1", LOCAL_PORT, &hints, &res);
    
    if (addr_info_res != 0)
        exit(-1);

    *sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (*sock == INVALID_SOCKET)
        exit(-1);

    int bind_result = bind(*sock, res->ai_addr, (int)res->ai_addrlen);
    if (bind_result == SOCKET_ERROR)
        exit(-1);

    freeaddrinfo(res);
}


void _setup_tremont(SOCKET* sock, Tremont_Nexus** nexus_ptr) {
    int res = 0;

    res = tremont_init_nexus(nexus_ptr);
    if (res != 0)
        exit(-1);

    char key[] = ENCRYPTION_KEY;
    if(settings.use_me == 1)
        res = tremont_key_nexus(settings.priv, 
            settings.priv_len, *nexus_ptr);
    else
        res = tremont_key_nexus(key, sizeof(key), *nexus_ptr);

    if (res != 0)
        exit(-1);

    res = tremont_bind_nexus(*sock, *nexus_ptr);
    if (res != 0)
        exit(-1);
}

int _get_remote_addrinfo(struct addrinfo** remote_addr_ptr) {
    struct addrinfo remote_hint;

    ZeroMemory(&remote_hint, sizeof(remote_hint));

    remote_hint.ai_family = AF_INET;
    remote_hint.ai_socktype = SOCK_DGRAM;
    remote_hint.ai_protocol = IPPROTO_UDP;
    
    int addr_info_res;
    if(settings.use_me == 1)
        addr_info_res = getaddrinfo(settings.ip, 
            settings.remote_port, &remote_hint, remote_addr_ptr);
    else
        addr_info_res = getaddrinfo(SERVER_IP, SERVER_PORT, &remote_hint, remote_addr_ptr);
    
    if (addr_info_res != 0)
        exit(-1);

    return 0;
}

int _connect(struct transport_pcb_t* pcb) {
    Tremont_Nexus* nexus = pcb->nexus;

    tremont_set_size(1200, nexus);

    _get_remote_addrinfo(&pcb->remote_addrinfo);
   
    int res = -1;
    while (res != 0) {
        res = tremont_req_stream(CTRL_STREAM,
            pcb->remote_addrinfo->ai_addr, 3, nexus);
    }
    return 0;
}

int transport_init(struct transport_pcb_t* pcb) {
    _init_winsock();
    _setup_socket(&pcb->sock);
    _setup_tremont(&pcb->sock, &pcb->nexus);
    _connect(pcb);
    return 0;
}