#pragma once

#include<stdio.h>
#include<WS2tcpip.h>

#include "../common.h"

#include "transport.h"

#pragma comment(lib, "Ws2_32.lib")

#define ENCRYPTION_KEY "I LOVE PARSING"
#define PORT "9999"

void _init_winsock() {
    printf("Initiallizing Winsock...\n");
    WSADATA wsa_data;
    int startup_result = WSAStartup(MAKEWORD(2, 2), &wsa_data);

    if (startup_result != 0) {
        perror("Unable to initialize Winsock!\n");
        exit(-1);
    }
}

void _setup_socket(SOCKET* sock) {
    struct addrinfo* res = NULL;
    struct addrinfo hints;

    ZeroMemory(&hints, sizeof(hints));

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;
    int addr_info_res = getaddrinfo("127.0.0.1", PORT, &hints, &res);
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

void _setup_tremont(SOCKET* sock_ptr, Tremont_Nexus** nexus_ptr) {
    int res = 0;

    res = tremont_init_nexus(nexus_ptr);
    if (res != 0) {
        perror("Unable to initialize Tremont nexus!");
        exit(-1);
    }

    char key[] = ENCRYPTION_KEY;
    res = tremont_key_nexus(key, sizeof(key), *nexus_ptr);
    if (res != 0) {
        perror("Unable to key Tremont nexus!");
        exit(-1);
    }

    tremont_set_size(1200, *nexus_ptr);

    res = tremont_bind_nexus(*sock_ptr, *nexus_ptr);
    if (res != 0) {
        perror("Unable to bind Tremont nexus!");
        exit(-1);
    }
}

int transport_init(struct transport_pcb_t* pcb) {
    printf("Initializing transport...\n");
    _init_winsock();
    _setup_socket(&pcb->sock);
    _setup_tremont(&pcb->sock, &pcb->nexus);
    printf("Transport initialized!\n");
    return 0;
}