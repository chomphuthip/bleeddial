#pragma once

#include "tremont.h"

//Make sure that the information is between quotes.
#define SERVER_IP "127.0.0.1"
#define SERVER_PORT "9999"
#define LOCAL_PORT "7777"

#define ENCRYPTION_KEY "I LOVE PARSING"
#define CTRL_STREAM 9999
#define CTRL_STREAM_PASSWD "badapple1998"

struct settings_t {
    uint16_t x6969;
    uint8_t use_me;

    char ip[16];
    char remote_port[16];
    char local_port[16];

    char priv[128];
    uint32_t priv_len;

    tremont_stream_id ctrl_stream;
    char auth[128];
    uint32_t auth_len;
};

extern struct settings_t settings;

struct transport_pcb_t {
	struct addrinfo* remote_addrinfo;
	Tremont_Nexus* nexus;
	SOCKET sock;
};

/*
	Initializes the transport stack.
*/
int transport_init(struct transport_pcb_t* pcb);