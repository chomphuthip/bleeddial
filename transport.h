#pragma once

#include "common.h"

struct transport_pcb_t {
	Tremont_Nexus* nexus;
	SOCKET sock;
};

/*
	Initializes the transport stack.
*/
int transport_init(struct transport_pcb_t* pcb);