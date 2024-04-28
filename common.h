#pragma once

#include<stdint.h>

#define _AMD64_
#include<synchapi.h>

#include "tremont.h"


typedef uint32_t endpoint_id_t;

struct bleeddial_ctx_t {
	CRITICAL_SECTION transport_pcb_cs;
	struct transport_pcb_t* transport_pcb;

	CRITICAL_SECTION endpoint_db_cs;
	struct endpoint_db_t* endpoint_db;

	CRITICAL_SECTION cli_info_cs;
	struct cli_info_t* cli_info;
};