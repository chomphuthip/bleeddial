#pragma once

#include "../common.h"

enum cli_state_t {
	TOP,
	TONE,
	GUEST
};

struct cli_info_t {
	enum cli_state_t cli_state;
	endpoint_id_t endpoint_id;

	void* guest_shell_params;
	int (*guest_shell)(void* params);
};

int cli_main(struct bleeddial_ctx_t* ctx);