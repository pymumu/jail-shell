#include "jailed-cmd.h"

void set_sock_opt(int sock)
{
	int on = 1;
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

}
