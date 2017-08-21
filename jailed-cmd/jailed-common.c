#include "jailed-cmd.h"

void set_sock_buff_size(int sockfd) 
{
	int n = 1024 * 1024;
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &n, sizeof(n)) == -1) {

	}
}

int send_data(int sockfd, void *data, size_t len, int flags)
{
	return 0;
}


void set_sock_opt(int sock)
{
	int on = 1;
	int buf_size = 512 * 1024;

	setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
	setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
	setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));

}
