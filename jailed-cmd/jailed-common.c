#include "jailed-common.h"

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
