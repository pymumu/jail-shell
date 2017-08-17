
#ifndef _JAILED_COMMON_
#define _JAILED_COMMON_

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pty.h>
#include <unistd.h>
#include <stdlib.h>


#define TMP_BUFF_LEN_32 32
#define ARG_DATA_LEN 4096
#define SOCKET_BUFF_LEN (1024 * 32)

#define MSG_MAGIC 0x615461446C49614A /* JaIlDaTa */

enum CMD_MSG_TYPE {
	CMD_MSG_CMD        = 1,
	CMD_MSG_DATA_IN    = 2,
	CMD_MSG_DATA_OUT   = 3,
	CMD_MSG_DATA_ERR   = 4,
	CMD_MSG_EXIT_CODE  = 5,
	CMD_MSG_WINSIZE    = 6,
	CMD_BUTT = 255
};

struct jailed_cmd_head {
	unsigned long long magic;
	unsigned int type;
	unsigned int data_len;
	unsigned char data[0];
};

struct jailed_cmd_cmd {
	uid_t uid;
	uid_t gid;
	int isatty;
	char term[TMP_BUFF_LEN_32];
	struct winsize ws;
	int argc;
	char argvs[ARG_DATA_LEN];
};

struct jailed_cmd_data {
	unsigned char data[0];
};

struct jailed_cmd_exit {
	unsigned int exit_code;
};

struct jailed_cmd_winsize {
	struct winsize ws;
};

struct sock_data {
	int total_len;
	int curr_offset;
	char data[SOCKET_BUFF_LEN];
};

#endif

