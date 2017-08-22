
#ifndef _JAILED_CMD_
#define _JAILED_CMD_

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <pty.h>
#include <sys/stat.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include <stdlib.h>
#include <libgen.h>

#define TMP_BUFF_LEN_32 32
#define SOCKET_BUFF_LEN (1024 * 32)

#define MSG_MAGIC 0x615461446C49614A /* JaIlDaTa */

#define max(x, y) ({				\
	typeof(x) _max1 = (x);			\
	typeof(y) _max2 = (y);			\
	(void) (&_max1 == &_max2);		\
	_max1 > _max2 ? _max1 : _max2; })

typedef enum CMD_MSG_TYPE {
	CMD_MSG_CMD        = 1,
	CMD_MSG_DATA_IN    = 2,
	CMD_MSG_DATA_OUT   = 3,
	CMD_MSG_DATA_ERR   = 4,
	CMD_MSG_DATA_EXIT  = 5,
	CMD_MSG_EXIT_CODE  = 6,
	CMD_MSG_WINSIZE    = 7,
	CMD_MSG_BUTT = 255
}CMD_MSG_TYPE;

typedef enum CMD_RETURN {
	CMD_RETURN_OK      = 0,
	CMD_RETURN_EXIT    = 1,
	CMD_RETURN_ERR     = 2,
	CMD_RETURN_CONT    = 3,
	CMD_RETURN_BUTT    =255
}CMD_RETURN;

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
	char argvs[0];
};

struct jailed_cmd_data {
	unsigned char data[0];
};

struct jailed_cmd_exit {
	int exit_code;
};

struct jailed_cmd_winsize {
	struct winsize ws;
};

struct sock_data {
	int total_len;
	int curr_offset;
	char data[SOCKET_BUFF_LEN];
};

extern void set_sock_opt(int sock);

#endif

