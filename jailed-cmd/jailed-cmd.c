
#define _BSD_SOURCE
#include "jailed-common.h"
#include <pty.h>
#include <unistd.h>
#include <stdlib.h>

#define JAILED_CMD_NAME "jailed-cmd"

int window_size_changed = 0;
int is_term_mode_change = 0;
struct termios tmios;

void help(void)
{
	char *help = ""
		"Usage: jailed-cmd [command] [args]\n"
		"run jailed command.\n"
	   	"press CTRL+] to exit.\n"
		;
	printf(help);
}

int set_term(void)
{
	struct termios tm;

	tcgetattr(STDIN_FILENO,  &tmios);
	memcpy(&tm, &tmios, sizeof(tm));
	cfmakeraw(&tm);
	tcsetattr(STDIN_FILENO, TCSANOW, &tm);

	is_term_mode_change = 1;
	return 0;

}

void reset_term(void)
{
	if (is_term_mode_change == 0) {
		return ;
	}

	tcsetattr(STDIN_FILENO, TCSANOW, &tmios);
}

int init_cmd(struct sock_data *send_data, int argc, char *argv[])
{
	struct jailed_cmd_head *cmd_head = (struct jailed_cmd_head *)send_data->data;
	struct jailed_cmd_cmd *cmd = NULL;
	int arg_len = 0;
	int i = 0;

	cmd_head->magic = MSG_MAGIC;
	cmd_head->type = CMD_MSG_CMD;
	cmd_head->data_len = sizeof(*cmd);
	cmd = (struct jailed_cmd_cmd *)(cmd_head->data);

	cmd->uid = geteuid();
	cmd->gid = getegid();
	cmd->isatty = isatty(STDIN_FILENO);

	if (getenv("TERM") != NULL) {
		snprintf(cmd->term, TMP_BUFF_LEN_32, getenv("TERM"));
	} else {
		snprintf(cmd->term, TMP_BUFF_LEN_32, "xterm");
	}
	
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &cmd->ws) != 0) {
		fprintf(stderr, "get console win size failed, %s", strerror(errno));
		return 1;
	}
	
	cmd->argc = argc;
	for (i = 0; i < argc; i++) {
		strncpy(cmd->argvs + arg_len, argv[i], ARG_DATA_LEN - arg_len);
		arg_len += strnlen(argv[i], ARG_DATA_LEN) + 1;
	}
	cmd_head->data_len -= (ARG_DATA_LEN - arg_len);

	send_data->total_len = sizeof(*cmd_head) + cmd_head->data_len;
	send_data->curr_offset = 0;

	return 0;
}

int cmd_loop(int sock, struct sock_data *send_data, struct sock_data *recv_data)
{
	fd_set rfds;
	fd_set rfds_set;
	fd_set wfds;
	fd_set wfds_set;
	int len;
	int prog_exit = 0;

	int retval;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);

	FD_SET(0, &rfds);
	FD_SET(sock, &rfds);
	FD_SET(sock, &wfds);
	
	while (1) {

		if (window_size_changed) {	
			struct jailed_cmd_head *cmd_head = (struct jailed_cmd_head *)send_data->data;
			struct jailed_cmd_winsize *cmd_winsize = (struct jailed_cmd_winsize *)cmd_head->data;
			cmd_head->magic = MSG_MAGIC;
			cmd_head->type = CMD_MSG_WINSIZE;
    		if (ioctl(STDIN_FILENO, TIOCGWINSZ, &cmd_winsize->ws) != 0) {
				fprintf(stderr, "get console win size failed, %s", strerror(errno));
				return 1;
			}	
			cmd_head->data_len = sizeof(*cmd_winsize);
			send_data->total_len = sizeof(*cmd_head) + cmd_head->data_len;
			send_data->curr_offset = 0;

			window_size_changed = 0;
			FD_SET(sock, &wfds);
		}

		rfds_set = rfds;
		wfds_set = wfds;

		retval = select(sock + 1, &rfds_set, &wfds_set, NULL, NULL);
		if (retval < 0) {
			continue;
		} else if (retval == 0) {
			continue;
		} 

		if (FD_ISSET(sock, &wfds_set)) {
			len = send(sock, send_data->data + send_data->curr_offset, send_data->total_len - send_data->curr_offset, MSG_NOSIGNAL | MSG_DONTWAIT);
			if (len < 0) {
				return 1;
			} 

			send_data->curr_offset += len;
			
			if (len >= send_data->total_len) {
				FD_CLR(sock, &wfds);
				send_data->total_len = 0;
			}
		}

		if (FD_ISSET(0, &rfds_set)) {
        	if (send_data->total_len == 0) {
				struct jailed_cmd_head *cmd_head = (struct jailed_cmd_head *)send_data->data;
				struct jailed_cmd_data *cmd_data = (struct jailed_cmd_data *)cmd_head->data;
				cmd_head->magic = MSG_MAGIC;
				cmd_head->type = CMD_MSG_DATA_IN;
				len = read(0, cmd_data->data, sizeof(send_data->data) - sizeof(*cmd_data) - sizeof(*cmd_data));
				if (len <= 0) {
					FD_CLR(0, &rfds_set);
					continue;
				}


				cmd_head->data_len = len;
				send_data->total_len = sizeof(*cmd_head) + cmd_head->data_len;
				send_data->curr_offset = 0;

				if (len == 2 && strncmp(send_data->data, "^\[", 2) == 0) {
					return 0;
				}

				FD_SET(sock, &wfds);

			}
		}

		if (FD_ISSET(sock, &rfds_set)) {
			len = recv(sock, recv_data->data, sizeof(recv_data->data), MSG_DONTWAIT);	
			if (len < 0) {
				return 1;
			} else if (len == 0) {
				fprintf(stdout, "peer close\r\n");
				return 0;
			}

			recv_data->total_len += len;
			if (recv_data->total_len >= sizeof(struct jailed_cmd_head)) {
				struct jailed_cmd_head *cmd_head = (struct jailed_cmd_head *)recv_data->data;
				if (cmd_head->magic != MSG_MAGIC || cmd_head->data_len > sizeof(recv_data->data) - sizeof(struct jailed_cmd_head)) {
					fprintf(stderr, "Data error.\r\n");
					return 1;
				}

				if (recv_data->total_len >= sizeof(struct jailed_cmd_head) + cmd_head->data_len) {
					switch (cmd_head->type) {
					case CMD_MSG_DATA_OUT:
					{
						struct jailed_cmd_data *cmd_data = (struct jailed_cmd_data *)cmd_head->data;
						fprintf(stdout, "%s", cmd_data->data);
						break;
					}
					case CMD_MSG_DATA_ERR:
					{
						struct jailed_cmd_data *cmd_data = (struct jailed_cmd_data *)cmd_head->data;
						fprintf(stderr, "%s", cmd_data->data);
						break;
					}
					case CMD_MSG_EXIT_CODE:
					{
						struct jailed_cmd_exit *cmd_exit = (struct jailed_cmd_exit *)cmd_head->data;
						prog_exit = cmd_exit->exit_code;
						break;
					}
					default:
						fprintf(stderr, "data type error.\r\n");
						return 1;
					}
				}
			}
		}
	}


	return prog_exit;
}

int run_cmd(int argc, char * argv[], int port)
{
	int client;
	struct sockaddr_in server_addr;
	struct sock_data *send_data ;
	struct sock_data *recv_data ;
	int retval = 1;

	send_data = malloc(sizeof(*send_data));
	if (send_data == NULL) {
		fprintf(stderr, "malloc send buffer failed, %s\n", strerror(errno));
		goto errout;
	}
	memset(send_data, 0, sizeof(*send_data));

	recv_data = malloc(sizeof(*recv_data));
	if (recv_data == NULL) {
		fprintf(stderr, "malloc send buffer failed, %s\n", strerror(errno));
		goto errout;
	}
	memset(recv_data, 0, sizeof(*recv_data));

	client = socket(PF_INET, SOCK_STREAM, 0);
	if (client < 0) {
		fprintf(stderr, "create socket failed, %s\n", strerror(errno));
		goto errout;
	}

	bzero((char *) &server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (connect(client, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		fprintf(stderr, "connect to cmdd server failed, %s\n", strerror(errno));
		goto errout;
	}

	if (init_cmd(send_data, argc, argv) != 0) {
		fprintf(stderr, "init cmd failed.\n");
		goto errout;
	}

	if (isatty(STDIN_FILENO)) {
		set_term();
	}


	retval = cmd_loop(client, send_data, recv_data);

errout:
	if (client > 0) {
		close(client);
	}

	if (recv_data) {
		free(recv_data);
	}

	if (send_data) {
		free(send_data);
	}
	return retval;
}

void onexit(void) 
{
	if (isatty(STDIN_FILENO)) {
		reset_term();
	}
}

void signal_handler(int sig)
{
	switch(sig) {
	case SIGWINCH: 
		window_size_changed = 1;
		break;
	}
	onexit();
	_exit(1);
}

int main(int argc, char *argv[])
{
	if (argc <= 1) {
		help();
		return 1;
	}

	atexit(onexit);
	signal(SIGWINCH, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGQUIT, signal_handler);

	return run_cmd(argc - 1, argv + 1, 9999);
}

