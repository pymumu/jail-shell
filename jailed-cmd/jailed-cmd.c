
#define _BSD_SOURCE
#include "jailed-common.h"

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

	memset(send_data, 0, sizeof(*send_data));
	cmd_head->magic = MSG_MAGIC;
	cmd_head->type = CMD_MSG_CMD;
	cmd_head->data_len = sizeof(*cmd);
	cmd = (struct jailed_cmd_cmd *)(cmd_head->data);

	cmd->uid = geteuid();
	cmd->gid = getegid();
	cmd->isatty = isatty(STDIN_FILENO);
	if (cmd->isatty) {
		if (getenv("TERM") != NULL) {
			snprintf(cmd->term, TMP_BUFF_LEN_32, getenv("TERM"));
		} else {
			snprintf(cmd->term, TMP_BUFF_LEN_32, "xterm");
		}
		
		if (ioctl(STDIN_FILENO, TIOCGWINSZ, &cmd->ws) != 0) {
			fprintf(stderr, "get console win size failed, %s", strerror(errno));
			return 1;
		}
	}
	
	cmd->argc = argc;
	for (i = 0; i < argc; i++) {
		strncpy(cmd->argvs + arg_len, argv[i], sizeof(send_data->data) - sizeof(*cmd_head) - sizeof(*cmd) - arg_len);
		arg_len += strlen(argv[i]) + 1;
	}
	cmd_head->data_len =  arg_len + sizeof(*cmd);

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
	int istty = isatty(STDIN_FILENO);
	int retval;
	int is_stdin_eof = 0;

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
			if (errno == EINTR) {
				continue;
			}
			fprintf(stderr, "select fd failed, %s\r\n", strerror(errno));
			return 1;
		} else if (retval == 0) {
			continue;
		} 

		if (FD_ISSET(sock, &wfds_set)) {
			len = send(sock, send_data->data + send_data->curr_offset, send_data->total_len - send_data->curr_offset, MSG_NOSIGNAL | MSG_DONTWAIT);
			if (len < 0) {
				fprintf(stderr, "socket send failed,  %s\r\n", strerror(errno));
				return 1;
			} 

			send_data->curr_offset += len;
			
			if (send_data->curr_offset == send_data->total_len) {
				FD_CLR(sock, &wfds);
				if (is_stdin_eof == 0) {
					FD_SET(0, &rfds);
				}
				send_data->total_len = 0;
				send_data->curr_offset = 0;
			} else if (send_data->curr_offset > send_data->total_len) {
				fprintf(stderr, "BUG: internal error, data length mismach\r\n");
				return 1;
			} else {
				memmove(send_data->data, send_data + send_data->curr_offset, send_data->total_len - send_data->curr_offset);
				send_data->total_len = send_data->total_len - send_data->curr_offset;
				send_data->curr_offset = 0;
			}
		}

		if (FD_ISSET(0, &rfds_set)) {
			int free_buff_size = sizeof(send_data->data)  - send_data->total_len;
			int need_size = sizeof(struct jailed_cmd_head) + sizeof(struct jailed_cmd_data) + 16;
			if ((free_buff_size - need_size) < 0) {
				FD_CLR(0, &rfds);
				continue;
			}
			struct jailed_cmd_head *cmd_head = (struct jailed_cmd_head *)(send_data->data + send_data->total_len);
			struct jailed_cmd_data *cmd_data = (struct jailed_cmd_data *)cmd_head->data;
			cmd_head->magic = MSG_MAGIC;
			cmd_head->type = CMD_MSG_DATA_IN;
			len = read(0, cmd_data->data, free_buff_size - sizeof(struct jailed_cmd_head) - sizeof(struct jailed_cmd_data));
			if (len < 0) {
				FD_CLR(0, &rfds);
				fprintf(stderr, "read mirror failed, %s\r\n", strerror(errno));
				return 1;
			} 

			cmd_head->data_len = len + sizeof(*cmd_data);;
			send_data->total_len += sizeof(*cmd_head) + cmd_head->data_len;

			if (len == 0 || (istty && len == 1 && cmd_data->data[0] == '\35')) {
				FD_CLR(0, &rfds);
				is_stdin_eof = !len;
				struct jailed_cmd_head *cmd_head_send = (struct jailed_cmd_head *)(send_data->data + send_data->total_len);
				cmd_head_send->magic = MSG_MAGIC;
				cmd_head_send->type = CMD_MSG_DATA_EXIT;
				cmd_head_send->data_len = 0;
				send_data->total_len += sizeof(*cmd_head_send) + cmd_head->data_len;
			}

			FD_SET(sock, &wfds);
		}

		if (FD_ISSET(sock, &rfds_set)) {
			len = recv(sock, recv_data->data + recv_data->total_len, sizeof(recv_data->data) - recv_data->total_len, MSG_DONTWAIT);	
			if (len < 0) {
				fprintf(stderr, "recv from socket failed, %s\r\n", strerror(errno));
				return 1;
			} else if (len == 0) {
				//TODO exit with error code.
				return 0;
			}

			recv_data->total_len += len;
			while (1) {
				if (recv_data->total_len >= sizeof(struct jailed_cmd_head)) {
					struct jailed_cmd_head *cmd_head = (struct jailed_cmd_head *)recv_data->data;
					if (cmd_head->magic != MSG_MAGIC || cmd_head->data_len > sizeof(recv_data->data) - sizeof(struct jailed_cmd_head)) {
						fprintf(stderr, "Data invalid, magic%llX:%llX, len=%d:%d.\n", 
								cmd_head->magic, MSG_MAGIC, cmd_head->data_len, sizeof(recv_data));
						return 1;
					}

					if (recv_data->total_len >= sizeof(struct jailed_cmd_head) + cmd_head->data_len) {
						switch (cmd_head->type) {
						case CMD_MSG_DATA_OUT:
						{
							struct jailed_cmd_data *cmd_data = (struct jailed_cmd_data *)cmd_head->data;
							write(STDOUT_FILENO, cmd_data->data, cmd_head->data_len);
							break;
						}
						case CMD_MSG_DATA_ERR:
						{
							struct jailed_cmd_data *cmd_data = (struct jailed_cmd_data *)cmd_head->data;
							write(STDOUT_FILENO, cmd_data->data, cmd_head->data_len);
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

						int cmd_msg_len = sizeof(struct jailed_cmd_head) + cmd_head->data_len;
						if (recv_data->total_len > cmd_msg_len) {
							memmove(recv_data->data, recv_data->data + cmd_msg_len, recv_data->total_len - cmd_msg_len);
							recv_data->curr_offset = 0;
						} 

						recv_data->total_len = recv_data->total_len - cmd_msg_len;
					} else {
						break;
					}
				} else {
					break;
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
		fprintf(stderr, "create socke failed, %s\n", strerror(errno));
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
		return;
		break;
	}
	onexit();
	_exit(1);
}

int main(int argc, char *argv[])
{
	struct stat buf;

	if (lstat(argv[0], &buf) != 0) {
		fprintf(stderr, "Get stat for %s failed, %s\n", argv[0], strerror(errno));
		return 1;
	}

	if (!S_ISLNK(buf.st_mode)) {
		argc -= 1;
		argv++;
		
		if (argc < 1) {
			help();
			return 1;
		}
	}


	atexit(onexit);
	signal(SIGWINCH, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGQUIT, signal_handler);

	return run_cmd(argc, argv, 9999);
}

