
#define _BSD_SOURCE
#include "jailed-cmd.h"

#define JAILED_CMD_NAME "jailed-cmd"

int window_size_changed = 0;
int is_term_mode_change = 0;
struct termios tmios;

struct cmd_context {
	int sock;
	int maxfd;

	int isatty;
	
	fd_set rfds;
	fd_set wfds;

	int is_stdin_eof;

	struct sock_data send_data;
	struct sock_data recv_data;

	int prog_exit;
};

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

int cmd_init(struct cmd_context *context, int argc, char *argv[])
{
	struct jailed_cmd_head *cmd_head = (struct jailed_cmd_head *)context->send_data.data;
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
	if (cmd->isatty) {
		if (getenv("TERM") != NULL) {
			snprintf(cmd->term, TMP_BUFF_LEN_32, getenv("TERM"));
		} else {
			snprintf(cmd->term, TMP_BUFF_LEN_32, "xterm");
		}
		
		if (ioctl(STDIN_FILENO, TIOCGWINSZ, &cmd->ws) != 0) {
			fprintf(stderr, "get console win size failed, %s\r\n", strerror(errno));
			return 1;
		}
	}
	
	cmd->argc = argc;
	for (i = 0; i < argc; i++) {
		strncpy(cmd->argvs + arg_len, argv[i], sizeof(context->send_data.data) - sizeof(*cmd_head) - sizeof(*cmd) - arg_len);
		arg_len += strlen(argv[i]) + 1;
	}
	cmd_head->data_len =  arg_len + sizeof(*cmd);

	context->send_data.total_len = sizeof(*cmd_head) + cmd_head->data_len;
	context->send_data.curr_offset = 0;

	return 0;
}

CMD_RETURN read_stdin(struct cmd_context *context) 
{
	int free_buff_size;
	int need_size;
	int len;

	struct jailed_cmd_head *cmd_head;
	struct jailed_cmd_data *cmd_data;

	free_buff_size = sizeof(context->send_data.data)  - context->send_data.total_len;
	need_size = sizeof(struct jailed_cmd_head) + sizeof(struct jailed_cmd_data) + 16;
	if ((free_buff_size - need_size) < 0) {
		FD_CLR(STDIN_FILENO, &context->rfds);
		return CMD_RETURN_OK;
	}
	
	cmd_head = (struct jailed_cmd_head *)(context->send_data.data + context->send_data.total_len);
	cmd_data = (struct jailed_cmd_data *)cmd_head->data;
	cmd_head->magic = MSG_MAGIC;
	cmd_head->type = CMD_MSG_DATA_IN;
	len = read(STDIN_FILENO, cmd_data->data, free_buff_size - sizeof(struct jailed_cmd_head) - sizeof(struct jailed_cmd_data));
	if (len < 0) {
		FD_CLR(STDIN_FILENO, &context->rfds);
		fprintf(stderr, "read mirror failed, %s\r\n", strerror(errno));
		return CMD_RETURN_ERR;
	} 

	cmd_head->data_len = len + sizeof(*cmd_data);;
	context->send_data.total_len += sizeof(*cmd_head) + cmd_head->data_len;
	if (len == 0) {
		FD_CLR(STDIN_FILENO, &context->rfds);
		shutdown(context->sock, SHUT_WR);
		return CMD_RETURN_OK;
	}

	if (context->isatty && len == 1 && cmd_data->data[0] == '\35') {
		FD_CLR(STDIN_FILENO, &context->rfds);
		context->is_stdin_eof = 1;
		struct jailed_cmd_head *cmd_head_send = (struct jailed_cmd_head *)(context->send_data.data);
		cmd_head_send->magic = MSG_MAGIC;
		cmd_head_send->type = CMD_MSG_DATA_EXIT;
		cmd_head_send->data_len = 0;
		context->send_data.total_len = sizeof(*cmd_head_send) + cmd_head_send->data_len;
	}

	FD_SET(context->sock, &context->wfds);

	return CMD_RETURN_OK;
}

CMD_RETURN process_msg(struct cmd_context *context, struct jailed_cmd_head *cmd_head) 
{	
	switch (cmd_head->type) {
	case CMD_MSG_DATA_OUT: {
		struct jailed_cmd_data *cmd_data = (struct jailed_cmd_data *)cmd_head->data;
		write(STDOUT_FILENO, cmd_data->data, cmd_head->data_len);
		break; }
	case CMD_MSG_DATA_ERR: {
		struct jailed_cmd_data *cmd_data = (struct jailed_cmd_data *)cmd_head->data;
		write(STDERR_FILENO, cmd_data->data, cmd_head->data_len);
		break; }
	case CMD_MSG_EXIT_CODE: {
		struct jailed_cmd_exit *cmd_exit = (struct jailed_cmd_exit *)cmd_head->data;
		context->prog_exit = cmd_exit->exit_code;
		return CMD_RETURN_EXIT;
		break; }
	default:
		fprintf(stderr, "data type error.\r\n");
		return CMD_RETURN_ERR;
	}
	
	return CMD_RETURN_OK;
}

CMD_RETURN send_sock(struct cmd_context *context) 
{
	int len;

	len = send(context->sock, context->send_data.data + context->send_data.curr_offset, context->send_data.total_len - context->send_data.curr_offset, MSG_NOSIGNAL | MSG_DONTWAIT);
	if (len < 0) {
		fprintf(stderr, "socket send failed,  %s\r\n", strerror(errno));
		return CMD_RETURN_ERR;
	} 

	context->send_data.curr_offset += len;
	
	if (context->send_data.curr_offset == context->send_data.total_len) {
		FD_CLR(context->sock, &context->wfds);
		if (context->is_stdin_eof == 0) {
			FD_SET(STDIN_FILENO, &context->rfds);
		}
		context->send_data.total_len = 0;
		context->send_data.curr_offset = 0;
	} else if (context->send_data.curr_offset > context->send_data.total_len) {
		fprintf(stderr, "BUG: internal error, data length mismach\r\n");
		return CMD_RETURN_ERR;
	} else {
		memmove(context->send_data.data, context->send_data.data + context->send_data.curr_offset, context->send_data.total_len - context->send_data.curr_offset);
		context->send_data.total_len = context->send_data.total_len - context->send_data.curr_offset;
		context->send_data.curr_offset = 0;
	}

	return CMD_RETURN_OK;
}

CMD_RETURN recv_sock(struct cmd_context *context) 
{
	int len;
	struct jailed_cmd_head *cmd_head;
	CMD_RETURN retval;

	len = recv(context->sock, context->recv_data.data + context->recv_data.total_len, sizeof(context->recv_data.data) - context->recv_data.total_len, MSG_DONTWAIT);	
	if (len < 0) {
		fprintf(stderr, "recv from socket failed, %s\r\n", strerror(errno));
		return CMD_RETURN_ERR;
	} else if (len == 0) {
		FD_CLR(context->sock, &context->rfds);
		return CMD_RETURN_EXIT;
	}

	context->recv_data.total_len += len;
	while (1) {
		if (context->recv_data.total_len < sizeof(struct jailed_cmd_head)) {
			break;
		}

		cmd_head = (struct jailed_cmd_head *)context->recv_data.data;
		if (cmd_head->magic != MSG_MAGIC || cmd_head->data_len > sizeof(context->recv_data.data) - sizeof(struct jailed_cmd_head)) {
			fprintf(stderr, "Data invalid, magic:%llX:%llX, len=%d:%d.\n", 
					cmd_head->magic, MSG_MAGIC, cmd_head->data_len, sizeof(context->recv_data));
			return CMD_RETURN_ERR;
		}

		if (context->recv_data.total_len < sizeof(struct jailed_cmd_head) + cmd_head->data_len) {
			break;
		}

		retval = process_msg(context, cmd_head);
		if (retval != CMD_RETURN_OK) {
			return retval;
		}

		int cmd_msg_len = sizeof(struct jailed_cmd_head) + cmd_head->data_len;
		if (context->recv_data.total_len > cmd_msg_len) {
			memmove(context->recv_data.data, context->recv_data.data + cmd_msg_len, context->recv_data.total_len - cmd_msg_len);
			context->recv_data.curr_offset = 0;
		} 

		context->recv_data.total_len -= cmd_msg_len;
	}

	return CMD_RETURN_OK;
}

int set_win_size(struct cmd_context *context) 
{
	struct jailed_cmd_head *cmd_head;
	struct jailed_cmd_winsize *cmd_winsize;

	if (window_size_changed == 0) {
		return 0;
	}	

	cmd_head = (struct jailed_cmd_head *)context->send_data.data;
	cmd_winsize = (struct jailed_cmd_winsize *)cmd_head->data;
	cmd_head->magic = MSG_MAGIC;
	cmd_head->type = CMD_MSG_WINSIZE;
	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &cmd_winsize->ws) != 0) {
		fprintf(stderr, "get console win size failed, %s", strerror(errno));
		return 1;
	}	

	cmd_head->data_len = sizeof(*cmd_winsize);
	context->send_data.total_len = sizeof(*cmd_head) + cmd_head->data_len;
	context->send_data.curr_offset = 0;

	window_size_changed = 0;
	FD_SET(context->sock, &context->wfds);

	return 0;
}

int cmd_loop(struct cmd_context *context)
{
	fd_set rfds_set;
	fd_set wfds_set;

	CMD_RETURN retval;
	int select_ret = 0;

	FD_ZERO(&context->rfds);
	FD_ZERO(&context->wfds);

	FD_SET(STDIN_FILENO, &context->rfds);
	FD_SET(context->sock, &context->rfds);
	FD_SET(context->sock, &context->wfds);
	
	while (1) {

		if (set_win_size(context) != 0) {
			goto errout;
		}

		rfds_set = context->rfds;
		wfds_set = context->wfds;

		select_ret = select(context->sock + 1, &rfds_set, &wfds_set, NULL, NULL);
		if (select_ret < 0) {
			if (errno == EINTR) {
				continue;
			}
			fprintf(stderr, "select fd failed, %s\r\n", strerror(errno));
			goto errout;
		} else if (select_ret == 0) {
			continue;
		}

		if (FD_ISSET(context->sock, &rfds_set)) {
			retval = recv_sock(context);
			if (retval == CMD_RETURN_EXIT) {
				goto out;
			} else if (retval == CMD_RETURN_ERR) {
				goto errout;
			}
		}

		if (FD_ISSET(context->sock, &wfds_set)) {
			retval = send_sock(context);
			if (retval == CMD_RETURN_EXIT) {
				goto out;
			} else if (retval == CMD_RETURN_ERR) {
				goto errout;
			}
		}

		if (FD_ISSET(STDIN_FILENO, &rfds_set)) {
			retval = read_stdin(context);
			if (retval == CMD_RETURN_EXIT) {
				goto out;
			} else if (retval == CMD_RETURN_ERR) {
				goto errout;
			}
		}
	}

out:
	return context->prog_exit;

errout:
	return 1;
}

int run_cmd(int argc, char * argv[], int port)
{
	int client;
	struct cmd_context *context;
	struct sockaddr_in server_addr;
	int retval = 1;

	context = malloc(sizeof(*context));
	if (context == NULL) {
		fprintf(stderr, "malloc cmd context failed, %s\n", strerror(errno));
		goto errout;
	}
	memset(context, 0, sizeof(*context));

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

	if (cmd_init(context, argc, argv) != 0) {
		fprintf(stderr, "init cmd failed.\n");
		goto errout;
	}

	context->sock = client;
	context->isatty = isatty(STDIN_FILENO);
	
	if (context->isatty) {
		set_term();
	}

	retval = cmd_loop(context);

errout:
	if (client > 0) {
		close(client);
	}

	if (context) {
		free(context);
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
		if (isatty(STDIN_FILENO)) {
			window_size_changed = 1;
		}
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

