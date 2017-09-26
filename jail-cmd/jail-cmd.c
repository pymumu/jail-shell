/*
 * Copyright (C) 2017 Ruilin Peng (Nick) <pymumu@gmail.com>
 */

#include "jail-cmd.h"

#define JAIL_CMD "jail-cmd"
#define JAIL_CMD_CONF_FILE "/etc/jail-shell/cmd_config"

int window_size_changed = 0;
int is_term_mode_change = 0;
struct termios tmios;
int is_atty = 0;

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

struct cmd_config {
	int port;
};

struct cmd_config config = {
	.port = DEFAULT_PORT,
};

void help(void)
{
	char *help = ""
		"Usage: jail-cmd [command] [args]\n"
		"run jail command.\n"
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

/*  send user information, term information, args to peer server. */
int cmd_init(struct cmd_context *context, int argc, char *argv[])
{
	struct jail_cmd_head *cmd_head = (struct jail_cmd_head *)context->send_data.data;
	struct jail_cmd_cmd *cmd = NULL;
	int arg_len = 0;
	int i = 0;
	char *jsidkey = NULL;

	cmd_head->magic = MSG_MAGIC;
	cmd_head->type = CMD_MSG_CMD;
	cmd_head->data_len = sizeof(*cmd);
	cmd = (struct jail_cmd_cmd *)(cmd_head->data);

	cmd->uid = geteuid();
	cmd->gid = getegid();
	cmd->isatty = is_atty;

	jsidkey = getenv(JAIL_KEY);
	if (jsidkey) {
		strncpy(cmd->jsid, getenv(JAIL_KEY), sizeof(cmd->jsid));
	} else {
		memset(cmd->jsid, 0, sizeof(cmd->jsid));
	}

	if (cmd->isatty) {
		/*  send term name to server */
		if (getenv("TERM") != NULL) {
			snprintf(cmd->term, TMP_BUFF_LEN_32, getenv("TERM"));
		} else {
			snprintf(cmd->term, TMP_BUFF_LEN_32, "xterm");
		}
		
		/*  send term win size to server */
		if (ioctl(STDIN_FILENO, TIOCGWINSZ, &cmd->ws) != 0) {
			fprintf(stderr, "get console win size failed, %s\r\n", strerror(errno));
			return -1;
		}
	}
	
	/*  send args to server 
	 *  data format: arg0\0arg1\0arg2\0...argn\0\0"
	 */
	
	cmd->argc = argc;
	if (argc > MAX_ARGS_COUNT) {
		fprintf(stderr, "too many args list.\r\n");
		return -1;
	}

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
	int len;
	int need_size;
	int free_buff_size;

	struct jail_cmd_head *cmd_head;
	struct jail_cmd_data *cmd_data;

	free_buff_size = sizeof(context->send_data.data)  - context->send_data.total_len;
	/*  if free space is not enougth, then block reading from stdin */
	need_size = sizeof(struct jail_cmd_head) + sizeof(struct jail_cmd_data) + 16;
	if ((free_buff_size - need_size) < 0) {
		FD_CLR(STDIN_FILENO, &context->rfds);
		return CMD_RETURN_OK;
	}
	
	cmd_head = (struct jail_cmd_head *)(context->send_data.data + context->send_data.total_len);
	cmd_data = (struct jail_cmd_data *)cmd_head->data;
	cmd_head->magic = MSG_MAGIC;
	cmd_head->type = CMD_MSG_DATA_IN;
	len = read(STDIN_FILENO, cmd_data->data, free_buff_size - sizeof(struct jail_cmd_head) - sizeof(struct jail_cmd_data));
	if (len < 0) {
		FD_CLR(STDIN_FILENO, &context->rfds);
		fprintf(stderr, "read mirror failed, %s\r\n", strerror(errno));
		return CMD_RETURN_ERR;
	} else if (len == 0) {
		/*  end of stdin, stop read stdin, and wake up sock , to send remain data to server.*/
		FD_CLR(STDIN_FILENO, &context->rfds);
		context->is_stdin_eof = 1;
		FD_SET(context->sock, &context->wfds);
		return CMD_RETURN_OK;
	}

	cmd_head->data_len = len + sizeof(*cmd_data);;
	context->send_data.total_len += sizeof(*cmd_head) + cmd_head->data_len;

	if (context->isatty && len == 1 && cmd_data->data[0] == '\35') {
		/*  if user press CTRL + ], then force exit. */
		FD_CLR(STDIN_FILENO, &context->rfds);
		context->is_stdin_eof = 1;
		cmd_head->magic = MSG_MAGIC;
		cmd_head->type = CMD_MSG_DATA_EXIT;
	}

	/*  have read data from stdin, wake up sock, and start send. */
	FD_SET(context->sock, &context->wfds);

	return CMD_RETURN_OK;
}

CMD_RETURN process_cmd(struct cmd_context *context, struct jail_cmd_head *cmd_head) 
{	
	switch (cmd_head->type) {
	case CMD_MSG_DATA_OUT: {
		 /*  Write out data to stdout */
		struct jail_cmd_data *cmd_data = (struct jail_cmd_data *)cmd_head->data;
		write(STDOUT_FILENO, cmd_data->data, cmd_head->data_len);
		break; }
	case CMD_MSG_DATA_ERR: {
		 /*  Write err data to stderr */
		struct jail_cmd_data *cmd_data = (struct jail_cmd_data *)cmd_head->data;
		write(STDERR_FILENO, cmd_data->data, cmd_head->data_len);
		break; }
	case CMD_MSG_EXIT_CODE: {
		/*  get exit code from peer child process */
		struct jail_cmd_exit *cmd_exit = (struct jail_cmd_exit *)cmd_head->data;
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

	/*  send data to server */
	len = send(context->sock, context->send_data.data + context->send_data.curr_offset, context->send_data.total_len - context->send_data.curr_offset, MSG_NOSIGNAL | MSG_DONTWAIT);
	if (len < 0) {
		fprintf(stderr, "socket send failed,  %s\r\n", strerror(errno));
		return CMD_RETURN_ERR;
	} 
	context->send_data.curr_offset += len;
	
	if (context->send_data.curr_offset == context->send_data.total_len) {
		/*  if all data has been sent, stop send event, and reset buffer length info */
		FD_CLR(context->sock, &context->wfds);
		context->send_data.total_len = 0;
		context->send_data.curr_offset = 0;
	} else if (context->send_data.curr_offset < context->send_data.total_len){
		/*  exists more data, move data to the beggining of the buffer */
		memmove(context->send_data.data, context->send_data.data + context->send_data.curr_offset, context->send_data.total_len - context->send_data.curr_offset);
		context->send_data.total_len = context->send_data.total_len - context->send_data.curr_offset;
		context->send_data.curr_offset = 0;
	} else {
		fprintf(stderr, "BUG: internal error, data length mismach\r\n");
		return CMD_RETURN_ERR;
	}

	if (context->is_stdin_eof == 0) {
		/*  Have enough free buff now, wake up stdin, and read. */
		FD_SET(STDIN_FILENO, &context->rfds);
	} else if (context->is_stdin_eof == 1 && context->send_data.total_len == 0) {
		/*  if stdin is closed and all data has been sent, then shutdown sock, to notify peer server exit. */
		shutdown(context->sock, SHUT_WR);
	}

	return CMD_RETURN_OK;
}

CMD_RETURN recv_sock(struct cmd_context *context) 
{
	int len;
	struct jail_cmd_head *cmd_head;
	CMD_RETURN retval;

	/*  recv data from peer server */
	len = recv(context->sock, context->recv_data.data + context->recv_data.total_len, sizeof(context->recv_data.data) - context->recv_data.total_len, MSG_DONTWAIT);	
	if (len < 0) {
		fprintf(stderr, "recv from socket failed, %s\r\n", strerror(errno));
		return CMD_RETURN_ERR;
	} else if (len == 0) {
		/*  if peer server closed, then exit. */
		FD_CLR(context->sock, &context->rfds);
		return CMD_RETURN_EXIT;
	}

	context->recv_data.total_len += len;

	/*  process data which received from server. */
	while (1) {
		/*  if data is partial, continue recv */
		if (context->recv_data.total_len - context->recv_data.curr_offset < sizeof(struct jail_cmd_head)) {
			break;
		}

		cmd_head = (struct jail_cmd_head *)(context->recv_data.data + context->recv_data.curr_offset);
		if (cmd_head->magic != MSG_MAGIC || cmd_head->data_len > sizeof(context->recv_data.data) - sizeof(struct jail_cmd_head)) {
			/*  if recevied error data, exit. */
			fprintf(stderr, "Data invalid\r\n"); 
			return CMD_RETURN_ERR;
		}

		/*  if data is partial, continue recv */
		if (context->recv_data.total_len - context->recv_data.curr_offset < sizeof(struct jail_cmd_head) + cmd_head->data_len) {
			break;
		}

		retval = process_cmd(context, cmd_head);
		if (retval != CMD_RETURN_OK) {
			return retval;
		}

		context->recv_data.curr_offset += sizeof(struct jail_cmd_head) + cmd_head->data_len;
	}

	if (context->recv_data.total_len == context->recv_data.curr_offset) {
		/*  if all data has been proceed, reset buffer length info */
		context->recv_data.curr_offset = 0;
		context->recv_data.total_len = 0;
	} else if (context->recv_data.total_len > context->recv_data.curr_offset) {
		/*  exists more data, move data to the beggining of the buffer */
		memmove(context->recv_data.data, context->recv_data.data + context->recv_data.curr_offset, context->recv_data.total_len - context->recv_data.curr_offset);
		context->recv_data.total_len -= context->recv_data.curr_offset;
		context->recv_data.curr_offset = 0;
	} else {
		fprintf(stderr, "BUG: internal error, data length mismach\r\n");
		return CMD_RETURN_ERR;
	}

	return CMD_RETURN_OK;
}

int set_win_size(struct cmd_context *context) 
{
	struct jail_cmd_head *cmd_head;
	struct jail_cmd_winsize *cmd_winsize;

	if (window_size_changed == 0) {
		return 0;
	}	

	if (sizeof(context->send_data.data) - context->send_data.total_len < sizeof(struct jail_cmd_head)) {
		return 0;
	}

	/*  if terminal win size changed, read winsize and send to peer server */
	cmd_head = (struct jail_cmd_head *)(context->send_data.data + context->send_data.total_len);
	cmd_winsize = (struct jail_cmd_winsize *)cmd_head->data;
	cmd_head->magic = MSG_MAGIC;
	cmd_head->type = CMD_MSG_WINSIZE;
	if (ioctl(STDIN_FILENO, TIOCGWINSZ, &cmd_winsize->ws) != 0) {
		fprintf(stderr, "get console win size failed, %s\r\n", strerror(errno));
		return -1;
	}	

	cmd_head->data_len = sizeof(*cmd_winsize);
	context->send_data.total_len += sizeof(*cmd_head) + cmd_head->data_len;

	window_size_changed = 0;
	/*  set sock write event, to send win size info. */
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
	/*  this event will send CMD_MSG_CMD message initialized by cmd_init*/
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
			/*  recv message from peer server */
			retval = recv_sock(context);
			if (retval == CMD_RETURN_EXIT) {
				goto out;
			} else if (retval == CMD_RETURN_ERR) {
				goto errout;
			}
		}

		if (FD_ISSET(context->sock, &wfds_set)) {
			/*  send message to peer server */
			retval = send_sock(context);
			if (retval == CMD_RETURN_EXIT) {
				goto out;
			} else if (retval == CMD_RETURN_ERR) {
				goto errout;
			}
		}

		if (FD_ISSET(STDIN_FILENO, &rfds_set)) {
			/*  read data from stdin */
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
	return -1;
}

int run_cmd(int argc, char * argv[], int port)
{
	int client = -1;
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

	set_sock_opt(client);

	context->sock = client;
	
	/*  whether current shell is interactive */
	context->isatty = is_atty;
	
	if (context->isatty) {
		/*  if current shell is interactive, then make this shell in raw mode. */
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
	if (is_atty) {
		reset_term();
	}
}

void signal_handler(int sig)
{
	switch(sig) {
	case SIGWINCH: 
		if (is_atty) {
			window_size_changed = 1;
		}
		return;
		break;
	}

	onexit();
	_exit(1);
}

int load_cmd_config(char *param, char *value)
{
	if (strncmp(param, CONF_PORT, sizeof(CONF_PORT)) == 0) {
		int port = atoi(value);
		if (port <= 0) {
			fprintf(stderr, "port is invalid: %s\n", value);
			return -1;
		}

		config.port = port;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	/*  if command is not executed from symbol link, the arg[1] is the command will being executed */
	if (strncmp(basename(argv[0]), JAIL_CMD, PATH_MAX) == 0) {
		argc -= 1;
		argv++;
		
		if (argc < 1) {
			help();
			return 1;
		}
	}

	is_atty = (isatty(STDIN_FILENO) && isatty(STDOUT_FILENO)) ? 1 : 0;

	atexit(onexit);

	if (access(JAIL_CMD_CONF_FILE, R_OK) == 0) {
		if (load_config(JAIL_CMD_CONF_FILE, load_cmd_config) != 0 ) {
			fprintf(stderr, "load configuration failed.\n");
			return 1;
		}
	}

	signal(SIGWINCH, signal_handler);
	signal(SIGTERM, signal_handler);
	signal(SIGQUIT, signal_handler);

	return run_cmd(argc, argv, config.port);
}

