#include "jailed-cmd.h"
#include <pty.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PID_FILE_PATH "/var/run/jailed-cmdd.pid"
struct cmdd_context {
	int sock;
	int mirror;
	int mirror_err;
	int maxfd;
	
	fd_set rfds;
	fd_set wfds;

	int isatty;

	int is_mirror_eof;
	int is_mirror_err_eof;

	int child_pid;

	struct sock_data send_data;
	struct sock_data recv_data;
};

void help(void)
{
	char *help = ""
		"Usage: jailed-cmdd [OPTION]...\n"
		"Start jailed cmd proxy server.\n"
		"  -f            run forground.\n"
		"  -h            show this help message.\n"
		"\n"
		;
	printf(help);
}

int create_pid_file(const char *pid_file)
{
	int fd;
	int flags;
	char buff[TMP_BUFF_LEN_32];

	fd = open(pid_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		fprintf(stderr, "create pid file failed, %s", strerror(errno));
		return 1;
	}

	flags = fcntl(fd, F_GETFD); 
	if (flags < 0) {
		fprintf(stderr, "Could not get flags for PID file %s", pid_file);
		goto errout;
	}

	flags |= FD_CLOEXEC; 
	if (fcntl(fd, F_SETFD, flags) == -1) {
		fprintf(stderr, "Could not set flags for PID file %s", pid_file);
		goto errout;
	}

	if (lockf(fd, F_TLOCK, 0) < 0) {
		fprintf(stderr, "Server is already running.\n");
		goto errout;
	}

	snprintf(buff, TMP_BUFF_LEN_32, "%d\n", getpid());
	
	if (write(fd, buff, strnlen(buff, TMP_BUFF_LEN_32)) < 0) {
		fprintf(stderr, "write pid to file failed, %s.\n", strerror(errno));
		goto errout;
	}

	return fd;
errout:
	if (fd > 0) {
		close(fd);
	}
	return 1;
}

int forksocket(int *mirror, int *mirror_err)
{
	int fd[2];
	int fd_err[2];

	static const int parentsocket = 0;
	static const int childsocket = 1;

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fd) != 0) {
		return -1;
	}

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fd_err) != 0) {
		return -1;
	}

	int pid = fork();

	if (pid == 0) {
		close(fd[parentsocket]);
		close(0);
		close(1);
		close(2);

		dup2(fd[childsocket], 0);
		dup2(fd[childsocket], 1);
		dup2(fd_err[childsocket], 2);

		*mirror = fd[childsocket];
		*mirror_err = fd_err[childsocket];

		return pid;
	} else if (pid > 0) {
		close(fd[childsocket]);
		*mirror = fd[parentsocket];
		*mirror_err = fd_err[parentsocket];
	}

	return pid;
}

int start_process(struct jailed_cmd_cmd *cmd_cmd, int *mirror, int *mirror_err)
{
	int argc = cmd_cmd->argc;
	char *argv[argc + 1];
	int i = 0;
	int len = 0;
	int pid = -1;

	for (i = 0; i < cmd_cmd->argc; i++) {
		argv[i] = cmd_cmd->argvs + len;
		len += strlen(cmd_cmd->argvs + len) + 1;
	}
	argv[i] = 0;
	
	if (cmd_cmd->isatty) {
		pid = forkpty(mirror, NULL, NULL, &cmd_cmd->ws);
	} else {
		pid = forksocket(mirror, mirror_err);
	}

	if (pid < 0) {
		return -1;
	} else if (pid == 0) {
		close(*mirror);
		if (*mirror_err > 0) {
			close(*mirror_err);
		}
		setenv("TERM", cmd_cmd->term, 1);
		execv(argv[0], argv);
		printf(" : %s\n", strerror(errno));
		_exit(0);
	} 

	return pid;
}


CMD_RETURN process_msg(struct cmdd_context *context, struct jailed_cmd_head *cmd_head) 
{
	switch (cmd_head->type) {
	case CMD_MSG_CMD: {
		struct jailed_cmd_cmd *cmd_cmd = (struct jailed_cmd_cmd *)cmd_head->data;
		context->child_pid = start_process(cmd_cmd, &context->mirror, &context->mirror_err);
		context->isatty = cmd_cmd->isatty;

		FD_SET(context->mirror, &context->rfds);
		if (context->mirror_err > 0) {
			FD_SET(context->mirror_err, &context->rfds);
		}

		context->maxfd = max(context->maxfd, context->mirror);
		context->maxfd = max(context->maxfd, context->mirror_err);
		break; }
	case CMD_MSG_DATA_IN: {
		struct jailed_cmd_data *cmd_data = (struct jailed_cmd_data *)cmd_head->data;
		if (context->mirror < 0) {
			break;
		}
		write(context->mirror, cmd_data->data, cmd_head->data_len);
		break; }
	case CMD_MSG_DATA_EXIT: {
		FD_CLR(context->mirror, &context->rfds);
		close(context->mirror);
		context->mirror = -1;
		return CMD_RETURN_EXIT;
		break; }
	case CMD_MSG_WINSIZE: {
		struct jailed_cmd_winsize *cmd_winsize = (struct jailed_cmd_winsize *)cmd_head->data;
		ioctl(context->mirror, TIOCSWINSZ, &cmd_winsize->ws);
		break; }
	default:
		fprintf(stderr, "data type error.\r\n");
		return CMD_RETURN_EXIT;
	}

	return CMD_RETURN_OK;
}

CMD_RETURN send_sock(struct cmdd_context *context) 
{
	int len;

	len = send(context->sock, 
			context->send_data.data + context->send_data.curr_offset, 
			context->send_data.total_len - context->send_data.curr_offset, MSG_NOSIGNAL | MSG_DONTWAIT);
	if (len < 0) {
		fprintf(stderr, "socket send failed,  %s\n", strerror(errno));
		return CMD_RETURN_ERR;
	} 

	context->send_data.curr_offset += len;
	
	if (context->send_data.curr_offset == context->send_data.total_len) {
		FD_CLR(context->sock, &context->wfds);
		if (context->is_mirror_eof == 0) {
			FD_SET(context->mirror, &context->rfds);
		}

		if (context->is_mirror_err_eof == 0) {
			FD_SET(context->mirror_err, &context->rfds);
		}

		context->send_data.total_len = 0;
		context->send_data.curr_offset = 0;
	} else if (context->send_data.curr_offset > context->send_data.total_len) {
		fprintf(stderr, "BUG: internal error, data length mismach\n");
		return CMD_RETURN_ERR;
	} else {
		memmove(context->send_data.data, context->send_data.data + context->send_data.curr_offset, 
				context->send_data.total_len - context->send_data.curr_offset);
		context->send_data.total_len =  context->send_data.total_len - context->send_data.curr_offset;
		context->send_data.curr_offset = 0;
	}

	return CMD_RETURN_OK;
}

CMD_RETURN recv_sock(struct cmdd_context *context) 
{
	int len;
	struct jailed_cmd_head *cmd_head;
	CMD_RETURN retval;

	len = recv(context->sock, context->recv_data.data + context->recv_data.total_len, sizeof(context->recv_data.data) - context->recv_data.total_len, MSG_DONTWAIT);	
	if (len < 0) {
		fprintf(stderr, "recv from socket failed, %s\n", strerror(errno));
		return CMD_RETURN_ERR;
	} else if (len == 0) {
		FD_CLR(context->sock, &context->rfds);
		shutdown(context->sock, SHUT_RD);
		if (context->isatty) {
			close(context->mirror);
			context->mirror = -1;
			if (context->mirror_err > 0) {
				close(context->mirror_err);
				context->mirror_err = -1;
			}
		} else {
			shutdown(context->mirror, SHUT_WR);
			if (context->mirror_err > 0) {
				shutdown(context->mirror_err, SHUT_WR);
			}
		}
		return CMD_RETURN_OK;
	}

	context->recv_data.total_len += len;
	while (1) {
		if (context->recv_data.total_len - context->recv_data.curr_offset < sizeof(struct jailed_cmd_head)) {
			break;
		}

		cmd_head = (struct jailed_cmd_head *)(context->recv_data.data + context->recv_data.curr_offset);
		if (cmd_head->magic != MSG_MAGIC || cmd_head->data_len > sizeof(context->recv_data.data) - sizeof(struct jailed_cmd_head)) {
			fprintf(stderr, "Data invalid\n");
			return CMD_RETURN_ERR;
		}

		if (context->recv_data.total_len - context->recv_data.curr_offset < sizeof(struct jailed_cmd_head) + cmd_head->data_len) {
			break;
		}

		retval = process_msg(context, cmd_head);
		if (retval != CMD_RETURN_OK) {
			return retval;
		}

		context->recv_data.curr_offset += sizeof(struct jailed_cmd_head) + cmd_head->data_len;
	}

	if (context->recv_data.total_len > context->recv_data.curr_offset) {
		memmove(context->recv_data.data, context->recv_data.data + context->recv_data.curr_offset, context->recv_data.total_len - context->recv_data.curr_offset);
		context->recv_data.total_len -= context->recv_data.curr_offset;
		context->recv_data.curr_offset = 0;
	} else if (context->recv_data.total_len == context->recv_data.curr_offset) {
		context->recv_data.curr_offset = 0;
		context->recv_data.total_len = 0;
	} else {
		fprintf(stderr, "BUG: internal error, data length mismach\r\n");
	}

	return CMD_RETURN_OK;
}

CMD_RETURN read_mirror_err(struct cmdd_context *context) 
{
	struct jailed_cmd_head *cmd_head;
	struct jailed_cmd_data *cmd_data;

	int len;
	int free_buff_size;
	int need_size;

	free_buff_size = sizeof(context->send_data.data)  - context->send_data.total_len;
	need_size = sizeof(struct jailed_cmd_head) + sizeof(struct jailed_cmd_data) + 16;
	if ((free_buff_size - need_size) < 0) {
		FD_CLR(context->mirror_err, &context->rfds);
		return CMD_RETURN_OK;
	}
	
	cmd_head = (struct jailed_cmd_head *)(context->send_data.data + context->send_data.total_len);
	cmd_data = (struct jailed_cmd_data *)cmd_head->data;
	cmd_head->magic = MSG_MAGIC;
	cmd_head->type = CMD_MSG_DATA_ERR;
	len = read(context->mirror_err, cmd_data->data, free_buff_size - sizeof(struct jailed_cmd_head) - sizeof(struct jailed_cmd_data));
	if (len < 0) {
		fprintf(stderr, "read mirror_err failed, %s\n", strerror(errno));
		FD_CLR(context->mirror_err, &context->rfds);
		context->is_mirror_err_eof = 1;
		return CMD_RETURN_OK;
	} 

	cmd_head->data_len = len + sizeof(*cmd_data);
	context->send_data.total_len += sizeof(*cmd_head) + cmd_head->data_len;

	if (len == 0 ) {
		FD_CLR(context->mirror_err, &context->rfds);
		context->is_mirror_err_eof = 1;
		return CMD_RETURN_OK;
	}

	FD_SET(context->sock, &context->wfds);

	return CMD_RETURN_OK;
}

CMD_RETURN read_mirror(struct cmdd_context *context)
{
	struct jailed_cmd_head *cmd_head;
	struct jailed_cmd_data *cmd_data;

	int len;
	int free_buff_size;
	int need_size;

	free_buff_size = sizeof(context->send_data.data)  - context->send_data.total_len;
	need_size = sizeof(struct jailed_cmd_head) + sizeof(struct jailed_cmd_data) + 16;
	if ((free_buff_size - need_size) < 0) {
		FD_CLR(context->mirror, &context->rfds);
		return CMD_RETURN_OK;
	}
	
	cmd_head = (struct jailed_cmd_head *)(context->send_data.data + context->send_data.total_len);
	cmd_data = (struct jailed_cmd_data *)cmd_head->data;
	cmd_head->magic = MSG_MAGIC;
	cmd_head->type = CMD_MSG_DATA_OUT;
	len = read(context->mirror, cmd_data->data, free_buff_size - sizeof(struct jailed_cmd_head) - sizeof(struct jailed_cmd_data));
	if (len < 0) {
		CMD_RETURN retval;
		/*  if child process exits normally, return exit coode to peer client. */
		if (errno == EIO || errno == ECONNRESET) {
			retval = CMD_RETURN_EXIT;
		} else {
			fprintf(stderr, "read mirror failed, %s\n", strerror(errno));
			retval = CMD_RETURN_ERR;
		}
		FD_CLR(context->mirror, &context->rfds);
		context->is_mirror_eof = 1;
		return retval;
	} 

	cmd_head->data_len = len + sizeof(*cmd_data);
	context->send_data.total_len += sizeof(*cmd_head) + cmd_head->data_len;

	if (len == 0 ) {
		FD_CLR(context->mirror, &context->rfds);
		context->is_mirror_eof = 1;
		return CMD_RETURN_EXIT;
	}

	FD_SET(context->sock, &context->wfds);

	return CMD_RETURN_OK;
}

void send_exit_code(struct cmdd_context *context)
{
	int status = 0x100;

	if (context->send_data.total_len > 0) {
		send(context->sock, context->send_data.data + context->send_data.curr_offset, context->send_data.total_len - context->send_data.curr_offset, MSG_NOSIGNAL | MSG_DONTWAIT);
		context->send_data.total_len = 0;
		context->send_data.curr_offset = 0;
	}

	struct jailed_cmd_head *cmd_head = (struct jailed_cmd_head *)(context->send_data.data + context->send_data.total_len);
	struct jailed_cmd_exit *cmd_exit = (struct jailed_cmd_exit *)cmd_head->data;
	cmd_head->magic = MSG_MAGIC;
	cmd_head->type = CMD_MSG_EXIT_CODE;
	cmd_head->data_len = sizeof(*cmd_exit);
	context->send_data.total_len += sizeof(*cmd_head) + cmd_head->data_len;

	if (waitpid(context->child_pid, &status, 0) < 0) {
		fprintf(stderr, "wait pid failed.\n");
	}

	cmd_exit->exit_code = WEXITSTATUS(status);

	send(context->sock, context->send_data.data + context->send_data.curr_offset, context->send_data.total_len - context->send_data.curr_offset, MSG_NOSIGNAL | MSG_DONTWAIT);
}

void server_loop(struct cmdd_context *context)
{
	fd_set rfds_set;
	fd_set wfds_set;

	CMD_RETURN retval;
	int select_ret = 0;

	context->mirror = -1;
	context->mirror_err = -1;
	FD_ZERO(&context->rfds);
	FD_ZERO(&context->wfds);

	FD_SET(context->sock, &context->rfds);
	context->maxfd = max(context->sock, context->maxfd);
	
	while (1) {

		rfds_set = context->rfds;
		wfds_set = context->wfds;

		select_ret = select(context->maxfd + 1, &rfds_set, &wfds_set, NULL, NULL);
		if (select_ret < 0) {
			if (errno == EINTR) {
				continue;
			}
			fprintf(stderr, "select fd failed, %s\r\n", strerror(errno));
			goto out;
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

		if (context->mirror_err > 0 && FD_ISSET(context->mirror_err, &rfds_set)) {
			retval = read_mirror_err(context);
			if (retval == CMD_RETURN_EXIT) {
				goto out;
			} else if (retval == CMD_RETURN_ERR) {
				goto errout;
			}
		}

		if (FD_ISSET(context->mirror, &rfds_set)) {
			retval = read_mirror(context);
			if (retval == CMD_RETURN_EXIT) {
				goto out;
			} else if (retval == CMD_RETURN_ERR) {
				goto errout;
			}
		}

	}

out:
	send_exit_code(context);
errout:

	if (context->mirror > 0) {
		close(context->mirror);
	}

	if (context->mirror_err > 0) {
		close(context->mirror_err);
	}

	return;

}

void serve(int sock) 
{
	struct cmdd_context *context;

	context = malloc(sizeof(*context));
	if (context == NULL) {
		fprintf(stderr, "malloc context failed, %s\n", strerror(errno));
		goto errout;
	}
	memset(context, 0, sizeof(*context));

	set_sock_opt(sock);

	context->sock = sock;

	signal(SIGCHLD, SIG_DFL);
	server_loop(context);
	
errout:
	if (context) {
		free(context);
	}
}

int run_server(int port)
{
	int server;
	int sock;
	socklen_t clilen;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	int pid;
	int on = 1;

	server = socket(PF_INET, SOCK_STREAM, 0);
	if (server < 0) {
		fprintf(stderr, "create socket failed, %s\n", strerror(errno));
		return 1;
	}

	if (setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
		fprintf(stderr, "setsockopt socket opt SO_REUSEADDR failed, %s", strerror(errno));
		goto errout;
	}

	if (setsockopt(server, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)) != 0) {
		fprintf(stderr, "setsockopt socket opt SO_KEEPALIVE failed, %s", strerror(errno));
		goto errout;
	}

	if (fcntl(server, F_SETFD, fcntl(server, F_GETFD) | FD_CLOEXEC) != 0) {
		fprintf(stderr, "setsockopt socket opt FD_CLOEXEC failed, %s", strerror(errno));
		goto errout;
	}

	bzero((char *) &server_addr, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(server, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		fprintf(stderr, "bind port %d failed, %s\n", port, strerror(errno));
		goto errout;
	}

	if (listen(server, 10) < 0) {
		fprintf(stderr, "listen failed, %s\n", strerror(errno));
		goto errout;
	}

	while (1) {
		sock = accept(server, (struct sockaddr *)&client_addr, &clilen);
		if (sock < 0) {
			fprintf(stderr, "accept connection failed, %s\n", strerror(errno));
			continue;
		}

		fcntl(sock, F_SETFD, fcntl(sock, F_GETFD) | FD_CLOEXEC);

		pid = fork();
		if (pid == 0) {
			close(server);
			serve(sock);
			shutdown(sock, SHUT_RDWR);
			close(sock);
			_exit(0);
		} else if (pid > 0) {
			close(sock);
		} else {
			fprintf(stderr, "fork failed, err %s\n", strerror(errno));
		}
	}

	close(server);
	return 0;

errout:
	if (server > 0) {
		close(server);
	}
	return 1;
}

int main(int argc, char *argv[])
{
	int opt;
	int is_forground = 0;

	while ((opt = getopt(argc, argv, "fh")) != -1) {
		switch (opt) {
		case 'f':
			is_forground = 1;
			break;
		case 'h':
			help();
			return 1;
		}
	}
	if (is_forground == 0) {
		if (daemon(0, 0) < 0) {
			fprintf(stderr, "run daemon process failed, %s\n", strerror(errno));
			return 1;
		}
	}

	if (create_pid_file(PID_FILE_PATH) != 0) {
		//return 1;	
	}

	signal(SIGCHLD, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);

	return run_server(9999);
}
