#include "jailed-common.h"
#include <pty.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PID_FILE_PATH "/var/run/jailed-cmdd.pid"

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

void server_loop(int sock, struct sock_data *send_data, struct sock_data *recv_data)
{
	fd_set rfds;
	fd_set rfds_set;
	fd_set wfds;
	fd_set wfds_set;

	int len;
	int retval;
	int mirror = -1;
	int mirror_err = -1;
	int is_mirror_eof = 0;
	int is_mirror_err_eof = 0;
	int maxfd = 0;
	int child_pid = -1;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);

	FD_SET(sock, &rfds);
	maxfd = max(sock, maxfd);
	
	while (1) {

		rfds_set = rfds;
		wfds_set = wfds;

		retval = select(maxfd + 1, &rfds_set, &wfds_set, NULL, NULL);
		if (retval < 0) {
			if (errno == EINTR) {
				continue;
			}
			fprintf(stderr, "select fd failed, %s\r\n", strerror(errno));
			return ;
		} else if (retval == 0) {
			continue;
		} 

		if (FD_ISSET(sock, &wfds_set)) {
			len = send(sock, send_data->data + send_data->curr_offset, send_data->total_len - send_data->curr_offset, MSG_NOSIGNAL | MSG_DONTWAIT);
			if (len < 0) {
				fprintf(stderr, "socket send failed,  %s\n", strerror(errno));
				goto out;
			} 

			send_data->curr_offset += len;
			
			if (send_data->curr_offset == send_data->total_len) {
				FD_CLR(sock, &wfds);
				if (is_mirror_eof == 0) {
					FD_SET(mirror, &rfds);
				}

				if (is_mirror_err_eof == 0) {
					FD_SET(mirror_err, &rfds);
				}

				send_data->total_len = 0;
				send_data->curr_offset = 0;
			} else if (send_data->curr_offset > send_data->total_len) {
				fprintf(stderr, "BUG: internal error, data length mismach\n");
				goto out;
			} else {
				memmove(send_data->data, send_data + send_data->curr_offset, send_data->total_len - send_data->curr_offset);
				send_data->total_len =  send_data->total_len - send_data->curr_offset;
				send_data->curr_offset = 0;
			}
		}


		if (FD_ISSET(mirror, &rfds_set)) {
			int free_buff_size = sizeof(send_data->data)  - send_data->total_len;
			int need_size = sizeof(struct jailed_cmd_head) + sizeof(struct jailed_cmd_data) + 16;
			if ((free_buff_size - need_size) < 0) {
				FD_CLR(mirror, &rfds);
				continue;
			}
			struct jailed_cmd_head *cmd_head = (struct jailed_cmd_head *)(send_data->data + send_data->total_len);
			struct jailed_cmd_data *cmd_data = (struct jailed_cmd_data *)cmd_head->data;
			cmd_head->magic = MSG_MAGIC;
			cmd_head->type = CMD_MSG_DATA_OUT;
			len = read(mirror, cmd_data->data, free_buff_size - sizeof(struct jailed_cmd_head) - sizeof(struct jailed_cmd_data));
			if (len < 0) {
				fprintf(stderr, "read mirror failed, %s\n", strerror(errno));
				FD_CLR(mirror, &rfds);
				is_mirror_eof = !len;
				break;
			} 

			cmd_head->data_len = len + sizeof(*cmd_data);
			send_data->total_len += sizeof(*cmd_head) + cmd_head->data_len;

			if (len == 0 ) {
				FD_CLR(mirror, &rfds);
				is_mirror_eof = !len;
				break;
			}

			FD_SET(sock, &wfds);
		}

		if (mirror_err > 0 && FD_ISSET(mirror_err, &rfds_set)) {
			int free_buff_size = sizeof(send_data->data)  - send_data->total_len;
			int need_size = sizeof(struct jailed_cmd_head) + sizeof(struct jailed_cmd_data) + 16;
			if ((free_buff_size - need_size) < 0) {
				FD_CLR(mirror_err, &rfds);
				continue;
			}
			struct jailed_cmd_head *cmd_head = (struct jailed_cmd_head *)(send_data->data + send_data->total_len);
			struct jailed_cmd_data *cmd_data = (struct jailed_cmd_data *)cmd_head->data;
			cmd_head->magic = MSG_MAGIC;
			cmd_head->type = CMD_MSG_DATA_ERR;
			len = read(mirror_err, cmd_data->data, free_buff_size - sizeof(struct jailed_cmd_head) - sizeof(struct jailed_cmd_data));
			if (len < 0) {
				fprintf(stderr, "read mirror failed, %s\n", strerror(errno));
				FD_CLR(mirror_err, &rfds);
				is_mirror_err_eof = !len;
				continue;
			} 

			cmd_head->data_len = len + sizeof(*cmd_data);
			send_data->total_len += sizeof(*cmd_head) + cmd_head->data_len;

			if (len == 0 ) {
				FD_CLR(mirror_err, &rfds);
				is_mirror_err_eof = !len;
				continue;
			}

			FD_SET(sock, &wfds);
		}

		if (FD_ISSET(sock, &rfds_set)) {
			len = recv(sock, recv_data->data + recv_data->total_len, sizeof(recv_data->data) - recv_data->total_len, MSG_DONTWAIT);	
			if (len < 0) {
				fprintf(stderr, "recv from socket failed, %s\n", strerror(errno));
				return ;
			} else if (len == 0) {
				FD_CLR(sock, &rfds);
				shutdown(sock, SHUT_RD);
				shutdown(mirror, SHUT_WR);
				if (mirror_err > 0) {
					shutdown(mirror_err, SHUT_WR);
				}
				continue;
			}

			recv_data->total_len += len;
			while (1) {
				if (recv_data->total_len >= sizeof(struct jailed_cmd_head)) {
					struct jailed_cmd_head *cmd_head = (struct jailed_cmd_head *)recv_data->data;
					if (cmd_head->magic != MSG_MAGIC || cmd_head->data_len > sizeof(recv_data->data) - sizeof(struct jailed_cmd_head)) {
						fprintf(stderr, "Data invalid, magic=%llX:%llX, len=%d:%d.\n", 
								cmd_head->magic, MSG_MAGIC, cmd_head->data_len, sizeof(recv_data));
						goto out;
					}

					if (recv_data->total_len >= sizeof(struct jailed_cmd_head) + cmd_head->data_len) {
						switch (cmd_head->type) {
						case CMD_MSG_CMD: {
							struct jailed_cmd_cmd *cmd_cmd = (struct jailed_cmd_cmd *)cmd_head->data;
							child_pid = start_process(cmd_cmd, &mirror, &mirror_err);
							FD_SET(mirror, &rfds);
							if (mirror_err > 0) {
								FD_SET(mirror_err, &rfds);
							}
							maxfd = max(maxfd, mirror);
							maxfd = max(maxfd, mirror_err);
							break; }
						case CMD_MSG_DATA_IN: {
							struct jailed_cmd_data *cmd_data = (struct jailed_cmd_data *)cmd_head->data;
							if (mirror < 0) {
								break;
							}
							write(mirror, cmd_data->data, cmd_head->data_len);
							break; }
						case CMD_MSG_DATA_EXIT: {
							goto out;
							break; }
						case CMD_MSG_WINSIZE: {
							struct jailed_cmd_winsize *cmd_winsize = (struct jailed_cmd_winsize *)cmd_head->data;
							ioctl(mirror, TIOCSWINSZ, &cmd_winsize->ws);
							break; }
						default:
							fprintf(stderr, "data type error.\r\n");
							goto out;
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

	if (send_data->total_len > 0) {
		send(sock, send_data->data + send_data->curr_offset, send_data->total_len - send_data->curr_offset, MSG_NOSIGNAL | MSG_DONTWAIT);
		send_data->total_len = 0;
		send_data->curr_offset = 0;
	}

	struct jailed_cmd_head *cmd_head = (struct jailed_cmd_head *)(send_data->data + send_data->total_len);
	struct jailed_cmd_exit *cmd_exit = (struct jailed_cmd_exit *)cmd_head->data;
	cmd_head->magic = MSG_MAGIC;
	cmd_head->type = CMD_MSG_EXIT_CODE;
	cmd_head->data_len = len + sizeof(*cmd_exit);
	send_data->total_len += sizeof(*cmd_head) + cmd_head->data_len;

	if (waitpid(child_pid, &cmd_exit->exit_code, 0) < 0) {
		fprintf(stderr, "wait pid failed.\n");
	}

	send(sock, send_data->data + send_data->curr_offset, send_data->total_len - send_data->curr_offset, MSG_NOSIGNAL | MSG_DONTWAIT);

out:
	if (mirror) {
		close(mirror);
	}

	if (mirror_err > 0) {
		close(mirror_err);
	}

	return;

}

void serve(int sock) 
{
	struct sock_data *send_data ;
	struct sock_data *recv_data ;

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

	signal(SIGCHLD, SIG_DFL);

	server_loop(sock, send_data, recv_data);
	
errout:
	if (recv_data) {
		free(recv_data);
	}

	if (send_data) {
		free(send_data);
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
