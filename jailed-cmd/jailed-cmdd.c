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

int start_process(struct jailed_cmd_cmd *cmd_cmd, int *mirror_in, int *mirror_out, int *mirror_err)
{
	int argc = cmd_cmd->argc;
	char **argv = malloc(argc * sizeof(char*));
	int i = 0;
	int len = 0;

	for (i = 0; i < cmd_cmd->argc; i++) {
		argv[i] = cmd_cmd->argvs + len;
		len += strlen(cmd_cmd->argvs + len) + 1;
	}

	return 0;
}

void server_loop(int sock, struct sock_data *send_data, struct sock_data *recv_data)
{
	fd_set rfds;
	fd_set rfds_set;
	fd_set wfds;
	fd_set wfds_set;
	int len;
	int retval;
	int mirror_in = -1;
	int mirror_out = -1;
	int mirror_err = -1;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);

	FD_SET(sock, &rfds);
	FD_SET(sock, &wfds);
	
	while (1) {

		rfds_set = rfds;
		wfds_set = wfds;

		retval = select(sock + 1, &rfds_set, &wfds_set, NULL, NULL);
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
				return ;
			} 

			send_data->curr_offset += len;
			
			if (send_data->curr_offset >= send_data->total_len) {
				FD_CLR(sock, &wfds);
				send_data->total_len = 0;
				send_data->curr_offset = 0;
			}
		}

		if (FD_ISSET(0, &rfds_set)) {
        	if (send_data->total_len == 0) {
				struct jailed_cmd_head *cmd_head = (struct jailed_cmd_head *)send_data->data;
				struct jailed_cmd_data *cmd_data = (struct jailed_cmd_data *)cmd_head->data;
				cmd_head->magic = MSG_MAGIC;
				cmd_head->type = CMD_MSG_DATA_IN;
				len = read(0, cmd_data->data, sizeof(send_data->data) - sizeof(*cmd_head) - sizeof(*cmd_data));
				if (len <= 0) {
					FD_CLR(0, &rfds_set);
					return ;
				}


				cmd_head->data_len = len;
				send_data->total_len = sizeof(*cmd_head) + cmd_head->data_len;
				send_data->curr_offset = 0;

				if (isatty(STDIN_FILENO) && len == 1 && send_data->data[0] == '\35') {
					return ;
				}

				FD_SET(sock, &wfds);
			} else {
				usleep(10000);
			}
		}

		if (FD_ISSET(sock, &rfds_set)) {
			len = recv(sock, recv_data->data + recv_data->total_len, sizeof(recv_data->data) - recv_data->total_len, MSG_DONTWAIT);	
			if (len < 0) {
				return ;
			} else if (len == 0) {
				fprintf(stdout, "peer close\r\n");
				return ;
			}

			recv_data->total_len += len;
			if (recv_data->total_len >= sizeof(struct jailed_cmd_head)) {
				struct jailed_cmd_head *cmd_head = (struct jailed_cmd_head *)recv_data->data;
				if (cmd_head->magic != MSG_MAGIC || cmd_head->data_len > sizeof(recv_data->data) - sizeof(struct jailed_cmd_head)) {
					fprintf(stderr, "Data error.\r\n");
					return ;
				}

				if (recv_data->total_len >= sizeof(struct jailed_cmd_head) + cmd_head->data_len) {
					switch (cmd_head->type) {
					case CMD_MSG_CMD:
					{
						struct jailed_cmd_cmd *cmd_cmd = (struct jailed_cmd_cmd *)cmd_head->data;
						start_process(cmd_cmd, &mirror_in, &mirror_out, &mirror_err);
						break;
					}
					case CMD_MSG_DATA_IN:
					{
						struct jailed_cmd_data *cmd_data = (struct jailed_cmd_data *)cmd_head->data;
						write(STDOUT_FILENO, cmd_data->data, cmd_head->data_len);
						break;
					}
					case CMD_MSG_WINSIZE:
					{
						struct jailed_cmd_data *cmd_data = (struct jailed_cmd_data *)cmd_head->data;
						write(STDOUT_FILENO, cmd_data->data, cmd_head->data_len);
						break;
					}
					default:
						fprintf(stderr, "data type error.\r\n");
						return ;
					}

					int cmd_msg_len = sizeof(struct jailed_cmd_head) + cmd_head->data_len;
					if (recv_data->total_len > cmd_msg_len) {
						memmove(recv_data->data, recv_data->data + cmd_msg_len, recv_data->total_len - cmd_msg_len);
					} 

					recv_data->total_len = recv_data->total_len - cmd_msg_len;
					recv_data->curr_offset = 0;


				}
			}
		}
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

	server = socket(PF_INET, SOCK_STREAM, 0);
	if (server < 0) {
		fprintf(stderr, "create socket failed, %s\n", strerror(errno));
		return 1;
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

	return run_server(9999);
}
