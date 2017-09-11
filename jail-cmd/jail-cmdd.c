/*
 * Copyright (C) 2017 Ruilin Peng (Nick) <pymumu@gmail.com>
 */

#include "jail-cmd.h"
#include <pty.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PID_FILE_PATH "/var/run/jail-cmdd.pid"
#define DEFAULT_ROOT_DIR "/usr/local/jail-shell/command"

struct cmdd_context {
	int sock;
	int mirror;
	int mirror_err;
	int maxfd;
	
	fd_set rfds;
	fd_set wfds;

	int isatty;

	int is_sock_eof;
	int is_mirror_eof;
	int is_mirror_err_eof;

	int child_pid;

	struct sock_data send_data;
	struct sock_data recv_data;
	struct sock_data mirror_data;
};


struct cmdd_config {
	int port;
	char rootdir[PATH_MAX];
	int enable_log;
};


struct cmdd_config config = {
	.port = DEFAULT_PORT,
	.rootdir = DEFAULT_ROOT_DIR,
	.enable_log = 1,
};

void help(void)
{
	char *help = ""
		"Usage: jail-cmdd [OPTION]...\n"
		"Start jail cmd proxy server.\n"
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

	/*  create pid file, and lock this file */
	fd = open(pid_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		fprintf(stderr, "create pid file failed, %s", strerror(errno));
		return -1;
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
	return -1;
}

/*  fork process and create socketpair to stdin, stdout, stderr for data writing and reading */
int forksocket(int *mirror, int *mirror_err)
{
	int fd[2];
	int fd_err[2];
	int pid;

	static const int parentsocket = 0;
	static const int childsocket = 1;

	/*  create socketpair for stdin, stdout, stderr */
	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fd) != 0) {
		return -1;
	}

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fd_err) != 0) {
		return -1;
	}

	pid = fork();
	if (pid == 0) {
		close(fd[parentsocket]);
		close(fd_err[parentsocket]);

		/*  close original std fd */
		close(0);
		close(1);
		close(2);

		/*  duplicate socket to std fd */
		dup2(fd[childsocket], 0);
		dup2(fd[childsocket], 1);
		dup2(fd_err[childsocket], 2);

		*mirror = fd[childsocket];
		*mirror_err = fd_err[childsocket];

		return pid;
	} else if (pid > 0) {
		close(fd[childsocket]);
		close(fd_err[childsocket]);
		*mirror = fd[parentsocket];
		*mirror_err = fd_err[parentsocket];
	}

	return pid;
}

int set_uid_gid(struct jail_cmd_cmd *cmd_cmd)
{
	int uid = cmd_cmd->uid;
	int gid = cmd_cmd->gid;
	struct passwd *pwd;

	pwd = getpwuid(uid);
	if (pwd == NULL) {
		fprintf(stderr, "User is invalid.\n");
		goto errout;
	}

	setenv("LOGNAME", pwd->pw_name, 1);
	setenv("USER", pwd->pw_name, 1);
	setenv("USERNAME", pwd->pw_name, 1);
	setenv("HOME", pwd->pw_dir, 1);
	setenv("SHELL", pwd->pw_shell, 1);

	if (setresgid(gid, gid, gid) < 0) {
		goto errout;
	}

	if (initgroups(pwd->pw_name, gid) < 0) {
		goto errout;
	}

	if (setresuid(uid, uid, uid) < 0) {
		goto errout;
	}

	return 0;
errout:
	return 1;

}

int injection_check(int argc, char *argv[])
{
	char *inject_char[] = {";", "|", "`", "$(", "&&", "||", ">", "<"};
	int char_count = sizeof(inject_char) / sizeof(char*);
	int i = 0; 
	int j = 0; 
	for (i = 0; i < argc; i++) {
		for (j = 0; j < char_count; j++) {
			if (strstr(argv[i], inject_char[j])) {
				return 1;
			}
		}
	}

	return 0;
}

void run_process(struct jail_cmd_cmd *cmd_cmd, char *jail_name) 
{
	char cmd_name[PATH_MAX];
	char cmd_path[PATH_MAX];
	char prog[PATH_MAX];
	int len = 0;
	int i = 0;
	int argc = cmd_cmd->argc;
	char *argv[argc + 1];
		
	/*  get args to standard parameter: argc, argv[] */
	for (i = 0; i < cmd_cmd->argc; i++) {
		argv[i] = cmd_cmd->argvs + len;
		len += strlen(cmd_cmd->argvs + len) + 1;
	}
	argv[i] = 0;

	/*  check shell inject characters */
	if (injection_check(argc, argv)) {
		errno = EINVAL;
		goto errout;
	}

	/*  change user id */
	if (set_uid_gid(cmd_cmd)) {
		goto errout;
	}

	snprintf(cmd_name, PATH_MAX, "/%s", argv[0]);
	if (normalize_path(cmd_name) <= 0) {
		goto errout;
	}

	snprintf(cmd_path, PATH_MAX, "%s/%s%s", config.rootdir, jail_name, cmd_name);

	if (chdir("/tmp") < 0) {
		goto errout;
	}

	len = readlink(cmd_path, prog, sizeof(prog));
	if (len < 0) {
		goto errout;
	}
	prog[len] = 0;

	execv(prog, argv);

errout:
	fprintf(stderr, "-sh: %s: %s\n", argv[0], strerror(errno));
}

int get_jail_name(struct jail_cmd_cmd *cmd_cmd, char *out, int out_max_len)
{
	struct passwd *pwd;
	char jsid_file_path[PATH_MAX];
	char buff[MAX_LINE_LEN];
	FILE *fp = NULL;
	int len;

	pwd = getpwuid(cmd_cmd->uid);
	if (pwd == NULL) {
		fprintf(stderr, "User is invalid.\n");
		goto errout;
	}

	snprintf(jsid_file_path, PATH_MAX, JAIL_JSID_FILE, pwd->pw_name);
	fp = fopen(jsid_file_path, "r");
	if (fp == NULL) {
		fprintf(stderr, "open %s failed, %s\n", jsid_file_path, strerror(errno));
		goto errout;
	}

	/*  read GSID */
	if (fgets(buff, sizeof(buff) - 1, fp) == NULL) {
		fprintf(stderr, "read gsid failed, %s\n", strerror(errno));
		goto errout;
	}
	len = strnlen(buff, sizeof(buff) - 1);
	if (buff[len - 1] == '\n') {
		buff[len - 1] = '\0';
	}	

	/*  check GSID */
	if (strncmp(buff, cmd_cmd->jsid, TMP_BUFF_LEN_32) != 0) {
		fprintf(stderr, "gsid not match, %s:%s\n", buff, cmd_cmd->jsid);
		goto errout;
	}

	/*  read user name */
	if (fgets(buff, sizeof(buff) - 1, fp) == NULL) {
		fprintf(stderr, "read gsid failed, %s\n", strerror(errno));
		goto errout;
	}
	len = strnlen(buff, sizeof(buff) - 1);
	if (buff[len - 1] == '\n') {
		buff[len - 1] = '\0';
	}	

	/*  check user name */
	if (strncmp(buff, pwd->pw_name, MAX_LINE_LEN) != 0) {
		fprintf(stderr, "user name not match, %s:%s\n", buff, pwd->pw_name);
		goto errout;
	}
	
	/*  read jail name */	
	if (fgets(out, out_max_len - 1, fp) == NULL) {
		fprintf(stderr, "read gsid failed, %s\n", strerror(errno));
		goto errout;
	}
	len = strnlen(out, out_max_len - 1);
	if (out[len - 1] == '\n') {
		out[len - 1] = '\0';
	}	

	if (strlen(out) <= 0) {
		fprintf(stderr, "jaiel name is invalid, %s", out);
		goto errout;
	}
	
	fclose(fp);
	return 0;
errout:
	if (fp) {
		fclose(fp);
	}
	return -1;
}

int start_process(struct jail_cmd_cmd *cmd_cmd, int *mirror, int *mirror_err)
{
	int pid = -1;
	char jail_name[MAX_LINE_LEN]={0};
	
	if (get_jail_name(cmd_cmd, jail_name, sizeof(jail_name)) != 0) {
		return -1;
	}

	if (cmd_cmd->isatty) {
		/*  if command comes from interactive shell, start a pty term and fork process */
		pid = forkpty(mirror, NULL, NULL, &cmd_cmd->ws);
	} else {
		/*  if command comes from non-interactive shell, make socketpair and fork process */
		pid = forksocket(mirror, mirror_err);
	}

	if (pid < 0) {
		/*  fork failed */
		return -1;
	} else if (pid == 0) {
		close(*mirror);
		if (*mirror_err > 0) {
			close(*mirror_err);
		}
		setenv("TERM", cmd_cmd->term, 1);

		run_process(cmd_cmd, jail_name);
		_exit(1);
	} 

	return pid;
}

int check_args(struct cmdd_context *context, struct jail_cmd_head *cmd_head, struct jail_cmd_cmd *cmd_cmd)
{
	int arg_len;
	int argc = cmd_cmd->argc;
	int arg_count = 0;
	int i;

	if (argc > MAX_ARGS_COUNT) {
		fprintf(stderr, "too many args\n");
		return 1;
	}

	if (cmd_head->data_len > sizeof(context->recv_data.data) - sizeof(*cmd_head)) {
		fprintf(stderr, "cmd length is invalid.\n");
		return 1;
	}

	/*  check arg number is valid. */
	arg_len = cmd_head->data_len - sizeof(*cmd_cmd);
	for (i = 0; i < arg_len; i++) {
		if (cmd_cmd->argvs[i] == 0) {
			arg_count++;
		}
	}

	if (argc != arg_count) {
		fprintf(stderr, "arg number is invalid.\n");
		return 1;
	}

	return 0;
}

CMD_RETURN process_cmd(struct cmdd_context *context, struct jail_cmd_head *cmd_head) 
{
	switch (cmd_head->type) {
	case CMD_MSG_CMD: {
		/*  init cmd message */
		struct jail_cmd_cmd *cmd_cmd = (struct jail_cmd_cmd *)cmd_head->data;

		if (check_args(context, cmd_head, cmd_cmd)) {
			FD_CLR(context->sock, &context->rfds);
			return CMD_RETURN_ERR;
		}

		context->child_pid = start_process(cmd_cmd, &context->mirror, &context->mirror_err);
		if (context->child_pid < 0) {
			FD_CLR(context->sock, &context->rfds);
			return CMD_RETURN_ERR;
		}

		context->isatty = cmd_cmd->isatty;

		FD_SET(context->mirror, &context->rfds);
		if (context->mirror_err > 0) {
			FD_SET(context->mirror_err, &context->rfds);
		}

		context->maxfd = max(context->maxfd, context->mirror);
		context->maxfd = max(context->maxfd, context->mirror_err);
		break; }
	case CMD_MSG_DATA_IN: {
		/*  input message  */
		struct jail_cmd_data *cmd_data = (struct jail_cmd_data *)cmd_head->data;
		if (context->mirror < 0) {
			break;
		}

		/*  if mirror_data is full, stop write to mirror, and stop read data from client socket */
		int mirror_free = sizeof(context->mirror_data.data) - context->mirror_data.total_len;
		if (mirror_free < cmd_head->data_len) {
			FD_CLR(context->sock, &context->rfds);
			return CMD_RETURN_CONT;
		}

		/*  copy read data to mirror_data, and start mirror write event. */
		memcpy(context->mirror_data.data + context->mirror_data.total_len, cmd_data->data, cmd_head->data_len);
		context->mirror_data.total_len += cmd_head->data_len;
		FD_SET(context->mirror, &context->wfds);
		break; }
	case CMD_MSG_DATA_EXIT: {
		/*  exit message  */
		FD_CLR(context->mirror, &context->rfds);
		close(context->mirror);
		context->mirror = -1;
		return CMD_RETURN_EXIT;
		break; }
	case CMD_MSG_WINSIZE: {
		/*  win size change message */
		struct jail_cmd_winsize *cmd_winsize = (struct jail_cmd_winsize *)cmd_head->data;
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

	/*  send data to client */
	len = send(context->sock, 
			context->send_data.data + context->send_data.curr_offset, 
			context->send_data.total_len - context->send_data.curr_offset, MSG_NOSIGNAL | MSG_DONTWAIT);
	if (len < 0) {
		fprintf(stderr, "socket send failed,  %s\n", strerror(errno));
		return CMD_RETURN_ERR;
	} 

	context->send_data.curr_offset += len;
	
	if (context->send_data.curr_offset == context->send_data.total_len) {
		/*  if all data has been sent, stop send event, and reset buffer length info */
		FD_CLR(context->sock, &context->wfds);
		context->send_data.total_len = 0;
		context->send_data.curr_offset = 0;
	}  else if (context->send_data.curr_offset < context->send_data.total_len) {
		/*  exists more data, move data to the beggining of the buffer */
		memmove(context->send_data.data, context->send_data.data + context->send_data.curr_offset, 
				context->send_data.total_len - context->send_data.curr_offset);
		context->send_data.total_len =  context->send_data.total_len - context->send_data.curr_offset;
		context->send_data.curr_offset = 0;
	} else {
		fprintf(stderr, "BUG: internal error, data length mismach\n");
		return CMD_RETURN_ERR;
	}

	/*  Have enough free buff now, wake up mirror stdout, stderr event, and read. */
	if (context->is_mirror_eof == 0) {
		FD_SET(context->mirror, &context->rfds);
	}

	if (context->is_mirror_err_eof == 0) {
		FD_SET(context->mirror_err, &context->rfds);
	}

	return CMD_RETURN_OK;
}

CMD_RETURN process_msg(struct cmdd_context *context) 
{
	struct jail_cmd_head *cmd_head;
	CMD_RETURN retval;

	/*  process data which received from client. */
	while (1) {
		/*  if data is partial, continue recv */
		if (context->recv_data.total_len - context->recv_data.curr_offset < sizeof(struct jail_cmd_head)) {
			break;
		}

		cmd_head = (struct jail_cmd_head *)(context->recv_data.data + context->recv_data.curr_offset);
		if (cmd_head->magic != MSG_MAGIC || cmd_head->data_len > sizeof(context->recv_data.data) - sizeof(struct jail_cmd_head)) {
			/*  if recevied error data, exit. */
			fprintf(stderr, "Data invalid\n");
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

CMD_RETURN recv_sock(struct cmdd_context *context) 
{
	int len;

	/*  recv data from client */
	len = recv(context->sock, context->recv_data.data + context->recv_data.total_len, sizeof(context->recv_data.data) - context->recv_data.total_len, MSG_DONTWAIT);	
	if (len < 0) {
		fprintf(stderr, "recv from socket failed, %s\n", strerror(errno));
		return CMD_RETURN_ERR;
	} else if (len == 0) {
		/*  if peer server closed, then stop recv event. */
		FD_CLR(context->sock, &context->rfds);
		shutdown(context->sock, SHUT_RD);
		context->is_sock_eof = 1;
		/*  wake up mirror write event, write remain data to stdin */
		FD_SET(context->mirror, &context->wfds);
		return CMD_RETURN_OK;
	}

	context->recv_data.total_len += len;

	return process_msg(context);
}

CMD_RETURN read_mirror_err(struct cmdd_context *context) 
{
	int len;
	int need_size;
	int free_buff_size;

	struct jail_cmd_head *cmd_head;
	struct jail_cmd_data *cmd_data;

	free_buff_size = sizeof(context->send_data.data)  - context->send_data.total_len;
	/*  if free space is not enougth, then block reading from stderr */
	need_size = sizeof(struct jail_cmd_head) + sizeof(struct jail_cmd_data) + 16;
	if ((free_buff_size - need_size) < 0) {
		FD_CLR(context->mirror_err, &context->rfds);
		return CMD_RETURN_OK;
	}
	
	cmd_head = (struct jail_cmd_head *)(context->send_data.data + context->send_data.total_len);
	cmd_data = (struct jail_cmd_data *)cmd_head->data;
	cmd_head->magic = MSG_MAGIC;
	cmd_head->type = CMD_MSG_DATA_ERR;
	len = read(context->mirror_err, cmd_data->data, free_buff_size - sizeof(struct jail_cmd_head) - sizeof(struct jail_cmd_data));
	if (len < 0) {
		fprintf(stderr, "read mirror_err failed, %s\n", strerror(errno));
		FD_CLR(context->mirror_err, &context->rfds);
		context->is_mirror_err_eof = 1;
		return CMD_RETURN_OK;
	} else if (len == 0 ) {
		FD_CLR(context->mirror_err, &context->rfds);
		context->is_mirror_err_eof = 1;
		return CMD_RETURN_OK;
	}

	cmd_head->data_len = len + sizeof(*cmd_data);
	context->send_data.total_len += sizeof(*cmd_head) + cmd_head->data_len;

	/*  have read data from stderr, wake up sock, and start send. */
	FD_SET(context->sock, &context->wfds);

	return CMD_RETURN_OK;
}

CMD_RETURN write_mirror(struct cmdd_context *context)
{
	int len;
	CMD_RETURN retval;

	/*  write mirror data to mirror as stdin */
	len = write(context->mirror, context->mirror_data.data + context->mirror_data.curr_offset, context->mirror_data.total_len - context->mirror_data.curr_offset);
	if (len < 0) {
		FD_CLR(context->mirror, &context->wfds);
		if (errno == EPIPE) {
			/* child process may exit, return ok to ensure all 
		 	 * child out data has been sent to client 
		 	 */
			return CMD_RETURN_OK;

		}

		fprintf(stderr, "write mirror failed, %s\n", strerror(errno));
		return CMD_RETURN_ERR;
	}

	context->mirror_data.curr_offset += len;

	if (context->mirror_data.total_len == context->mirror_data.curr_offset) {
		/* if all data has been written to mirror as stin, stop write event, and reset buffer length info */
		FD_CLR(context->mirror, &context->wfds);
		context->mirror_data.total_len = 0;
		context->mirror_data.curr_offset = 0;
	} else if (context->mirror_data.total_len  > context->mirror_data.curr_offset) {
		/*  exists more data, move data to the beggining of the buffer */
		memmove(context->mirror_data.data, context->mirror_data.data + context->mirror_data.curr_offset, context->mirror_data.total_len - context->mirror_data.curr_offset);
		context->mirror_data.total_len -= context->mirror_data.curr_offset;
		context->mirror_data.curr_offset = 0;
	} else  {
		fprintf(stderr, "BUG: internal error, data length mismach.");
		return CMD_MSG_DATA_ERR;
	}

	if (context->is_sock_eof == 0 || context->recv_data.total_len > context->recv_data.curr_offset) {
		/*  Have enough free buff and recv buffer has data, wake up sock for reading. */
		FD_SET(context->sock, &context->rfds);
	}

	/*  process CMD_MSG_DATA_IN message */
	retval = process_msg(context);

	if (context->is_sock_eof == 1 && context->mirror_data.total_len == 0 && context->recv_data.total_len == 0) {
		/*  if sock recv is closed and all data has been sent, then shutdown mirror stdin, notify child process exit. */
		if (context->isatty) {
			/*  interactive shell, just close fd */
			close(context->mirror);
			context->mirror = -1;
			if (context->mirror_err > 0) {
				close(context->mirror_err);
				context->mirror_err = -1;
			}

			return CMD_RETURN_EXIT;
		} else {
			/*  socketpair, do shutdown write */
			shutdown(context->mirror, SHUT_WR);
			if (context->mirror_err > 0) {
				shutdown(context->mirror_err, SHUT_WR);
			}
		}
	}

	return retval;

}

CMD_RETURN read_mirror(struct cmdd_context *context)
{
	struct jail_cmd_head *cmd_head;
	struct jail_cmd_data *cmd_data;

	int len;
	int free_buff_size;
	int need_size;

	free_buff_size = sizeof(context->send_data.data)  - context->send_data.total_len;
	/*  if free space is not enougth, then block reading from stdout */
	need_size = sizeof(struct jail_cmd_head) + sizeof(struct jail_cmd_data) + 16;
	if ((free_buff_size - need_size) < 0) {
		FD_CLR(context->mirror, &context->rfds);
		return CMD_RETURN_OK;
	}
	
	cmd_head = (struct jail_cmd_head *)(context->send_data.data + context->send_data.total_len);
	cmd_data = (struct jail_cmd_data *)cmd_head->data;
	cmd_head->magic = MSG_MAGIC;
	cmd_head->type = CMD_MSG_DATA_OUT;
	len = read(context->mirror, cmd_data->data, free_buff_size - sizeof(struct jail_cmd_head) - sizeof(struct jail_cmd_data));
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
	} else 	if (len == 0 ) {
		/*  end of mirror stdout, stop read stdout.*/
		FD_CLR(context->mirror, &context->rfds);
		context->is_mirror_eof = 1;
		return CMD_RETURN_EXIT;
	}

	cmd_head->data_len = len + sizeof(*cmd_data);
	context->send_data.total_len += sizeof(*cmd_head) + cmd_head->data_len;

	/*  have read data from mirror as stdout, wake up sock, and start send to client. */
	FD_SET(context->sock, &context->wfds);

	return CMD_RETURN_OK;
}

void send_exit_code(struct cmdd_context *context)
{
	int status = 0x100;

	/*  send last remain data to client with block io */
	if (context->send_data.total_len > 0) {
		send(context->sock, context->send_data.data + context->send_data.curr_offset, context->send_data.total_len - context->send_data.curr_offset, MSG_NOSIGNAL);
		context->send_data.total_len = 0;
		context->send_data.curr_offset = 0;
	}

	/* send child process exit code to client. */
	struct jail_cmd_head *cmd_head = (struct jail_cmd_head *)(context->send_data.data + context->send_data.total_len);
	struct jail_cmd_exit *cmd_exit = (struct jail_cmd_exit *)cmd_head->data;
	cmd_head->magic = MSG_MAGIC;
	cmd_head->type = CMD_MSG_EXIT_CODE;
	cmd_head->data_len = sizeof(*cmd_exit);
	context->send_data.total_len += sizeof(*cmd_head) + cmd_head->data_len;

	/*  get child process exit code. */
	if (context->child_pid > 0) {
		if (waitpid(context->child_pid, &status, 0) < 0) {
			fprintf(stderr, "wait pid failed.\n");
		}
	}

	cmd_exit->exit_code = WEXITSTATUS(status);

	send(context->sock, context->send_data.data + context->send_data.curr_offset, context->send_data.total_len - context->send_data.curr_offset, MSG_NOSIGNAL);
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
			/*  recv message from client */
			retval = recv_sock(context);
			if (retval == CMD_RETURN_EXIT) {
				goto out;
			} else if (retval == CMD_RETURN_ERR) {
				goto errout;
			}
		}

		if (FD_ISSET(context->sock, &wfds_set)) {
			/*  send message to client */
			retval = send_sock(context);
			if (retval == CMD_RETURN_EXIT) {
				goto out;
			} else if (retval == CMD_RETURN_ERR) {
				goto errout;
			}
		}
		
		if (FD_ISSET(context->mirror, &wfds_set)) {
			/*  write data to child's stdin */
			retval = write_mirror(context);
			if (retval == CMD_RETURN_EXIT) {
				goto out;
			} else if (retval == CMD_RETURN_ERR) {
				goto errout;
			}
		}

		if (context->mirror_err > 0 && FD_ISSET(context->mirror_err, &rfds_set)) {
			/*  read data from child's stderr */
			retval = read_mirror_err(context);
			if (retval == CMD_RETURN_EXIT) {
				goto out;
			} else if (retval == CMD_RETURN_ERR) {
				goto errout;
			}
		}

		if (FD_ISSET(context->mirror, &rfds_set)) {
			/*  read data from child's stdout */
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

	/*  restore SIGCHLD handle to default*/
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
		clilen = sizeof(client_addr);
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

			/* wait peer recv all data */
			shutdown(sock, SHUT_WR);
			char buf[4096];
			while(recv(sock, buf, sizeof(buf), 0) > 0) {
			}
			shutdown(sock, SHUT_RD);
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

void onexit(void) 
{
	
	unlink(PID_FILE_PATH);	
}

void signal_handler(int sig)
{
	switch(sig) {
	case SIGTERM: 
	case SIGINT:
	case SIGABRT:
	case SIGQUIT:
		onexit();
		_exit(1);
		break;
	}
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

	if (create_pid_file(PID_FILE_PATH) < 0) {
		return 1;	
	}

	atexit(onexit);

	/*  ignore SIGCHLD, child will be recycled automatically */
	signal(SIGCHLD, SIG_IGN);
	signal(SIGPIPE, SIG_IGN);
	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGQUIT, signal_handler);
	signal(SIGABRT, signal_handler);

	return run_server(config.port);
}
