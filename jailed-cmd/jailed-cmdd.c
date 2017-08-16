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

void serve(int socket)
{


}

int server_loop(int port)
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
		return 1;	
	}

	return server_loop(9999);
}
