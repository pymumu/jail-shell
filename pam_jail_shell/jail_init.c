/*
 * Copyright (C) 2017 Ruilin Peng (Nick) <pymumu@gmail.com>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h> 
#include <sys/prctl.h>

#define NS_PID_FILE_PATH "/var/run/jail-shell-ns-%s.pid"

#define TMP_BUFF_LEN_32   32
#define MAX_LINE_LEN      4096

int only_one_process(void)
{
	DIR *dir;
	struct dirent *dent;
	int proc_num = 0;
	char comm_file[PATH_MAX];
	int is_one_process = 1;

	dir = opendir("/proc");
	if (dir == NULL) {
		return -1;
	}	

	while((dent = readdir(dir)) != NULL) {
		if (dent->d_type != DT_DIR) {
			continue;
		}

		snprintf(comm_file, PATH_MAX, "/proc/%s/comm", dent->d_name);
		if (access(comm_file, F_OK) != 0) {
			continue;
		}
		
		proc_num++;
		if (proc_num > 1) {
			is_one_process = 0;
			break;
		}
	}

	closedir(dir);

	return is_one_process;
}

void set_process_name(const char *user)
{
	int fd = 0;
	int cmd_len = 0;
	char buff[4096];
	fd = open("/proc/self/cmdline", O_RDONLY);
	if (fd < 0) {
		return;
	}

	/*  get length of cmdline */
	cmd_len = read(fd, buff, 4096);
	if (cmd_len < 0) {
		close(fd);
		return;
	}
	close(fd);

	/*  zero cmdline */
	memset(program_invocation_name, 0, cmd_len);

	/*  set cmdline to init [user] */
	snprintf(program_invocation_name,  TMP_BUFF_LEN_32, "init [%s]", user);
}

int loop(char *user)
{
	int wstat;
	int sleep_cnt = 0;
	int last_proccess = 0;
	int pid_wait;

	set_process_name(user);

	/*  wait until all process exit, except jail_init process. */
	while ((pid_wait = waitpid(-1, &wstat, 0)) > 0 || last_proccess == 0) {
		if (pid_wait > 0) {
			continue;
		}

		sleep_cnt++;
		sleep(1);

		if (sleep_cnt % 30 == 0) {
			sleep_cnt = 0;
			last_proccess = only_one_process();
		}
	}

	return 0;
}

void help(void)
{
	char *help = ""
		"Usage: jail-init [OPTION]...\n"
		"jail init process.\n"
		"  -u            user name.\n"
		"  -l            lock file fd.\n"
		"  -h            help message.\n"
		"\n"
		;
	printf("%s", help);
}

int main(int argc, char *argv[])
{
	int opt;
	char user[MAX_LINE_LEN]={0};
	int lock_fd = -1;
	int flags;

	while ((opt = getopt(argc, argv, "u:l:h")) != -1) {
		switch (opt) {
		case 'u':
			strncpy(user, optarg, MAX_LINE_LEN - 1);
			break;
		case 'l':
			lock_fd = atoi(optarg);
			break;
		case 'h':
			help();
			return 1;
		}
	}

	if (user[0] == 0) {
		help();
		return 1;
	}

	if (lock_fd > 0) {
		flags = fcntl(lock_fd, F_GETFD); 
		if (flags < 0) {
			fprintf(stderr, "Could not get flags for PID file, fd is %d\n", lock_fd);
			return 1;
		}

		flags |= FD_CLOEXEC; 
		if (fcntl(lock_fd, F_SETFD, flags) == -1) {
			fprintf(stderr, "Could not set flags for PID file, fd is %d\n", lock_fd);
			return 1;
		}
	}

	return loop(user);
}
