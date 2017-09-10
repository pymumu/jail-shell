/*
 * Copyright (C) 2017 Ruilin Peng (Nick) <pymumu@gmail.com>
 */

#define _GNU_SOURCE
#include <syslog.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sched.h>
#include <signal.h>
#include <sched.h>
#include <sys/mount.h>
#include <linux/fs.h>
#include <linux/capability.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h> 


#define  PAM_SM_SESSION
#include <security/pam_modules.h>
#include <sys/prctl.h>

#define MAX_GROUP_NUM  32

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#define JAIL_CONF_PATH "/etc/security/jailed-shell.conf"
#define NS_PID_FILE_PATH "/var/run/jailed-shell-ns-%s.pid"
#define JAIL_VAR_DIR "/var/run/jailed-shell"
#define JAIL_JSID_FILE "/var/run/jailed-shell/jsid-%s"

#define TMP_BUFF_LEN_32   32
#define MAX_LINE_LEN      4096
#define MAX_USER_INFO_LEN 4096
#define MAX_FIELD_LEN     1024
#define JAIL_HOME_CONFIG  "JAIL_HOME"
#define JAIL_KEY          "JSID"

extern char *program_invocation_name;

struct user_jail_struct {
	char name[MAX_FIELD_LEN];
	char jail[MAX_FIELD_LEN];
	int pid_namespace;
};

struct user_jail_struct user_jail[MAX_USER_INFO_LEN];
int user_jail_number;
char jail_home[MAX_LINE_LEN];

struct cap_drop_struct {
	char *capname;
	unsigned int cap;
	int isdrop;
};

/*  for cap details, please read (man capabilities) */
struct cap_drop_struct cap_drop[] = 
{
	{"CAP_AUDIT_CONTROL",    CAP_AUDIT_CONTROL,    1},
#ifdef CAP_AUDIT_READ
	{"CAP_AUDIT_READ",       CAP_AUDIT_READ,       1},
#endif
	{"CAP_AUDIT_WRITE",      CAP_AUDIT_WRITE,      1},
#ifdef CAP_BLOCK_SUSPEND
	{"CAP_BLOCK_SUSPEND",    CAP_BLOCK_SUSPEND,    1},
#endif	
	{"CAP_CHOWN",            CAP_CHOWN,            0},
	{"CAP_DAC_OVERRIDE",     CAP_DAC_OVERRIDE,     1},
	{"CAP_DAC_READ_SEARCH",  CAP_DAC_READ_SEARCH,  1},
	{"CAP_FOWNER",           CAP_FOWNER,           1},
	{"CAP_FSETID",           CAP_FSETID,           1},
	{"CAP_IPC_LOCK",         CAP_IPC_LOCK,         0},
	{"CAP_IPC_OWNER",        CAP_IPC_OWNER,        1},
	{"CAP_KILL",             CAP_KILL,             1},
	{"CAP_LEASE",            CAP_LEASE,            0},
	{"CAP_LINUX_IMMUTABLE",  CAP_LINUX_IMMUTABLE,  0},
	{"CAP_MAC_ADMIN",        CAP_MAC_ADMIN,        0},
	{"CAP_MAC_OVERRIDE",     CAP_MAC_OVERRIDE,     0},
	{"CAP_MKNOD",            CAP_MKNOD,            1},
	{"CAP_NET_ADMIN",        CAP_NET_ADMIN,        1},
	{"CAP_NET_BIND_SERVICE", CAP_NET_BIND_SERVICE, 1},
	{"CAP_NET_BROADCAST",    CAP_NET_BROADCAST,    0},
	{"CAP_NET_RAW",          CAP_NET_RAW,          1},
	{"CAP_SETGID",           CAP_SETGID,           0},
	{"CAP_SETFCAP",          CAP_SETFCAP,          1},
	{"CAP_SETPCAP",          CAP_SETPCAP,          1},
	{"CAP_SETUID",           CAP_SETUID,           1},
	{"CAP_SYS_ADMIN",        CAP_SYS_ADMIN,        1},
	{"CAP_SYS_BOOT",         CAP_SYS_BOOT,         1},
	{"CAP_SYS_CHROOT",       CAP_SYS_CHROOT,       1},
	{"CAP_SYS_MODULE",       CAP_SYS_MODULE,       1},
	{"CAP_SYS_NICE",         CAP_SYS_NICE,         1},
	{"CAP_SYS_PACCT",        CAP_SYS_PACCT,        0},
	{"CAP_SYS_PTRACE",       CAP_SYS_PTRACE,       1},
	{"CAP_SYS_RAWIO",        CAP_SYS_RAWIO,        1},
	{"CAP_SYS_RESOURCE",     CAP_SYS_RESOURCE,     1},
	{"CAP_SYS_TIME",         CAP_SYS_TIME,         1},
	{"CAP_SYS_TTY_CONFIG",   CAP_SYS_TTY_CONFIG,   0},
#ifdef CAP_SYSLOG
	{"CAP_SYSLOG",           CAP_SYSLOG,           0},
#endif
#ifdef CAP_WAKE_ALARM
	{"CAP_WAKE_ALARM",       CAP_WAKE_ALARM,       0},
#endif
};

int cap_drop_size = sizeof(cap_drop) / sizeof(struct cap_drop_struct);

void pam_log(const char *format, ...) 
{
	va_list args;

	va_start(args, format);
	vprintf(format, args);
	va_end(args);
}

unsigned long get_rnd_number(void) 
{
	int rnd_fd = -1;
	unsigned long rnd_num = 0;

	rnd_fd = open("/dev/urandom", O_RDONLY);
	if (rnd_fd < 0) {
		goto errout;
	}

	if (read(rnd_fd, &rnd_num, sizeof(rnd_num)) != sizeof(rnd_num)) {
		goto errout;
	}

	close(rnd_fd);

	return rnd_num;
errout:
	if (rnd_fd > 0) {
		close(rnd_fd);
	}
	return -1;
}

int only_one_process(const char *proc_dir)
{
	DIR *dir;
	struct dirent *dent;
	int proc_num = 0;
	char comm_file[PATH_MAX];
	int is_one_process = 1;

	dir = opendir(proc_dir);
	if (dir == NULL) {
		return -1;
	}	

	while((dent = readdir(dir)) != NULL) {
		if (dent->d_type != DT_DIR) {
			continue;
		}

		snprintf(comm_file, PATH_MAX, "%s/%s/comm", proc_dir, dent->d_name);
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

int load_config(void)
{
	FILE *fp;
	char line[MAX_LINE_LEN];
	char filed1[MAX_FIELD_LEN];
	char filed2[MAX_FIELD_LEN];
	char filed3[MAX_FIELD_LEN];
	int filedNum = 0;

	fp = fopen(JAIL_CONF_PATH, "r");
	if (fp == NULL) {
		return 1;
	}

	while (fgets(line, MAX_LINE_LEN, fp)) {
		filedNum = sscanf(line, "%1024s %1024s %1024s", filed1, filed2, filed3);
		if (filedNum < 0) {
			continue;
		}

		if (filedNum == 2) {
			if (strncmp(filed1, JAIL_HOME_CONFIG, sizeof(filed1) != 0)) {
				continue;
			}
			strncpy(jail_home, filed2, MAX_FIELD_LEN);
		} else if (filedNum == 3) {
			struct user_jail_struct *info;
			int value;
			if (filed1[0] == '#') {
				continue;
			}
			info = &user_jail[user_jail_number];
			strncpy(info->name, filed1, MAX_FIELD_LEN);
			strncpy(info->jail, filed2, MAX_FIELD_LEN);
			value = atoi(filed3);
			if (value) {
				info->pid_namespace = 1;
			} else {
				info->pid_namespace = 0;
			}
			user_jail_number++;
		}
	}

	fclose(fp);
	return 0;
}

struct user_jail_struct *get_user_jail(pam_handle_t *pamh) 
{
	struct passwd *pwd;
	struct group *gr;
	const char *user;
	int ret;
	gid_t groups[MAX_GROUP_NUM];
	int ngroups = MAX_GROUP_NUM;
	int i;
	int j;
	struct user_jail_struct *info;

	ret = pam_get_user(pamh, &user, NULL);
	if (ret != PAM_SUCCESS) {
		return NULL;
	}

	for (i = 0; i < user_jail_number; i++) {
		info = &user_jail[i];
		if (strncmp(user, info->name, MAX_FIELD_LEN) != 0) {
			continue;
		}

		return info;
	}

	pwd = getpwnam(user);
	if (pwd == NULL) {
		return NULL;
	}

	if (getgrouplist(user, pwd->pw_gid, groups, &ngroups) < 0) {
		return NULL;
	}

	for (i = 0; i < ngroups; i++) {
		gr = getgrgid(groups[i]);
		if (gr == NULL) {
			continue;
		}

		for (j = 0; j < user_jail_number; j++) {
			info = &user_jail[j];
			if (info->name[0] != '@') {
				continue;
			}

			if (strncmp(gr->gr_name, info->name + 1, MAX_FIELD_LEN) != 0) {
				continue;
			}

			return info;
		}
	}

	return NULL;
}

int do_chroot(const char *path)
{
	if (chroot(path) < 0) {
		return -1;
	}

	chdir("/");
	
	return 0;
}

int try_lock_pid(const char *pid_file)
{
	int fd;
	int flags;

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

	return fd;
errout:
	if (fd > 0) {
		close(fd);
	}
	return -1;
}

int mount_proc(const char *root_path)
{
	char proc_path[PATH_MAX];
	char pts_path[PATH_MAX];
	char check_file[PATH_MAX];
	struct stat buf;

	snprintf(proc_path, PATH_MAX, "%s/proc", root_path);
	snprintf(pts_path, PATH_MAX, "%s/dev/pts", root_path);

	mkdir(proc_path, 0555);
	mkdir(pts_path, 0755);

	mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL);
	mount("none", "/proc", NULL, MS_REC|MS_PRIVATE, NULL);

	snprintf(check_file, PATH_MAX, "%s/ptmx", pts_path);
	if (lstat(check_file, &buf) != 0) {
		if (mount("devpts", pts_path, "devpts",  MS_NOSUID|MS_NOEXEC, NULL) < 0) {
			return 1;
		}
	}

	/*
	if (do_chroot(chroot_path) < 0) {

		exit(0);
	}
	*/
	snprintf(check_file, PATH_MAX, "%s/uptime", proc_path);
	if (lstat(check_file, &buf) != 0) {
		if (mount("proc", proc_path, "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL) < 0) {
			return 1;
		}
	}

	return 0;
}

void set_process_name(const char *user)
{
	char prog_name[TMP_BUFF_LEN_32];
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

	/*  set comm to init */
	snprintf(prog_name, TMP_BUFF_LEN_32, "init");
	prctl(PR_SET_NAME, prog_name, NULL, NULL, NULL); 

	/*  set cmdline to init [user] */
	snprintf(program_invocation_name,  TMP_BUFF_LEN_32, "init [%s]", user);
}

void jail_init(struct user_jail_struct *info, const char *user, char *pid_file, const char *chroot_path)
{
	int wstat;
	int i = 0;
	int fd;
	int sleep_cnt = 0;
	int last_proccess = 0;
	char proc_path[PATH_MAX];
	int pid_wait;

	snprintf(proc_path, PATH_MAX, "%s/proc", chroot_path);

	/*  remount proc directory */
	if (mount_proc(chroot_path) != 0) {
		goto out;
	}

	fd = open("/dev/null", O_RDWR);
	close(0);
	close(1);
	close(2);
	if (fd > 0 ) {
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
		close(fd);
	}

	for (i = 3; i < 1024; i++) {
		close(i);
	}

	set_process_name(user);

	fd = try_lock_pid(pid_file);
	if (fd < 0) {
		goto out;
	}


	/*  wait until all process exit, except jail_init process. */
	while ((pid_wait = waitpid(-1, &wstat, 0)) > 0 || last_proccess == 0) {
		if (pid_wait > 0) {
			continue;
		}

		sleep_cnt++;
		sleep(1);

		if (sleep_cnt % 15 == 0) {
			sleep_cnt = 0;
			last_proccess = only_one_process(proc_path);
		}
	}

	unlink(pid_file);
out:
	_exit(0);
}

int create_jail_ns(struct user_jail_struct *info, const char *user, char *pid_file, const char *chroot_path)
{
	int unshare_err;
	int pid;
	int fd = -1;
	char buff[TMP_BUFF_LEN_32];

	unshare_err = unshare(CLONE_NEWPID | CLONE_NEWNS);
	if (unshare_err) {
		/*  NOT support */
		if (errno == EINVAL) {
			return mount_proc(chroot_path);
		}	
		return 1;
	}

	pid = fork();
	if (pid < 0) {
		return 1;
	} else if (pid == 0) {
		jail_init(info, user, pid_file, chroot_path);
	}

	fd = open(pid_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		goto errout;
	}

	ftruncate(fd, 0);

	snprintf(buff, TMP_BUFF_LEN_32, "%d\n", pid);
	if (write(fd, buff, strnlen(buff, TMP_BUFF_LEN_32)) < 0) {
		goto errout;
	}

	close(fd);
	return 0;

errout:
	kill(pid, SIGKILL);
	close(fd);
	return 1;
}

int enter_ns(int pid, char *ns_name, int flag) 
{
	char ns_file[MAX_LINE_LEN];
	int fd = 0;
	snprintf(ns_file, MAX_LINE_LEN, "/proc/%d/ns/%s", pid, ns_name);

	fd = open(ns_file, O_RDONLY);
	if (fd < 0) {
		return 1;
	}

	if (setns(fd, flag) != 0) {
		close(fd);
		return 1;
	}

	close(fd);

	return 0;
}

int enter_jail_ns(struct user_jail_struct *info, const char *user, char *pid_file, const char *chroot_path)
{
	char buff[TMP_BUFF_LEN_32];
	int fd = -1;
	int ret = 1;
	int ns_pid = 0;

	fd = open(pid_file, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT) {
			return 0;
		}
		return 1;
	}

	/*  read jail init process pid */
	if (read(fd, buff, sizeof(buff)) < 0) {
		ret = 1;
		goto out;
	}

	ns_pid = atoi(buff);
	if (ns_pid <= 0) {
		ret = 1;
		goto out;
	}

	ns_pid = atoi(buff);
	if (ns_pid <= 0) {
		ret = 1;
		goto out;
	}

	if (enter_ns(ns_pid, "pid", CLONE_NEWPID) != 0) {
		ret = 1;
		goto out;
	}

	if (enter_ns(ns_pid, "mnt", CLONE_NEWNS) != 0) {
		ret = 1;
		goto out;
	}

	ret = 0;
out:
	if (fd > 0) {
		close(fd);
	}
	return ret;
}

int set_jsid_env(pam_handle_t *pamh, struct user_jail_struct *info, const char *user)
{
	unsigned long rnd_num = -1;
	char jsid_env[TMP_BUFF_LEN_32];
	char buff[MAX_LINE_LEN];
	char jsid_file_path[PATH_MAX];
	char pid_file[MAX_LINE_LEN];
	int fd = -1;
	int jsid_fd = -1;
	int create_gid = 0;
	int ret;

	mkdir(JAIL_VAR_DIR, 0700);
	
	snprintf(pid_file, MAX_LINE_LEN, NS_PID_FILE_PATH, user);
	snprintf(jsid_file_path, PATH_MAX, JAIL_JSID_FILE, user);

	fd = try_lock_pid(pid_file);
	jsid_fd = open(jsid_file_path, O_RDONLY);
	if (jsid_fd < 0) {
		create_gid = 1;
	} else {
		if (fd > 0) {
			create_gid = 1;
			close(jsid_fd);
			jsid_fd = -1;
		} else {
			create_gid = 0;
		}
	}

	if (create_gid) {
		jsid_fd = open(jsid_file_path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
		if (jsid_fd < 0) {
			ret = 1;
			goto out;
		}

		rnd_num = get_rnd_number();
		if (rnd_num == -1) {
			ret = 1;
			goto out;
		}

		ftruncate(jsid_fd, 0);

		snprintf(buff, MAX_LINE_LEN, "%lu\n", rnd_num);
		if (write(jsid_fd, buff, strnlen(buff, MAX_LINE_LEN)) < 0) {
			ret = 1;
			goto out;
		}

		snprintf(buff, MAX_LINE_LEN, "%s\n", user);
		if (write(jsid_fd, buff, strnlen(buff, MAX_LINE_LEN)) < 0) {
			ret = 1;
			goto out;
		}

		snprintf(buff, MAX_LINE_LEN, "%s\n", info->jail);
		if (write(jsid_fd, buff, strnlen(buff, MAX_LINE_LEN)) < 0) {
			ret = 1;
			goto out;
		}

		snprintf(jsid_env, TMP_BUFF_LEN_32, "%s=%lu", JAIL_KEY, rnd_num);	
	} else {
		char *line_end;
		int len = read(jsid_fd, buff, MAX_LINE_LEN - 1);
		if ( len < 0) {
			ret = 1;
			goto out;
		}
		buff[len] = 0;

		line_end = index(buff, '\n');
		if (line_end == NULL) {
			buff[line_end - buff] = 0;
		}

		snprintf(jsid_env, TMP_BUFF_LEN_32, "%s=%s", JAIL_KEY, buff);
	}

	if (pam_putenv(pamh, jsid_env) != PAM_SUCCESS) {
		return PAM_SERVICE_ERR;
	}

	ret = 0;
out:
	if (jsid_fd> 0) {
		close(jsid_fd);
	}

	if (fd > 0) {
		close(fd);
	}

	return ret;
}

int wait_proc_mounted(const char *root_path) 
{
	char proc_uname_path[PATH_MAX];
	int count;

	snprintf(proc_uname_path, PATH_MAX, "%s/proc/uptime", root_path);

	while (access(proc_uname_path, F_OK) < 0) {
		usleep(100000);
		count++;
		/* wait for 5 seconds */
		if (count > 10 * 5) {
			return 1;
		}
	}

	return 0;
}

int unshare_pid(struct user_jail_struct *info, const char *user, const char *chroot_path) 
{
	char pid_file[MAX_LINE_LEN];
	int fd;

	snprintf(pid_file, MAX_LINE_LEN, NS_PID_FILE_PATH, user);
	fd = try_lock_pid(pid_file);
	if ( fd > 0) {
		close(fd);
		if (create_jail_ns(info, user, pid_file, chroot_path) != 0) {
			return 1;
		}
	} else {
		if (enter_jail_ns(info, user, pid_file, chroot_path) != 0) {
			return 1;
		}
	}

	/*  from mount success */
	if (wait_proc_mounted(chroot_path) != 0) {
		return 1;
	}

	return 0;
}

int drop_cap(void)
{
	int i;

	for (i = 0; i < cap_drop_size; i++) {
		if (cap_drop[i].isdrop == 0) {
			continue;
		}

		if (prctl(PR_CAPBSET_DROP, cap_drop[i].cap, 0, 0) < 0) {
			pam_log("Drop %s failed, errno %s\n", cap_drop[i].capname, strerror(errno));
			continue;
		}

	}
	return 0;
}

int start_jail(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	struct user_jail_struct *info;
	char jail_path[MAX_LINE_LEN];

	const char *user;

	if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) {
		return PAM_USER_UNKNOWN;
	}

	if (load_config()) {
		return PAM_SUCCESS;
	}

	info = get_user_jail(pamh);
	if (info == NULL) {
		return PAM_SUCCESS;
	}

	if (set_jsid_env(pamh, info, user) != 0) {
		return PAM_SERVICE_ERR;
	}

	snprintf(jail_path, MAX_LINE_LEN, "%s/%s", jail_home, info->jail);
	if (unshare_pid(info, user, jail_path) < 0) {
		return PAM_SERVICE_ERR;
	}

	if (do_chroot(jail_path) < 0) {
		return PAM_SERVICE_ERR;
	}

	if (drop_cap() != 0) {
		return PAM_SERVICE_ERR;
	}

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	if (start_jail(pamh, flags, argc, argv) != PAM_SUCCESS) {
		return PAM_USER_UNKNOWN;
	}

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	return PAM_SERVICE_ERR;
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_jailed_shell");
#endif
