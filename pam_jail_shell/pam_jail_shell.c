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
#include <sys/syscall.h>

#define  PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <sys/prctl.h>

#define MAX_GROUP_NUM  64

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#define JAIL_CONF_PATH     "/etc/jail-shell/jail-shell.conf"
#define NS_PID_FILE_PATH   "/var/run/jail-shell-ns-%s.pid"
#define JAIL_VAR_DIR       "/var/local/jail-shell"
#define JAIL_VAR_JSID_DIR  "/var/local/jail-shell/jsid"
#define JAIL_JSID_FILE     "/var/local/jail-shell/jsid/jsid-%s"
#define MOUNT_SCRIPT_PATH  "/usr/local/jail-shell/bin/jail-shell-setup"
#define LOGIN_POST_SCRIPT  "/usr/local/jail-shell/bin/jail-shell-post"

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
	int namespace_flag;
};

struct user_jail_struct user_jail[MAX_USER_INFO_LEN];
int user_jail_number;
char jail_home[MAX_LINE_LEN];

struct cap_drop_struct {
	char *capname;
	unsigned int cap;
	int isdrop;
};

int setns(int fd, int nstype) __attribute__((weak));

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

enum {
	FLAG_NEWIPC = 0,
	FLAG_NEWNET,
	FLAG_NEWNS,
	FLAG_NEWPID,
	FLAG_NEWUSER,
	FLAG_NEWUTS,
	FLAG_NONE,
};

char *const namespace_opt[] = {
	[FLAG_NEWIPC]  = "ipc",
	[FLAG_NEWNET]  = "net",
	[FLAG_NEWNS]   = "mnt",
	[FLAG_NEWPID]  = "pid",
	/* [FLAG_NEWUSER] = "user", */
	[FLAG_NEWUTS]  = "uts",
	[FLAG_NONE]    = "none",
	NULL
};

int cap_drop_size = sizeof(cap_drop) / sizeof(struct cap_drop_struct);

pam_handle_t *jail_shell_pamh = NULL;

void pam_log(int priority, const char *format, ...) 
{
	va_list args;

	va_start(args, format);
	if (jail_shell_pamh == NULL) {
		vprintf(format, args);
	} else {
		pam_vsyslog(jail_shell_pamh, priority, format, args);
	}
	va_end(args);
}

int drop_cap(void)
{
	int i;

	for (i = 0; i < cap_drop_size; i++) {
		if (cap_drop[i].isdrop == 0) {
			continue;
		}

		if (prctl(PR_CAPBSET_DROP, cap_drop[i].cap, 0, 0) < 0) {
			//pam_log("Drop %s failed, errno %s\n", cap_drop[i].capname, strerror(errno));
			continue;
		}

	}
	return 0;
}

unsigned long get_rnd_number(void) 
{
	int rnd_fd = -1;
	unsigned long rnd_num = 0;

	rnd_fd = open("/dev/urandom", O_RDONLY);
	if (rnd_fd < 0) {
		pam_log(LOG_ERR, "open /dev/urandom file failed, %s", strerror(errno));
		goto errout;
	}

	if (read(rnd_fd, &rnd_num, sizeof(rnd_num)) != sizeof(rnd_num)) {
		pam_log(LOG_ERR, "read /dev/urandom file failed, %s", strerror(errno));
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

int get_namespace_flag(char *namespace, int max_len) 
{
#ifdef __NR_setns
	int flag = 0;
	char *value;
	char optarg[MAX_FIELD_LEN];
	char *subopts = optarg;

	strncpy(optarg, namespace, max_len);

	while (*subopts != '\0') {
		switch (getsubopt(&subopts, namespace_opt, &value)) {
		case FLAG_NEWIPC:
			flag |= CLONE_NEWIPC;
			break;
		case FLAG_NEWNET:
			flag |= CLONE_NEWNET;
			break;
		case FLAG_NEWNS:
			flag |= CLONE_NEWNS;
			break;
		case FLAG_NEWPID:
			flag |= CLONE_NEWPID;
			break;
		case FLAG_NEWUSER:
			flag |= CLONE_NEWUSER;
			break;
		case FLAG_NEWUTS:
			flag |= CLONE_NEWUTS;
			break;
		case FLAG_NONE:
			return 0;
		default:
			pam_log(LOG_ERR, "namespace option is invalid. %s", namespace);
			return -1;
			break;
		}
	}

	return flag;
#else
	return 0;
#endif
}

int load_config(void)
{
	FILE *fp;
	int ret = 0;
	char line[MAX_LINE_LEN];
	char filed1[MAX_FIELD_LEN];
	char filed2[MAX_FIELD_LEN];
	char filed3[MAX_FIELD_LEN];
	int filedNum = 0;
	int flag = -1;

	fp = fopen(JAIL_CONF_PATH, "r");
	if (fp == NULL) {
		pam_log(LOG_ERR, "open %s file failed, %s", JAIL_CONF_PATH, strerror(errno));
		return -1;
	}

	while (fgets(line, MAX_LINE_LEN, fp)) {
		filedNum = sscanf(line, "%1024s %1024s %1024s", filed1, filed2, filed3);
		if (filedNum < 0) {
			continue;
		}

		if (filedNum == 2) {
			if (strncmp(filed1, JAIL_HOME_CONFIG, sizeof(filed1)) != 0) {
				continue;
			}
			strncpy(jail_home, filed2, MAX_FIELD_LEN);
		} else if (filedNum == 3) {
			struct user_jail_struct *info;
			if (filed1[0] == '#') {
				continue;
			}
			info = &user_jail[user_jail_number];
			strncpy(info->name, filed1, MAX_FIELD_LEN);
			strncpy(info->jail, filed2, MAX_FIELD_LEN);
			flag = get_namespace_flag(filed3, MAX_FIELD_LEN);
			if (flag == -1) {
				ret = 1;
				break;
			}
			info->namespace_flag = flag;
			user_jail_number++;
		}
	}

	fclose(fp);
	return ret;
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
		pam_log(LOG_ERR, "get user passwd failed, user %s, %s", user, strerror(errno));
		return NULL;
	}

	if (getgrouplist(user, pwd->pw_gid, groups, &ngroups) < 0) {
		pam_log(LOG_ERR, "get group list for user %s failed, %s", user, strerror(errno));
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
		pam_log(LOG_ERR, "chroot %s failed, %s", path, strerror(errno));
		return -1;
	}

	if (chdir("/") != 0) {
		pam_log(LOG_WARNING, "chdir / failed, %s", path, strerror(errno));	
	}
	
	return 0;
}

int try_lock_pid(const char *pid_file, int no_close_exec)
{
	int fd;
	int flags;

	/*  create pid file, and lock this file */
	fd = open(pid_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		pam_log(LOG_ERR, "create pid file %s failed, %s", pid_file, strerror(errno));
		return -1;
	}

	flags = fcntl(fd, F_GETFD); 
	if (flags < 0) {
		pam_log(LOG_ERR, "get flags for pid file %s failed, %s", pid_file, strerror(errno));
		goto errout;
	}

	if (no_close_exec == 0) {
		flags |= FD_CLOEXEC; 
		if (fcntl(fd, F_SETFD, flags) == -1) {
			pam_log(LOG_ERR, "set flags for pid file %s failed, %s", pid_file, strerror(errno));
			goto errout;
		}
	}

	if (lockf(fd, F_TLOCK, 0) < 0) {
		goto errout;
	}

	return fd;
errout:
	if (fd > 0) {
		close(fd);
	}
	return -1;
}

int mount_from_cfg(struct user_jail_struct *info, const char *user)
{
	char mount_cmd[PATH_MAX];
	int ret;

	/*  do bind directory for user */
	snprintf(mount_cmd, PATH_MAX, "%s --user %s --mount %s", MOUNT_SCRIPT_PATH, user, info->jail);

	ret = system(mount_cmd);
	if (ret != 0) {
		pam_log(LOG_ERR, "run  %s failed, ret = %d", mount_cmd, ret);
		return -1;
	}

	return 0;
}

int do_mount(struct user_jail_struct *info, const char *user, const char *root_path)
{
	char proc_path[PATH_MAX * 2];
	char pts_path[PATH_MAX];
	char check_file[PATH_MAX * 2];
	char mount_cmd[PATH_MAX * 4];
	struct stat buf;
	uid_t ruid;
	uid_t euid;
	uid_t suid;
	int ret = 0;

	snprintf(proc_path, sizeof(proc_path) - 1 , "%s/proc", root_path);
	snprintf(pts_path, sizeof(pts_path) - 1 , "%s/dev/pts", root_path);
	snprintf(check_file, sizeof(check_file) - 1, "%s/ptmx", pts_path);
	/*  if jail is ready mounted, return */
	if (lstat(check_file, &buf) == 0) {
		return 0;
	}

	mkdir(proc_path, 0555);
	mkdir(pts_path, 0755);

	if (getresuid(&ruid, &euid, &suid) != 0) {
		pam_log(LOG_ERR, "get resuid failed, %s", strerror(errno));
		return -1;	
	}

	if (setresuid(0, 0, 0) != 0) {
		pam_log(LOG_ERR, "set resuid failed, %s", strerror(errno));
		return -1;	
	}
#if 0
	mount("none", "/", NULL, MS_REC|MS_PRIVATE, NULL);
	mount("none", "/proc", NULL, MS_REC|MS_PRIVATE, NULL);
#endif

	/*  For selinux call shell command to mount directory */
	/*  mount API may fail, when selinux is enabled. */
	ret = system("mount --make-rprivate /");
	if (ret != 0) {
		pam_log(LOG_ERR, "mount --make-rprivate / failed, ret = %d", mount_cmd, ret);
		goto errout;
	}

	ret = system("mount --make-rprivate /proc");
	if (ret != 0) {
		pam_log(LOG_ERR, "mount --make-rprivate /proc failed, ret = %d", mount_cmd, ret);
		goto errout;
	}

	if (mount_from_cfg(info, user) != 0) {
		goto errout;
	}

	snprintf(mount_cmd, sizeof(mount_cmd) - 1, "mount -t proc proc %s -o nosuid,noexec,nodev,ro", proc_path);
	ret = system(mount_cmd);
	if (ret != 0) {
		pam_log(LOG_ERR, "run %s failed, ret = %d", mount_cmd, ret);
		goto errout;
	}

	snprintf(mount_cmd, sizeof(mount_cmd) - 1, "mount -t devpts devpts %s -o nosuid,noexec", pts_path);
	ret = system(mount_cmd);
	if (ret != 0) {
		pam_log(LOG_ERR, "run %s failed, ret = %d", mount_cmd, ret);
		goto errout;
	}
#if 0
	/*  mount proc for jail */
	if (mount("proc", proc_path, "proc", MS_RDONLY | MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL) < 0) {
		goto errout;
	}

	if (mount("devpts", pts_path, "devpts",  MS_NOSUID|MS_NOEXEC, NULL) < 0) {
		goto errout;
	}
#endif
	if (setresuid(ruid, euid, suid) != 0) {
		pam_log(LOG_ERR, "set suid failed");
		goto errout;
	}

	return 0;
errout:
	if (setresuid(ruid, euid, suid) != 0) {

	}
	return -1;
}

void jail_init(struct user_jail_struct *info, char *user, char *pid_file, char *chroot_path)
{
	int i = 0;
	int fd;
	char *argv[] = {"/usr/bin/init", "-u", user, "-l", 0, 0};
	char str_fd[TMP_BUFF_LEN_32];

	/*  remount proc directory */
	if (do_mount(info, user, chroot_path) != 0) {
		goto out;
	}

	/* start a init process for new namespace */
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

	/*  create pid file and lock */
	fd = try_lock_pid(pid_file, 1);
	if (fd < 0) {
		goto out;
	}

	if (do_chroot(chroot_path) < 0) {
		goto out;
	}

	if (drop_cap() != 0) {
		goto out;
	}

	snprintf(str_fd, TMP_BUFF_LEN_32, "%d", fd);
	argv[4] = str_fd;

	execv(argv[0], argv);
	pam_log(LOG_ERR, "execve %s failed, %s", argv[0], strerror(errno));
out:
	_exit(0);
}

int create_jail_ns(struct user_jail_struct *info, char *user, char *pid_file, char *chroot_path)
{
	int pid;
	int fd = -1;
	char buff[TMP_BUFF_LEN_32];

	if (setns) {
		if (info->namespace_flag == 0) {
			return do_mount(info, user, chroot_path);
		}
		if (unshare(info->namespace_flag) != 0) {
			pam_log(LOG_ERR, "unshare %d failed, user %s, %s", info->namespace_flag, user, strerror(errno));
			return -1;
		}
	} else {
		/*  NOT support */
		return do_mount(info, user, chroot_path);
	}

	pid = fork();
	if (pid < 0) {
		pam_log(LOG_ERR, "fork jail-init failed, %s", strerror(errno));
		return -1;
	} else if (pid == 0) {
		/*  start user's init process */
		jail_init(info, user, pid_file, chroot_path);
	}

	fd = open(pid_file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		pam_log(LOG_ERR, "open pid file %s failed, %s", pid_file, strerror(errno));
		goto errout;
	}

	if (ftruncate(fd, 0) != 0) {
		pam_log(LOG_WARNING, "truncate file %s failed, %s", pid_file, strerror(errno));
	}

	/*  write init pid to pid file */
	snprintf(buff, TMP_BUFF_LEN_32, "%d\n", pid);
	if (write(fd, buff, strnlen(buff, TMP_BUFF_LEN_32)) < 0) {
		pam_log(LOG_ERR, "write pid to file failed, %s", strerror(errno));
		goto errout;
	}

	close(fd);
	return 0;

errout:
	if (pid > 0) {
		/*  kill namespace init process */
		kill(pid, SIGKILL);
	}

	if (fd > 0) {
		close(fd);
	}
	return -1;
}

int enter_ns(int pid, char *ns_name, int flag) 
{
#ifdef __NR_setns
	char ns_file[MAX_LINE_LEN];
	int fd = 0;
	snprintf(ns_file, MAX_LINE_LEN, "/proc/%d/ns/%s", pid, ns_name);

	fd = open(ns_file, O_RDONLY);
	if (fd < 0) {
		pam_log(LOG_ERR, "open ns file %s failed, %s", ns_file, strerror(errno));
		return -1;
	}

	if (setns(fd, flag) != 0) {
		pam_log(LOG_ERR, "set ns %s failed, %s", ns_file, strerror(errno));
		close(fd);
		return -1;
	}

	close(fd);

	return 0;
#else
	return -1;
#endif
}

int enter_jail_ns(struct user_jail_struct *info, const char *user, char *pid_file, const char *chroot_path)
{
	char buff[TMP_BUFF_LEN_32];
	int fd = -1;
	int ret = 1;
	int ns_pid = 0;

	/*  read pid from pid file */
	fd = open(pid_file, O_RDONLY);
	if (fd < 0) {
		if (errno == ENOENT) {
			return 0;
		} 
		pam_log(LOG_ERR, "open pid file  %s failed, %s", pid_file, strerror(errno));
		return -1;
	}

	/*  read jail init process pid */
	if (read(fd, buff, sizeof(buff)) < 0) {
		ret = -1;
		pam_log(LOG_ERR, "read pid file %s failed, %s", pid_file, strerror(errno));
		goto out;
	}

	ns_pid = atoi(buff);
	if (ns_pid <= 0) {
		ret = -1;
		pam_log(LOG_ERR, "get pid %s from %s failed.", buff, pid_file);
		goto out;
	}

#ifdef __NR_setns
	/*  enter ipc namespace */
	if (enter_ns(ns_pid, "ipc", CLONE_NEWIPC) != 0) {
		ret = 1;
		goto out;
	}

	/*  enter net namespace */
	if (enter_ns(ns_pid, "net", CLONE_NEWNET) != 0) {
		ret = 1;
		goto out;
	}

	/*  enter mnt namespace */
	if (enter_ns(ns_pid, "mnt", CLONE_NEWNS) != 0) {
		ret = 1;
		goto out;
	}

	/*  enter pid namespace */
	if (enter_ns(ns_pid, "pid", CLONE_NEWPID) != 0) {
		ret = 1;
		goto out;
	}

	/*  enter user namespace */
	/* TODO
	 * currently return EINVAL
	if (enter_ns(ns_pid, "user", CLONE_NEWUSER) != 0) {
		ret = 1;
		goto out;
	}
	*/ 

	/*  enter uts namespace */
	if (enter_ns(ns_pid, "uts", CLONE_NEWUTS) != 0) {
		ret = 1;
		goto out;
	}

	ret = 0;
#else
	ret = -1;
#endif
out:
	if (fd > 0) {
		close(fd);
	}
	return ret;
}

int set_jsid_env(pam_handle_t *pamh, struct user_jail_struct *info, const char *user)
{
	unsigned long rnd_num = -1;
	char jsid_env[PATH_MAX * 2];
	char buff[MAX_LINE_LEN];
	char jsid_file_path[PATH_MAX];
	char pid_file[MAX_LINE_LEN];
	int fd = -1;
	int jsid_fd = -1;
	int create_jid = 0;
	int ret;

	mkdir(JAIL_VAR_DIR, 0755);
	mkdir(JAIL_VAR_JSID_DIR, 0700);
	
	snprintf(pid_file, MAX_LINE_LEN, NS_PID_FILE_PATH, user);
	snprintf(jsid_file_path, PATH_MAX, JAIL_JSID_FILE, user);

	fd = try_lock_pid(pid_file, 0);
	jsid_fd = open(jsid_file_path, O_RDONLY);
	if (jsid_fd < 0) {
		/*  if jsid file doesn't exist, just create jsid file. */
		create_jid = 1;
	} else {
		if (fd > 0 && lseek(fd, 0, SEEK_END) > 0) {
			/*  if jsid file exists, and init process is not running, create a new JSID */
			create_jid = 1;
			close(jsid_fd);
			jsid_fd = -1;
		} else {
			/*  if jsid file exist, and pid file is empty, just read JSID in jsid file 
			 *  or user's init process is running, just read JSID in jsid file*/
			create_jid = 0;
		}
	}

	if (create_jid) {
		jsid_fd = open(jsid_file_path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
		if (jsid_fd < 0) {
			ret = -1;
			pam_log(LOG_ERR, "open jsid file  %s failed, %s", jsid_file_path, strerror(errno));
			goto out;
		}

		rnd_num = get_rnd_number();
		if (rnd_num == -1) {
			ret = -1;
			goto out;
		}

		if (ftruncate(jsid_fd, 0) != 0) {
			pam_log(LOG_WARNING, "truncate file %s failed, %s", jsid_file_path, strerror(errno));
		}

		/*  write JSID number */
		snprintf(buff, MAX_LINE_LEN, "%lu\n", rnd_num);
		if (write(jsid_fd, buff, strnlen(buff, MAX_LINE_LEN)) < 0) {
			ret = -1;
			pam_log(LOG_ERR, "write jsid failed, file %s, %s", jsid_file_path, strerror(errno));
			goto out;
		}

		/*  write user name */
		snprintf(buff, MAX_LINE_LEN, "%s\n", user);
		if (write(jsid_fd, buff, strnlen(buff, MAX_LINE_LEN)) < 0) {
			ret = -1;
			pam_log(LOG_ERR, "write user name failed, file %s, %s", jsid_file_path, strerror(errno));
			goto out;
		}

		/*  write jail name */
		snprintf(buff, MAX_LINE_LEN, "%s\n", info->jail);
		if (write(jsid_fd, buff, strnlen(buff, MAX_LINE_LEN)) < 0) {
			ret = -1;
			pam_log(LOG_ERR, "write jail name failed, file %s, %s", jsid_file_path, strerror(errno));
			goto out;
		}

		snprintf(jsid_env, TMP_BUFF_LEN_32, "%s=%lu", JAIL_KEY, rnd_num);	
	} else {
		char *line_end;
		int len = read(jsid_fd, buff, MAX_LINE_LEN - 1);
		if ( len < 0) {
			ret = -1;
			pam_log(LOG_ERR, "read jsid failed, file %s, %s", jsid_file_path, strerror(errno));
			goto out;
		}
		buff[len] = 0;

		line_end = index(buff, '\n');
		if (line_end) {
			buff[line_end - buff] = 0;
		}

		snprintf(jsid_env, sizeof(jsid_env) - 1, "%s=%s", JAIL_KEY, buff);
	}

	/*  set JSID enviroment to shell */
	if (pam_putenv(pamh, jsid_env) != PAM_SUCCESS) {
		pam_log(LOG_ERR, "put env failed, user  %s, %s", user, strerror(errno));
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
	int count = 0;

	snprintf(proc_uname_path, PATH_MAX, "%s/proc/uptime", root_path);

	/* wait for directory mount */
	while (access(proc_uname_path, F_OK) < 0) {
		usleep(100000);
		count++;
		/* wait for 5 seconds */
		if (count > 10 * 5) {
			pam_log(LOG_ERR, "wait for %s mount time out.", proc_uname_path);
			return -1;
		}
	}

	return 0;
}

int unshare_pid(struct user_jail_struct *info, char *user, char *chroot_path) 
{
	char pid_file[MAX_LINE_LEN];
	int fd;

	snprintf(pid_file, MAX_LINE_LEN, NS_PID_FILE_PATH, user);
	fd = try_lock_pid(pid_file, 0);
	if ( fd > 0) {
		close(fd);
		/*  if no user's namespace init process running 
		 *  create new namepace, and start a init process for user.
		 */
		if (create_jail_ns(info, user, pid_file, chroot_path) != 0) {
			return -1;
		}
	} else {
		/*
		 * if user's namepsace init process running
		 * just enter the namepsace of init process  
		 */
		if (enter_jail_ns(info, user, pid_file, chroot_path) != 0) {
			return -1;
		}
	}

	/*  from mount success */
	if (wait_proc_mounted(chroot_path) != 0) {
		return -1;
	}

	return 0;
}

int run_jail_post_script(const char *user, struct user_jail_struct *info)
{
	int ret;
	char post_cmd[PATH_MAX * 2];
	uid_t ruid;
	uid_t euid;
	uid_t suid;

	if (access(LOGIN_POST_SCRIPT, X_OK) != 0) {
		return 0;
	}

	if (getresuid(&ruid, &euid, &suid) != 0) {
		pam_log(LOG_ERR, "get resuid for %s failed, %s", user, strerror(errno));
		return -1;	
	}

	if (setresuid(0, 0, 0) != 0) {
		pam_log(LOG_WARNING, "set resuid for %s failed, %s", user, strerror(errno));
	}

	/* LOGIN_POST_SCRIPT %user% %jail_root_path%*/
	snprintf(post_cmd, sizeof(post_cmd) - 1, "%s %s %s/%s", LOGIN_POST_SCRIPT, user, jail_home, info->jail);
	ret = system(post_cmd);
	
	if (setresuid(ruid, euid, suid) != 0) {
		pam_log(LOG_WARNING, "set resuid for %s failed, %s", user, strerror(errno));
	}

	if (ret != 0) {
		pam_log(LOG_ERR, "run %s failed, ret %d", post_cmd, ret);
		return -1;
	}

	return 0;

}

int start_jail(pam_handle_t *pamh, int flags, int argc, const char *argv[])
{
	struct user_jail_struct *info;
	char jail_path[MAX_LINE_LEN * 2];
	char user[MAX_LINE_LEN];
	const char *user_pam;

	/*  get username from pam */
	if (pam_get_user(pamh, &user_pam, NULL) != PAM_SUCCESS) {
		pam_log(LOG_ERR, "pam get user failed.");
		return PAM_USER_UNKNOWN;
	}
	strncpy(user, user_pam, MAX_LINE_LEN - 1);

	/*  load configuration from jail-shell.conf */
	if (load_config()) {
		return PAM_SUCCESS;
	}

	/* get jail info from user name */
	info = get_user_jail(pamh);
	if (info == NULL) {
		return PAM_SUCCESS;
	}

	/*  set JSID enviroment with a random number 
	 *  if JSID exists, read from existrs and set.
	 */
	if (set_jsid_env(pamh, info, user) != 0) {
		pam_log(LOG_INFO, "set env failed, user %s.", user);
		return PAM_SERVICE_ERR;
	}

	/*
	 * run jail-shell-post script, in order to add user entry in /etc/passwd
	 */
	if (run_jail_post_script(user, info) != 0) {
		pam_log(LOG_ERR, "run jail post script failed, user %s.", user);
		return PAM_SERVICE_ERR;
	}

	snprintf(jail_path, sizeof(jail_path) - 1, "%s/%s", jail_home, info->jail);
	if (unshare_pid(info, user, jail_path) != 0) {
		pam_log(LOG_ERR, "unshared namespace failed, user %s.", user);
		return PAM_SERVICE_ERR;
	}

	/*  chroot to jail directory */
	if (do_chroot(jail_path) < 0) {
		pam_log(LOG_ERR, "chroot failed. user %s", user);
		return PAM_SERVICE_ERR;
	}

	/*  Drop all unnesseary cap */
	if (drop_cap() != 0) {
		pam_log(LOG_ERR, "drop cap failed, user %s.", user);
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
	jail_shell_pamh = pamh;
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
PAM_MODULE_ENTRY("pam_jail_shell");
#endif
