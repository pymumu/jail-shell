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
#include <signal.h>
#include <sched.h>
#include <sys/mount.h>
#include <linux/fs.h>
#include <linux/capability.h>

#define  PAM_SM_SESSION
#include <security/pam_modules.h>
#include <sys/prctl.h>

#define MAX_GROUP_NUM  32

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

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

int load_config(void) 
{
	return PAM_SUCCESS;
}

int unshare_pid(void) 
{
#ifdef CLONE_NEWPID
	int unshare_err = unshare(CLONE_NEWPID | CLONE_NEWNS);
	if (unshare_err) {
		return PAM_SESSION_ERR;
	}

	int pid = fork();
	if (pid == 0) {
		/*  remount proc directory */
		mount("none", "/proc", NULL, MS_REC|MS_PRIVATE, NULL);
		mount("proc", "/proc", "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL);
		/*  send kill to child when parent exit. */
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		/*  wait until parent process exit. */
		select(1, 0, 0, 0, 0);
		exit(0);
	}
#endif
	return PAM_SUCCESS;
}

int do_chroot(void)
{
	return PAM_SUCCESS;	
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
	return PAM_SUCCESS;
}


int get_user(pam_handle_t *pamh) 
{
	struct passwd *pwd;
	struct group *gr;
	const char *user;
	int ret;
	gid_t groups[MAX_GROUP_NUM];
	int ngroups = MAX_GROUP_NUM;

	ret = pam_get_user(pamh, &user, NULL);
	if (ret != PAM_SUCCESS) {
		return PAM_USER_UNKNOWN;
	}

	pwd = getpwnam(user);
	if (pwd == NULL) {
		return PAM_USER_UNKNOWN;
	}

	pam_log("user = %s\n", user);
	if (getgrouplist(user, pwd->pw_gid, groups, &ngroups) < 0) {
		return PAM_USER_UNKNOWN;
	}

	int i;
	for (i = 0; i < ngroups; i++) {
		printf("%d. ", groups[i]);
		gr = getgrgid(groups[i]);
		if (gr) {
			printf("%s", gr->gr_name);
		}
		printf("\n");
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
