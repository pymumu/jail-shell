

JAIL_CMD_DIR=jail-cmd

PAM_JAIL_SHELL_DIR=pam_jail_shell
PAM_JAIL_SHELL_BIN=$(PAM_JAIL_SHELL_DIR)/pam_jail_shell.so

JAIL_SHELL_HOME_DIR=$(PREFIX)/usr/local/jail-shell
JAIL_SHELL_CONF_DIR=$(PREFIX)/etc/jail-shell
JAIL_SHELL_INIT_DIR=$(PREFIX)/etc/init.d
LIB_DIR=$(shell ldd /bin/sh | grep libc | awk '{print $$3}' | xargs dirname)
SECURITY_DIR=$(LIB_DIR)/security

.PHONY: all JAIL_CMD PAM_JAIL_SHELL

all: JAIL_CMD PAM_JAIL_SHELL

JAIL_CMD: 
	$(MAKE) -C $(JAIL_CMD_DIR) $(MAKEFLAGS) all

PAM_JAIL_SHELL: 
	$(MAKE) -C $(PAM_JAIL_SHELL_DIR) $(MAKEFLAGS) all

install: all
	@install -v -d $(JAIL_SHELL_HOME_DIR)/command $(JAIL_SHELL_HOME_DIR)/jail-cmd/ $(JAIL_SHELL_CONF_DIR)/jail-config $(JAIL_SHELL_CONF_DIR) $(JAIL_SHELL_HOME_DIR)/rootfs
	@install -v -d $(JAIL_SHELL_HOME_DIR)/bin 
	@install -v -t $(JAIL_SHELL_HOME_DIR)/jail-cmd/ jail-cmd/jail-cmd jail-cmd/jail-cmdd -m 0755
	@install -v -t $(JAIL_SHELL_HOME_DIR)/bin bin/jail-shell -m 0755
	@install -v -t $(JAIL_SHELL_HOME_DIR)/bin bin/jail-shell-setup -m 0755
	@install -v -t $(SECURITY_DIR) pam_jail_shell/pam_jail_shell.so -m 0755
	@install -v -t /etc/security pam_jail_shell/jail-shell.conf -m 0600
	@ln -v -f -s /usr/local/jail-shell/jail-cmd/jail-cmdd $(PREFIX)/usr/sbin/jail-cmdd 
	@ln -v -f -s /usr/local/jail-shell/bin/jail-shell $(PREFIX)/usr/sbin/jail-shell
	@ln -v -f -s /etc/security/jail-shell.conf $(JAIL_SHELL_CONF_DIR)/jail-shell.conf
	@install -v -t $(JAIL_SHELL_INIT_DIR) etc/init.d/jail-shell -m 0755
	@install -v -t /lib/systemd/system lib/systemd/system/jail-shell.service -m 0644
	@install -v -t /etc/default etc/default/jail-shell -m 0644
	@install -v -t $(JAIL_SHELL_CONF_DIR) etc/jail-shell/cmd_config etc/jail-shell/cmdd_config -m 640
	@install -v -t $(JAIL_SHELL_CONF_DIR)/jail-config etc/jail-shell/jail-config/default-jail.cfg -m 640
	@systemctl daemon-reload
	@systemctl enable jail-shell
	@systemctl start jail-shell

uninstall:
	@systemctl stop jail-shell
	@systemctl disable jail-shell
	$(RM) -r $(JAIL_SHELL_HOME_DIR)
	$(RM) -r $(JAIL_SHELL_CONF_DIR)
	$(RM) $(JAIL_SHELL_INIT_DIR)/jail-shell
	$(RM) $(PREFIX)/usr/sbin/jail-cmdd
	$(RM) $(PREFIX)/usr/sbin/jail-shell
	$(RM) $(SECURITY_DIR)/pam_jail_shell.so
	$(RM) /etc/security/jail-shell.conf
	$(RM) /lib/systemd/system/jail-shell.service
	$(RM) /etc/default/jail-shell
	@systemctl daemon-reload

clean:
	$(MAKE) -C $(JAIL_CMD_DIR) clean
	$(MAKE) -C $(PAM_JAIL_SHELL_DIR) clean
