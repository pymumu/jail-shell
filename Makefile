

JAILED_CMD_DIR=jailed-cmd
JAILED_CMD_BIN=$(JAILED_CMD_DIR)/jailed-cmd
JAILEDD_CMD_BIN=$(JAILED_CMD_DIR)/jailed-cmdd

PAM_JAILED_SHELL_DIR=pam_jailed_shell
PAM_JAILED_SHELL_BIN=$(PAM_JAILED_SHELL_DIR)/pam_jailed_shell.so

JAILED_HOME_DIR=$(PREFIX)/usr/local/jailed-shell
JAILED_CONF_DIR=$(PREFIX)/etc/jailed-shell
JAILED_INIT_DIR=$(PREFIX)/etc/init.d
LIB_DIR=$(shell ldd /bin/sh | grep libc | awk '{print $$3}' | xargs dirname)
SECURITY_DIR=$(LIB_DIR)/security

.PHONY: all JAILED_CMD PAM_JAILED_SHELL

all: JAILED_CMD PAM_JAILED_SHELL

JAILED_CMD: 
	$(MAKE) -C $(JAILED_CMD_DIR) $(MAKEFLAGS) all

PAM_JAILED_SHELL: 
	$(MAKE) -C $(PAM_JAILED_SHELL_DIR) $(MAKEFLAGS) all

install: all
	@install -v -d $(JAILED_HOME_DIR)/command $(JAILED_HOME_DIR)/jailed-cmd/ $(JAILED_CONF_DIR)/jail-config $(JAILED_CONF_DIR) $(JAILED_HOME_DIR)/rootfs
	@install -v -d $(JAILED_HOME_DIR)/bin 
	@install -v -t $(JAILED_HOME_DIR)/jailed-cmd/ jailed-cmd/jailed-cmd jailed-cmd/jailed-cmdd -m 0755
	@install -v -t $(JAILED_HOME_DIR)/bin bin/jailed-shell -m 0755
	@install -v -t $(JAILED_HOME_DIR)/bin bin/jailed-shell-setup -m 0755
	@install -v -t $(SECURITY_DIR) pam_jailed_shell/pam_jailed_shell.so -m 0755
	@install -v -t /etc/security pam_jailed_shell/jailed-shell.conf -m 0600
	@ln -v -f -s /usr/local/jailed-shell/jailed-cmd/jailed-cmdd $(PREFIX)/usr/sbin/jailed-cmdd 
	@ln -v -f -s /usr/local/jailed-shell/bin/jailed-shell $(PREFIX)/usr/sbin/jailed-shell
	@ln -v -f -s /etc/security/jailed-shell.conf $(JAILED_CONF_DIR)/jailed-shell.conf
	@install -v -t $(JAILED_INIT_DIR) etc/init.d/jailed-shell -m 0755
	@install -v -t $(JAILED_CONF_DIR) etc/jailed-shell/cmd_config etc/jailed-shell/cmdd_config -m 640
	@install -v -t $(JAILED_CONF_DIR)/jail-config etc/jailed-shell/jail-config/default-jail.cfg -m 640

uninstall:
	$(RM) -r $(JAILED_HOME_DIR)
	$(RM) -r $(JAILED_CONF_DIR)
	$(RM) $(JAILED_INIT_DIR)/jailed-shell
	$(RM) $(PREFIX)/usr/sbin/jailed-cmdd
	$(RM) $(PREFIX)/usr/sbin/jailed-shell
	$(RM) $(SECURITY_DIR)/pam_jailed_shell.so
	$(RM) /etc/security/jailed-shell.conf

clean:
	$(MAKE) -C $(JAILED_CMD_DIR) clean
	$(MAKE) -C $(PAM_JAILED_SHELL_DIR) clean
