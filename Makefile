

JAILED_CMD_DIR=jailed-cmd
JAILED_CMD_BIN=$(JAILED_CMD_DIR)/jailed-cmd
JAILEDD_CMD_BIN=$(JAILED_CMD_DIR)/jailed-cmdd

PAM_CHROOT_DIR=pam_chroot
PAM_CHROOT_BIN=$(PAM_CHROOT_DIR)/pam_chroot.so

JAILED_HOME_DIR=$(PREFIX)/usr/local/jailed-shell
JAILED_CONF_DIR=$(PREFIX)/etc/jailed-shell
JAILED_INIT_DIR=$(PREFIX)/etc/init.d
LIB_DIR=$(shell ldd /bin/sh | grep libc | awk '{print $$3}' | xargs dirname)
SECURITY_DIR=$(LIB_DIR)/security

.PHONY: all JAILED_CMD PAM_CHROOT

all: JAILED_CMD PAM_CHROOT

JAILED_CMD: 
	$(MAKE) -C $(JAILED_CMD_DIR) all

PAM_CHROOT: 
	$(MAKE) -C $(PAM_CHROOT_DIR) all

install: all
	@install -d $(JAILED_HOME_DIR)/command $(JAILED_HOME_DIR)/jailed-cmd/ $(JAILED_CONF_DIR)/jail-config $(JAILED_CONF_DIR) $(JAILED_HOME_DIR)/rootfs
	@install -d $(JAILED_HOME_DIR)/bin 
	@install -t $(JAILED_HOME_DIR)/jailed-cmd/ jailed-cmd/jailed-cmd jailed-cmd/jailed-cmdd -m 0755
	@install -t $(JAILED_HOME_DIR)/bin bin/jailed-shell -m 0755
	@install -t $(JAILED_HOME_DIR)/bin bin/jailed-shell-setup -m 0755
	@install -t $(SECURITY_DIR) pam_chroot/pam_chroot.so -m 0755
	@ln -f -s /usr/local/jailed-shell/jailed-cmd/jailed-cmdd $(PREFIX)/usr/sbin/jailed-cmdd 
	@ln -f -s /usr/local/jailed-shell/bin/jailed-shell $(PREFIX)/usr/sbin/jailed-shell
	@install -t $(JAILED_INIT_DIR) etc/init.d/jailed-shell -m 0755
	@install -t $(JAILED_CONF_DIR) etc/jailed-shell/cmd_config etc/jailed-shell/cmdd_config -m 640
	@install -t $(JAILED_CONF_DIR)/jail-config etc/jailed-shell/jail-config/default-jail.cfg -m 640

uninstall:
	$(RM) -r $(JAILED_HOME_DIR)
	$(RM) -r $(JAILED_CONF_DIR)
	$(RM) $(JAILED_INIT_DIR)/jailed-shell
	$(RM) $(PREFIX)/usr/sbin/jailed-cmdd
	$(RM) $(PREFIX)/usr/sbin/jailed-shell
	$(RM) $(SECURITY_DIR)/pam_chroot.so

clean:
	$(MAKE) -C $(JAILED_CMD_DIR) clean
	$(MAKE) -C $(PAM_CHROOT_DIR) clean
