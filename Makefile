

JAIL_CMD_DIR=jail-cmd

PAM_JAIL_SHELL_DIR=pam_jail_shell
PAM_JAIL_SHELL_BIN=$(PAM_JAIL_SHELL_DIR)/pam_jail_shell.so


.PHONY: all JAIL_CMD PAM_JAIL_SHELL

all: JAIL_CMD PAM_JAIL_SHELL

JAIL_CMD: 
	$(MAKE) -C $(JAIL_CMD_DIR) $(MAKEFLAGS) all

PAM_JAIL_SHELL: 
	$(MAKE) -C $(PAM_JAIL_SHELL_DIR) $(MAKEFLAGS) all

install: all
	@chmod +x install
	@./install -i

uninstall:
	@chmod +x install
	@./install -u

clean:
	$(MAKE) -C $(JAIL_CMD_DIR) clean
	$(MAKE) -C $(PAM_JAIL_SHELL_DIR) clean
