
PAM_JAIL_SHELL_OBJS=pam_jail_shell.o
PAM_JAIL_SHELL=pam_jail_shell.so

PAM_JAIL_INIT_OBJS=jail_init.o
PAM_JAIL_INIT=jail-init

CFLAGS +=-g -O2 -fPIC -Wall -Wall -Wstrict-prototypes -fno-omit-frame-pointer -Wstrict-aliasing 
CXXFLAGS +=-Wall -fno-omit-frame-pointer -Wstrict-aliasing

.PHONY: all 

all: $(PAM_JAIL_SHELL) $(PAM_JAIL_INIT)

$(PAM_JAIL_SHELL) : $(PAM_JAIL_SHELL_OBJS)
	$(CC) $(CFLAGS) $^ -shared -o $@

$(PAM_JAIL_INIT): $(PAM_JAIL_INIT_OBJS)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	$(RM) $(PAM_JAIL_SHELL) $(PAM_JAIL_SHELL_OBJS) $(PAM_JAIL_INIT) $(PAM_JAIL_INIT_OBJS) 


