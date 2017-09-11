
PAM_JAIL_SHELL_OBJS=pam_jail_shell.o
PAM_JAIL_SHELL=pam_jail_shell.so

CFLAGS +=-g -fPIC -Wall -Wall -Wstrict-prototypes -fno-omit-frame-pointer -Wstrict-aliasing 
CXXFLAGS +=-Wall -fno-omit-frame-pointer -Wstrict-aliasing

.PHONY: all 

all: $(PAM_JAIL_SHELL) 

$(PAM_JAIL_SHELL) : $(PAM_JAIL_SHELL_OBJS)
	$(CC) $(CFLAGS) $^ -shared -o $@


clean:
	$(RM) $(PAM_JAIL_SHELL) $(PAM_JAIL_SHELL_OBJS) 


