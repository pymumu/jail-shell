
PAM_JAILED_SHELL_OBJS=pam_jailed_shell.o
PAM_JAILED_SHELL=pam_jailed_shell.so

CFLAGS +=-g  -Wall -Wall -Wstrict-prototypes -fno-omit-frame-pointer -Wstrict-aliasing 
CXXFLAGS +=-Wall -fno-omit-frame-pointer -Wstrict-aliasing

.PHONY: all 

all: $(PAM_JAILED_SHELL) 

$(PAM_JAILED_SHELL) : $(PAM_JAILED_SHELL_OBJS)
	$(CC) $(CFLAGS) $^ -shared -o $@


clean:
	$(RM) $(PAM_JAILED_SHELL) $(PAM_JAILED_SHELL_OBJS) 


