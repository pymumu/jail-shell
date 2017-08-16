
JAILED_COMMON_OBJS=jailed-common.o
JAILED_CMD_OBJS=jailed-cmd.o $(JAILED_COMMON_OBJS)
JAILED_CMDD_OBJS=jailed-cmdd.o $(JAILED_COMMON_OBJS)
JAILED_CMD=jailed-cmd
JAILED_CMDD=jailed-cmdd

CFLAGS +=-g  -Werror -Wall -Wstrict-prototypes -fno-omit-frame-pointer -Wstrict-aliasing 
CXXFLAGS +=-Wall -fno-omit-frame-pointer -Wstrict-aliasing

.PHONY: all 

all: $(JAILED_CMD) $(JAILED_CMDD)

$(JAILED_CMD) : $(JAILED_CMD_OBJS)
	$(CC) $(CFLAGS) $^ -o $@

$(JAILED_CMDD) : $(JAILED_CMDD_OBJS)
	$(CC) $(CFLAGS) $^ -o $@


clean:
	$(RM) $(JAILED_CMD) $(JAILED_CMD_OBJS) $(JAILED_CMDD) $(JAILED_CMDD_OBJS) 


