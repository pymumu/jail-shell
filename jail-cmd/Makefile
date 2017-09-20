
JAIL_COMMON_OBJS=jail-common.o
JAIL_CMD_OBJS=jail-cmd.o $(JAIL_COMMON_OBJS)
JAIL_CMDD_OBJS=jail-cmdd.o $(JAIL_COMMON_OBJS)
JAIL_CMD=jail-cmd
JAIL_CMDD=jail-cmdd
JAIL_CMDD_LIB =  -lutil

CFLAGS +=-g -O2 -Werror -Wall -Wstrict-prototypes -fno-omit-frame-pointer -Wstrict-aliasing 
CXXFLAGS +=-Wall -fno-omit-frame-pointer -Wstrict-aliasing

.PHONY: all 

all: $(JAIL_CMD) $(JAIL_CMDD)

$(JAIL_CMD) : $(JAIL_CMD_OBJS)
	$(CC) $(CFLAGS) $^ -o $@

$(JAIL_CMDD) : $(JAIL_CMDD_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(JAIL_CMDD_LIB)


clean:
	$(RM) $(JAIL_CMD) $(JAIL_CMD_OBJS) $(JAIL_CMDD) $(JAIL_CMDD_OBJS) 


