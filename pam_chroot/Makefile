# $Id: Makefile,v 1.2 2007/09/30 18:05:47 schmolli Exp $

CC = gcc

# if you are not using gmake, you may need to convert the ":=" variables into
# "=" variables.  you cannot have recursive definitions if you do that.
CFLAGS   := -fPIC -O2 -Wall -Werror -pedantic $(CFLAGS)
CPPFLAGS := -I.
LDFLAGS  := -x --shared $(LDFLAGS)

OUT=pam_chroot.so

all:	$(OUT)

%.so: %.o
	$(LD) $(LDFLAGS) -o $@ $< -lpam

clean:
	rm -f *.o $(OUT)

install:
	install -s -o0 -g0 -m755 $(OUT) /lib/security
