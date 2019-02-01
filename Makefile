.PHONY: all install dist clean

PROGRAMS = pfiles plimit
VERSION := $(shell sed -n 's/Version:[[:space:]]*\(.*\)/\1/p' putils.spec)


CC = gcc -std=gnu17
CFLAGS = -O2 -g
DEFINES = -D_GNU_SOURCE -DVERSION=\"$(VERSION)\"
ifeq (yes,$(shell if printf '\043include <dirent.h>\n__auto_type p = scandirat64;'|$(CC) -c -x c $(DEFINES) - -o /dev/null >& /dev/null; then echo yes; else echo no; fi))
DEFINES += -DHAVE_SCANDIRAT
endif
WARN = -Wall -Wextra -Wnull-dereference -Wdouble-promotion -Wshadow -Wformat=2 -Wduplicated-cond -Wduplicated-branches -Wlogical-op -Wrestrict -Wjump-misses-init -Werror

all: $(PROGRAMS)

$(PROGRAMS): %: %.c
	$(CC) -o $@ $(CFLAGS) $(DEFINES) $(WARN) $<

install: all
	for f in $(PROGRAMS); do \
	  install -D $$f $(DESTDIR)/usr/bin/$$f; \
	done

dist:
	rm -f putils-$(VERSION)
	ln -s . putils-$(VERSION)
	tar jcvfh putils-$(VERSION).tar.bz2 putils-$(VERSION)/{Makefile,pfiles.c,plimit.c,putils.spec}
	rm -f putils-$(VERSION)

clean:
	-rm -f $(PROGRAMS)
