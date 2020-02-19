COMMON=../common
NAME_SOURCE=nss_mapiamname.c ${COMMON}/common.c ${COMMON}/map.c ${COMMON}/list.c
NSSNAMELIB=libnss_mapiamname.so.2

# set to x86_64-linux-gnu, arm-linux-gnueabi, etc. by packaging tools
# If not set, just install directly to /lib
#DEB_TARGET_GNU_TYPE=x86_64-linux-gnu/tls/x86_64
#LIBDIR=/lib/${DEB_TARGET_GNU_TYPE}
LIBDIR=/lib64

CC = gcc

ifneq (,$(filter noopt,$(DEB_BUILD_OPTIONS)))
		OPTFLAGS = -O2
else
		OPTFLAGS = -g3 -O0
endif
ifeq (,$(filter nostrip,$(DEB_BUILD_OPTIONS)))
	STRIP = strip
    FVISIBILITY = -fvisibility=hidden
else
	STRIP=echo Nostrip
    FVISIBILITY = -fvisibility=default
endif

CPPFLAGS = -D_FORTIFY_SOURCE=2
CFLAGS = $(CPPFLAGS) ${OPTFLAGS} -fPIC \
         -std=gnu99 \
		 -Wformat -Werror=format-security -Wall $(FVISIBILITY)

#FLAGS   =
#CFLAGS  = -Wall -fPIC
#DEBUGFLAGS =
LDLIBS =  -lconfig -laudit
LDFLAGS = -shared  -fPIC -DPIC \
		  -Wl,-z -Wl,relro -Wl,-z -Wl,now -Wl,-soname -Wl,$@


all: $(NSSNAMELIB)

$(NSSNAMELIB): $(NAME_SOURCE)
#$(NSSNAMELIB): $(OBJECTS)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)
#	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)
# 	$(CC)  $(CFLAGS) -o $(NSSNAMELIB) $(OBJECTS)


install: all
	install -m 755 -d $(DESTDIR)/$(LIBDIR) $(DESTDIR)/etc
	install -m 644 $(NSSNAMELIB) $(DESTDIR)$(LIBDIR)
	$(STRIP) --strip-all --keep-symbol=_nss_mapiamname_getpwnam_r \
			$(DESTDIR)$(LIBDIR)/${NSSNAMELIB}
	#install -m 644 pam_nss.conf $(DESTDIR)/etc/

clean:
	rm -f *.o

uninstall:
	rm -f $(NSSNAMELIB)

.PHONY: all install uninstall clean distclean
