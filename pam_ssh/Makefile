CC      = gcc
FLAGS   =
CFLAGS  = -g -O2 -fPIC -lcurl -lpam
LDFLAGS = -lcurl -lc -x --shared -lpam -lconfig -laudit
TARGET  = /lib64/security/pam_ssh.so
OS=$(shell lsb_release  -si 2>/dev/null)
ifeq ($(OS),Debian)
	TARGET  = /lib/x86_64-linux-gnu/security/pam_ssh.so
endif

COMMON  = ../common
SOURCES = ${COMMON}/common.c ${COMMON}/map.c  ${COMMON}/list.c pam_ssh.c mjson.c pam_ssh_common.c 
OBJECTS = $(SOURCES:.c=.o)

all: lib

lib: 
	$(CC) $(CFLAGS) -c $(SOURCES)
	mv common.o map.o list.o ${COMMON}
clean:
	rm -f $(OBJECTS) $(TARGET)

install: lib
	ld $(LDFLAGS) -o $(TARGET) $(OBJECTS)

uninstall:
	rm -f $(TARGET)

.PHONY: all install uninstall clean

distclean: clean
	rm -f common.o list.o map.o 
