/*
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * All rights reserved.
 * Author: Dave Olson <olson@cumulusnetworks.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program - see the file COPYING.
 */

/*
 * This is the header file for the common code used by the nss_mapuser and
 * nss_mapuid NSS plugin library.   None of it's symbols are public, they are
 * stripped during the linking phase (made internal only).
 */

#ifndef _MAP_COMMON_H
#define _MAP_COMMON_H

#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <libaudit.h>
#include <libconfig.h>
#include <libgen.h>
#include <linux/sched.h>
#include <nss.h>
#include <pwd.h>
#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>

#include "map.h"
#include "list.h"

#define TASK_COMM_LEN 16
/*
 * pwbuf is used to reduce number of arguments passed around; the strings in
 * the passwd struct need to point into this buffer.
 */
struct pwbuf {
    char *name;
    char *buf;
    struct passwd *pw;
    int *errnop;
    size_t buflen;
};

extern struct map* mapped_users;
extern struct list* excluded_users;
extern int map_debug;
extern config_t cf;

extern void sys_log(int err, const char *format, ...);
extern int make_mapuser(struct pwbuf*, const char*);
extern int map_init_common(int*, const char*);
extern char* map_get_mapped_user(const char* fullusername, const bool used_in_pam);
extern char* map_get_url_for_location(const char* location);
extern bool traverse_username(const char* address, char** username, char** host);

#endif