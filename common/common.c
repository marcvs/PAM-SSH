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
 * This is common code used by the nss_mapuser and nss_mapuid NSS
 * plugin library.   None of it's symbols are public, they are stripped
 * during the linking phase (made internal only).
 */

#include "common.h"
#include <sys/stat.h>
#include <stddef.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>


static const char* config_file = "/etc/pam_nss.conf";

/* set from configuration file parsing; stripped from exported symbols
 * in build, so local to the shared lib. */
config_setting_t *iam_mappings, *debug, *excl_users;


struct map* mapped_users = NULL;
struct list* excluded_users = NULL;
char *mappeduser;
int map_debug = 0;

config_t cf;
static int conf_parsed = 0;
static const char *libname = NULL;    /* for syslogs, set in each library */
static const char dbdir[] = "/run/mapiamuser/";

/*
 * If you aren't using glibc or a variant that supports this,
 * and you have a system that supports the BSD getprogname(),
 * you can replace this use with getprogname()
 */
extern const char *__progname;

/* Log events to syslog */
void sys_log(int err, const char *format, ...)
{
   va_list  args;
   va_start(args, format);
   openlog(libname, LOG_PID | LOG_NDELAY, LOG_SYSLOG);
   vsyslog(err, format, args);
   va_end(args);
   closelog();
}

/*  reset all config variables when we are going to re-parse */
static void reset_config(void)
{
    /*  reset the config variables that we use, freeing memory where needed */
    if (map_debug > 1)
        sys_log(LOG_DEBUG,"reset_config start");
    config_destroy(&cf);
    if (mapped_users) {
        map_close(&mapped_users);
    }
    if (excluded_users) {
        list_close(&excluded_users);
    }
    map_debug = 0;
    if (map_debug > 1)
        sys_log( LOG_DEBUG,"reset_config end");
}

/*
 * Read pam_nss config file and allocates the necessary memory for the input data
 * return 0 on succesful parsing (at least no hard errors), 1 if
 *  an error, and 2 if already parsed and no change to config file
 */

int nss_mapiamuser_config(int *errnop, const char *lname)
{
    //const config_setting_t *mappings;
    int count;
    static struct stat lastconf;
    struct user* mapped_users_items = NULL;
    libname = lname;
    if (map_debug > 1)
        sys_log(LOG_DEBUG,"nss_mapiamuser_config start, conf_parsed=%d", conf_parsed);
    if (conf_parsed) {
        struct stat st, *lst = &lastconf;
        /*
         *  check to see if the config file(s) have changed since last time,
         *  in case we are part of a long-lived daemon.  If any changed,
         *  reparse.  If not, return the appropriate status (err or OK)
         */

        if (stat(config_file, &st) && st.st_ino == lst->st_ino &&
            st.st_mtime == lst->st_mtime
            && st.st_ctime == lst->st_ctime)
            return 2;    //  nothing to reparse
        reset_config();
        conf_parsed = 0;
        if (map_debug && conf_parsed)
            sys_log(LOG_DEBUG,
                   "%s: Configuration file changed, re-initializing",
                   libname);
    }    
    if (map_debug > 1)
        sys_log(LOG_DEBUG, "Setting lib name: %s", libname);
    //cf = &cfg;
    config_init(&cf);
    if (map_debug > 1)
        sys_log(LOG_DEBUG, "Calling config init");
    if (config_read_file(&cf, config_file) != CONFIG_TRUE) {
        sys_log(LOG_DEBUG, "%s:%d - %s\n",
            config_error_file(&cf),
            config_error_line(&cf),
            config_error_text(&cf));
        config_destroy(&cf);
        return(EXIT_FAILURE);
    }
    if (map_debug > 1)
        sys_log(LOG_DEBUG, "Config read");
    if (stat(config_file, &lastconf) > 0)
        memset(&lastconf, 0, sizeof lastconf);    
    if (!config_lookup_int(&cf, "debug", &map_debug))
        map_debug = 0;

    if (map_debug > 1)
        sys_log(LOG_DEBUG, "Config read excluded_users");
    excl_users = config_lookup(&cf, "excluded_users");
    if (excl_users != NULL && config_setting_is_list(excl_users) == CONFIG_TRUE){
        if (map_debug > 1)
            sys_log(LOG_DEBUG, "Excluded users: OK\n");
        if (!excluded_users)
            excluded_users = list_new();
        count = config_setting_length(excl_users);
        int i;
        if (map_debug > 1)
            sys_log(LOG_DEBUG, "Excluded users count: %d", count);
        for(i = 0; i < count; ++i)
        {
            const char* e_name = config_setting_get_string_elem(excl_users, i);
            const char *name;
            if (e_name != NULL)
            {
                  name = strdup(e_name);
                  if (map_debug > 1)
                      sys_log(LOG_DEBUG, "Adding: %s", name);
                list_add((char*)name, &excluded_users);
            }
        }
    }
    
    iam_mappings = config_lookup(&cf, "mappings");
    if (iam_mappings != NULL){        
        mapped_users = map_new();        
        count = config_setting_length(iam_mappings);
        if (map_debug > 1)
            sys_log(LOG_DEBUG, "Mappings: OK, sections count: %d\n", count);
        int i;
        for(i = 0; i < count; ++i)
        {
            config_setting_t *mapping = config_setting_get_elem(iam_mappings, i);
            config_setting_t *users = config_setting_get_member(mapping, "users");
            int count_users = users ? config_setting_length(users): 0;
            const char *name, *url;
            if (!(config_setting_lookup_string(mapping, (char*)"name", &name)
                   && config_setting_lookup_string(mapping, (char*)"url", &url)
                   && users))
                continue;
            char* name_ = strdup(name);
            char* url_ = strdup(url);
            
            if (map_debug > 1)
                sys_log(LOG_DEBUG, "Mappings section: %s, users count: %d\n", name, count_users);
            mapped_users_items = map_items_new();
            map_item_add(users, &mapped_users_items);
            map_add((char*)name_, (char*)url_, mapped_users_items, &mapped_users);
            if (name_)
                free(name_);
            if (url_)
                free(url_);
        }
    }
    
    config_destroy(&cf);
    conf_parsed = 1;
    if (map_debug > 1)
        sys_log(LOG_DEBUG, "nss_mapiamuser_config on return: %d", mapped_users ? 0 : 1);
    return mapped_users ? 0 : 1;
}



/*
 * copy a passwd structure and it's strings, using the provided buffer
 * for the strings.
 * user name is used for the new pw_name, the last part of the homedir,
 * and the GECOS field.
 * For strings, if pointer is null, use an empty string.
 * Returns 0 if everything fit, otherwise 1.
 */
int
pwcopy(char *buf, size_t len, const char *usename, struct passwd *srcpw,
       struct passwd *destpw)
{
    int needlen, cnt, origlen = len;
    char *shell;

    if (!usename) {        /*  this should never happen */
        if (map_debug > 1)
            syslog(LOG_DEBUG, "%s: empty username, failing",
                   libname);
        return 1;
    }

    needlen = 2 * strlen(usename) + 2 +    /*  pw_name and pw_gecos */
    srcpw->pw_dir ? strlen(srcpw->pw_dir) + 1 : 1 + srcpw->pw_shell ?
    strlen(srcpw->pw_shell) + 1 : 1 + 2 +    /*  for 'x' in passwd */
        12;            /*  for the "Mapped user" in gecos */
    if (needlen > len) {
        if (map_debug > 1)
            syslog(LOG_DEBUG,
                   "%s provided password buffer too small (%ld<%d)",
                   libname, (long)len, needlen);
        return 1;
    }

    destpw->pw_uid = srcpw->pw_uid;
    destpw->pw_gid = srcpw->pw_gid;

    cnt = snprintf(buf, len, "%s", usename);
    if (cnt < 1) return 1;
    destpw->pw_name = buf;
    cnt++;            /* allow for null byte also */
    buf += cnt;
    len -= cnt;
    cnt = snprintf(buf, len, "%s", "x");
    if (cnt < 1) return 1;
    destpw->pw_passwd = buf;
    cnt++;
    buf += cnt;
    len -= cnt;
    cnt = snprintf(buf, len, "%s", srcpw->pw_shell ? srcpw->pw_shell : "");
    if (cnt < 1) return 1;
    destpw->pw_shell = buf;
    //shell = strrchr(buf, '/');
    //shell = shell ? shell + 1 : buf;
    cnt++;
    buf += cnt;
    len -= cnt;
    cnt = snprintf(buf, len, "%s mapped user", usename);
    if (cnt < 1) return 1;
    destpw->pw_gecos = buf;
    cnt++;
    buf += cnt;
    len -= cnt;

    char *slash, dbuf[strlen(srcpw->pw_dir) + strlen(usename) + 1];
    if (snprintf(dbuf, sizeof dbuf, "%s",
         srcpw->pw_dir ? srcpw->pw_dir : "") < 1) return 1;
    slash = strrchr(dbuf, '/');
    if (slash) {
        slash++;
        if (snprintf(slash, sizeof dbuf - (slash - dbuf), "%s",
             usename) < 1) return 1;
    }
    cnt = snprintf(buf, len, "%s", dbuf);
    if (cnt < 1) return 1;

    destpw->pw_dir = buf;
    cnt++;
    buf += cnt;
    len -= cnt;
    if (len < 0) {
        if (map_debug > 1)
            syslog(LOG_DEBUG,
                   "%s provided password buffer too small (%ld<%d)",
                   libname, (long)origlen, origlen - (int)len);
        return 1;
    }
    return 0;
}
/*
 * pb->name is non-NULL when we have the name and want to look it up
 * from the mapping.  mapuid will be the auid if we found it in the
 * files, otherwise will be what was passed down, which should
 * be the UID we are looking up when pb->name is NULL, when it's
 * the uid lookup, and otherwise should be -1 when pb->name is not NULL.
 * Returns 0 on success, 1 if uid not found in mapping files (even if
 * uid matches the radius mapping users; let nss_files handle that).
 */
int
get_pw_mapuser(const char *name, struct pwbuf *pb)
{
    FILE *pwfile;
    struct passwd *pwd;
    int ret = 1;
    if (map_debug > 1){
        sys_log(LOG_DEBUG,"get_pw_mapuser start");
        sys_log(LOG_DEBUG,"checking /etc/passwd");
    }

    pwfile = fopen("/etc/passwd", "r");
    if (!pwfile) {
        if (map_debug > 1)
            sys_log(LOG_WARNING, "%s: failed to open /etc/passwd: %m",
                   libname);
        return 1;
    }
    
    for (ret = 1; ret && (pwd = fgetpwent(pwfile));) {
        if (!pwd->pw_name)
            continue;    // shouldn't happen
        if (strcmp(pwd->pw_name, name) == 0) {
            ret = pwcopy(pb->buf, pb->buflen, pb->name, pwd, pb->pw);
            if (map_debug > 1)
                sys_log(LOG_DEBUG,"strcmp(pwd->pw_name, name) == OK, ret=%d", ret); 
            break;
        }
    }
    fclose(pwfile);
    if (map_debug > 1)
            sys_log(LOG_DEBUG,"After /etc/passwd checking section.");
    if (ret) {
        if (map_debug > 1){
            sys_log(LOG_DEBUG,"Finding user details in next in next db.");
            sys_log(LOG_DEBUG,"get_pw_mapuser before while loop");
        }
        while ((pwd = getpwent()) != NULL && ret)
        {
            if (!pwd->pw_name)
                continue;
            
            if (map_debug > 1)
                sys_log(LOG_DEBUG,"user = '%s', uid = %d, gid = %d, name = '%s'",
                   pwd->pw_name, pwd->pw_uid, pwd->pw_gid, pwd->pw_gecos);
            
            if (!strcmp(pwd->pw_name, name)) {            
                ret =
                    pwcopy(pb->buf, pb->buflen, pb->name, pwd, pb->pw);
                if (map_debug > 1)
                    sys_log(LOG_DEBUG,"strcmp(pwd->pw_name, name) == OK, ret=%d", ret);
                break;
            }        
        }
        if (map_debug > 1)
            sys_log(LOG_DEBUG,"get_pw_mapuser after while loop");
    }
    if (ret) {
        *pb->errnop = ERANGE;
    }
    if (map_debug > 1)
        sys_log(LOG_DEBUG,"get_pw_mapuser on return %d", ret);
    return ret;
}




/*
 * Used when there are no mapping entries, just create an entry from
 * the default radius user
 * This is needed so that ssh and login accept the username, and continue.
 */
int make_mapuser(struct pwbuf *pb, const char *mappedname)
{
    int ret;
    if (map_debug > 1)
        sys_log(LOG_DEBUG,"make_mapuser");
    ret = get_pw_mapuser(mappedname, pb);
    return ret;
}

static char*_getcmdname(void)
{
    static char buf[TASK_COMM_LEN + 1];
    char *rv = NULL;
    int ret, fd;
    if (map_debug > 1)
        sys_log(LOG_DEBUG,"_getcmdname");
    if (*buf)
        return buf;

    fd = open("/proc/self/comm", O_RDONLY);
    if (fd == -1) {
        if (map_debug > 1)
            sys_log(LOG_DEBUG,
                   "%s: failed to open /proc/self/comm: %m",
                   libname);
    } else {
        ret = read(fd, buf, sizeof buf);
        if (ret <= 0) {
            if (map_debug > 1)
                sys_log(LOG_DEBUG,
                       "%s: read /proc/self/comm ret %d: %m",
                       libname, ret);
        } else {
            (void)strtok(buf, "\n\r ");
            rv = buf;
        }
    }

    return rv;
}

static int chk_progs(const char *pname)
{
    static const char *progs[] =
        { "useradd", "usermod", "userdel", "adduser",
        "deluser", NULL
    };
    const char **prog;
    int ret = 0;
    if (map_debug > 1)
        sys_log(LOG_DEBUG,"chk_progs");
    for (prog = &progs[0]; pname && *prog && !ret; prog++) {
        if (strcmp(pname, *prog) == 0) {
            if (map_debug > 1)
                sys_log(LOG_DEBUG,
                       "%s: running from %s, skip lookup",
                       libname, *prog);
            ret = 1;
        }
    }
    return ret;
}

/*
 * the useradd family will not add/mod/del users correctly with
 * the mapuid functionality, so return immediately if we are
 * running as part of those processes.  Same for adduser, deluser
 * adduser and deluser are often perl scripts, so check for "comm"
 * name from /proc, also, unless already matched from progname.
 */
int skip_program(void)
{
    if (map_debug > 1)
        sys_log(LOG_DEBUG,"skip_program");
    return chk_progs(__progname) || chk_progs(_getcmdname());
}

/*
 * All the entry points have this same common prolog, so put it here
 */
int map_init_common(int *errnop, const char *plugname)
{
    libname = plugname;
    if (map_debug > 1)
        sys_log(LOG_DEBUG,"map_init_common start");
    if (skip_program())
        return 1;

    if (nss_mapiamuser_config(errnop, plugname) == 1) {
        *errnop = ENOENT;
        if (map_debug > 1)
            sys_log(LOG_NOTICE, "%s: bad configuration", plugname);
        return 1;
    }
    if (map_debug > 1)
        sys_log(LOG_DEBUG,"map_init_common end");
    return 0;
}


void remove_char(char *str, char c) {
    char *pr = str, *pw = str;
    while (*pr) {
        *pw = *pr++;
        pw += (*pw != c);
    }
    *pw = '\0';
}

/*
 * Splits address into username and host.
 * Input: address
 * Output: username and host -> have to be allocated prior to function call
 */

bool traverse_username(const char* address, char** username, char** host)
{
    char* token;
    const char sep[2] = "@";
    int cnt;
    if (!address || !*username || !*host)
        return false;
      
    if (map_debug > 1)
        sys_log(LOG_DEBUG,"traverse_username start");
      
    int len_username = strlen(*username);
    int len_address = strlen(address);
    char* address_cpy =  (char *)calloc(len_address, sizeof(char));
    if (!address_cpy)
        return false;
    cnt = snprintf(address_cpy, len_address + 1, "%s", address);
    if (cnt < 1) return false;
    token = strtok(address_cpy, sep);
    if (token){
        int len_token = strlen(token);
        snprintf(*username, len_token + 1, "%s", token);
        token = strtok(NULL, sep);          
        if (token){                             
            len_token = strlen(token);
            cnt = snprintf(*host, len_token + 1, "%s", token);
            if (cnt < 1) return false;
        } else 
            memset(*host, '\0', strlen(*host));
        // no need to free token!
    } else {
        int l_user_add = len_username < len_address? len_username : len_address;
        cnt = snprintf(*username, l_user_add + 1, "%s", address_cpy);
        if (cnt < 1) return false;
        memset(*host, '\0', strlen(*host));
    }
    free(address_cpy);  
    return true;
}

/*
bool traverse_username2(const char* address, char** username, char** host){
    char* token; 
      const char sep[2] = "@";
      char* address_cpy = NULL;
      if (map_debug > 1)
        sys_log(LOG_DEBUG,"traverse_username start");
      if (address){
          address_cpy = strdup(address);
        token = strtok((char*)address_cpy, sep);        
        if (token){
            if (!*username){                
                *username = strdup(token);
              } else {
                  int len = strlen(token);
                strncpy(*username, token, len);
                *username[len] = '\0';
              }
              token = strtok(NULL, sep);
              if (token){
                if (!*host)
                      *host = strdup(token);
                else {
                    int len = strlen(token);
                      strncpy(*host, token, len);
                      *host[len] = '\0';
                }
              } else
                  *host = NULL;
        } else {
            *username = strdup(address_cpy);
            *host = NULL;
        }
        free(address_cpy);  
        return true;
      } else      
          return false;
}
*/

/*
 * Get mapped username based on pam_nss.conf file
 *
*/
char* map_get_mapped_user(const char* fullusername, const bool used_in_pam){
    if (!fullusername)
        return NULL;
    char *location = strdup(fullusername);
    char *username = strdup(fullusername);
    //const char *to = NULL, *url = NULL;    
    bool found = false;
    if (map_debug > 1)
        sys_log(LOG_DEBUG, "map_get_mapped_user start, fullusername: %s, used_in_pam: %d", fullusername, used_in_pam);
    bool code = traverse_username(fullusername, &username, &location);
    if (map_debug > 1)
    {
        sys_log(LOG_DEBUG, "code: %d, fullusername: %s", code, fullusername);
        sys_log(LOG_DEBUG, "strcmp: %d", !strcmp(fullusername, username));
        sys_log(LOG_DEBUG, "username: %s, location: %s", username, location);
    }
    if (mapped_users && username){
        if (code && location){
            struct mapitem* mapped_item = (struct mapitem*)map_get_key(location, mapped_users);
            if (mapped_item && mapped_item->users){
                int i = 0;                
                while (i < mapped_item->users->size && !found)
                {
                    if (strcmp((mapped_item->users->items + i)->from, username) == 0)
                        found = true;
                    i++;
                }
                if (found){
                    if (map_debug > 1)
                        sys_log(LOG_DEBUG, "map_get_mapped_user on return when user found");
                    if (username)
                        free(username);
                    if (location)
                        free(location);
                    return (used_in_pam)? mapped_item->url: strdup((mapped_item->users->items + i - 1)->to);
                }
            }
        } else {
            //char *to_or_url = (char*)calloc(10, sizeof(char));
            char *to_or_url = NULL;
            bool unique = map_check_uniqueness_and_set(username, mapped_users, (char**)&to_or_url, used_in_pam);
            if (map_debug > 1)
                sys_log(LOG_DEBUG, "map_get_mapped_user on return when unique: %d", unique);
            //sys_log(LOG_DEBUG, "unique: %d, to: %s\n", unique, to);
            if (username)
                free(username);
            if (location)
                free(location);
            return (unique) ? (char*)to_or_url: NULL;
        }
    }
    if (map_debug > 1)
        sys_log(LOG_DEBUG, "map_get_mapped_user on return: NULL\n");
    if (username)
        free(username);
    if (location)
        free(location);
    return NULL;
}


/*
void* map_get_mapped_user_pam(const char* fullusername, const bool used_in_pam){
    char *location = NULL;
    char *username = NULL;
    const char *from = NULL, *to, *url;
    bool found = false;
    if (map_debug > 1)
        sys_log(LOG_DEBUG, "map_get_mapped_user_pam start");
    bool code = traverse_username(fullusername, &username, &location);
    if (map_debug > 1)
        sys_log(LOG_DEBUG, "username: %s, location: %s\n", username, location);

    if (mapped_users && username){
        if (code && location){
            struct mapitem* mapped_item = (struct mapitem*)map_get_key(location, mapped_users);
            if (mapped_item && mapped_item->users){
                int i = 0;
                while (i < mapped_item->users->size && !found)
                {
                    if (!strcmp((mapped_item->users->items + i)->from, username))
                        found = true;
                    i++;
                }
                if (found)
                    return mapped_item->url;
            }
        } else {
            bool unique = map_check_if_unique(username, mapped_users, (char**)&url, used_in_pam);            
            if (map_debug > 1)
                sys_log(LOG_DEBUG, "map_get_mapped_user on return when unique: %d", unique);
            return (unique) ? (char*)url: NULL;
        }
    }
    return NULL;
}
*/

char* map_get_url_for_location(const char* location){
    if (map_debug > 1)
        sys_log(LOG_DEBUG, "map_get_url_for_location start");
    if (mapped_users){
        struct mapitem* mapped_item = (struct mapitem*)map_get_key(location, mapped_users);
        if (mapped_item){
            if (map_debug > 1)
                sys_log(LOG_DEBUG, "mapped_item is not null, url: %s", mapped_item->url);
            return mapped_item->url;
        } else
            if (map_debug > 1)
                sys_log(LOG_DEBUG, "mapped_item is null");
    }
    return NULL;
}
