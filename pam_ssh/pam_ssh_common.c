#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <stdarg.h>
#include "mjson.h"
#include "pam_ssh_common.h"

static const char pam_tmp_file[] = "/tmp/libpam_ssh";


/* 
 * https://stackoverflow.com/questions/8778834/change-owner-and-group-in-c
 */

/* Object specific parsing function */
int json_userinfo_read(const char *buf, struct userinfo *ui) {
    
   const struct json_attr_t userinfo_attrs[] = {
        {"sub", t_string, .addr.string = ui->sub, .len = sizeof(ui->sub)},
        {"name", t_string, .addr.string = ui->name, .len = sizeof(ui->name)},
        {"preferred_username", t_string, .addr.string = ui->preferred_username, .len = sizeof(ui->preferred_username)},
        {"given_name", t_string, .addr.string = ui->given_name, .len = sizeof(ui->given_name)},
        {"family_name", t_string, .addr.string = ui->family_name, .len = sizeof(ui->family_name)},
        {"picture", t_string, .addr.string = ui->picture, .len = sizeof(ui->picture)},
        {"updated_at", t_integer, .addr.integer = &ui->updated_at},
        {"email", t_string, .addr.string = ui->email, .len = sizeof(ui->email)},
        {"email_verified", t_boolean, .addr.boolean = &ui->email_verified},
        {"groups", t_array, .addr.array.element_type = t_string,
                            .addr.array.arr.strings.ptrs = ui->groupsptrs,
                            .addr.array.arr.strings.store = ui->groupsstore,
                            .addr.array.arr.strings.storelen = sizeof(ui->groupsstore),
                            .addr.array.count = &ui->groupscount,
                            .addr.array.maxlen = sizeof(ui->groupsptrs)/sizeof(ui->groupsptrs[0])},
        {"organisation_name", t_string, .addr.string = ui->organisation_name, .len = sizeof(ui->organisation_name)},
        {NULL},
    };
    
    /* Parse the JSON object from buffer */
    return json_read_object(buf, userinfo_attrs, NULL);
}


/* 
 * Traversing IAM URL from PAM config file (e.g. common-auth. 
 * Extracts hostname from URL/domain.
 */

bool traverse_url(const char* domain, char** host){
    CURLU *h;
    CURLUcode uc;
    if (!host || !domain)
        return false;
    // parse a full URL
    h = curl_url(); // get a handle to work with
    if(!h)
        return false;
    uc = curl_url_set(h, CURLUPART_URL, domain, 0);
    if(!uc) {
        // extract host name from the parsed URL
        char* tmp_host;
        uc = curl_url_get(h, CURLUPART_HOST, &tmp_host, 0);    
        if(!uc) {
            int len_token = strlen(tmp_host);
            snprintf(*host, len_token + 1, "%s", tmp_host);
            //sys_log(LOG_DEBUG, "Host name: %s\n", *host);
            curl_free(tmp_host);
        }
    }
    curl_url_cleanup(h); /* free url handle */   
    return true;
}
