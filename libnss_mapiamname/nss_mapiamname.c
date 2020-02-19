#include <stdio.h>
#include <syslog.h>
#include <stdbool.h>
#include <fcntl.h>
#include <grp.h>
#include <nss.h>
#include "../common/common.h"

const char *nssname = "LIB-NSS";        // for syslogs

/*
 *  This is an NSS entry point.
 *  We map any username given to the account listed in the configuration file
 *  We only fail if we can't read the configuration file, or the username
 *  in the configuration file can't be found in the /etc/passwd file.
 *  Because we always have a positive reply, it's important that this
 *  be the last NSS module for passwd lookups.
 *  CAUTION: 'name' is always the username is using to login as
 */
__attribute__ ((visibility("default")))
enum nss_status _nss_mapiamname_getpwnam_r(const char *name,
                                        struct passwd *pw,
                                        char *buffer,
                                        size_t buflen,
                                        int *errnop) {
    enum nss_status status = NSS_STATUS_NOTFOUND; //0
    bool islocal = 0;
    struct pwbuf pbuf;
    char* mappeduser = NULL;
/*
    if (map_debug > 1)
    {
        sys_log(LOG_DEBUG, "_nss_mapiamname_getpwnam_r start");
        sys_log(LOG_DEBUG, "NSS user: %s, initial status: %d", name, status);
    }
*/
    if (name == NULL)
        return status;

    if (map_debug > 0)
        sys_log(LOG_DEBUG, "Calling map_init_common");

    if (!mapped_users){
        if (map_init_common(errnop, nssname)){
            if (map_debug)
                sys_log(LOG_DEBUG, "map_init_common (%s) ended with an error: %d", nssname, *errnop);
                return errnop
                    && *errnop == ENOENT ? NSS_STATUS_UNAVAIL : status;
        }
    }
    if (map_debug > 1)
        sys_log(LOG_DEBUG, "Calling map_get_mapped_user for '%s'", name);
    mappeduser = (char*)map_get_mapped_user(name, UNUSED_IN_PAM);
    if (map_debug > 1)
        sys_log(LOG_DEBUG, "map_get_mapped_user for '%s' ended", name);
    if (mappeduser && strcmp(mappeduser, name) == 0){
        islocal = 1;
        if (map_debug > 1)
            sys_log(LOG_DEBUG, "islocal (1): %d", islocal);
    } else if (excluded_users) {
        int i;
        if (map_debug > 1)
            sys_log(LOG_DEBUG, "Inside excluded_users for '%s'", name);
        for (i = 0; i < excluded_users->size; i++)
        {
            if (!strcmp((excluded_users->items + i)->data, name)) // == 0
            {
                islocal = 1;
                break;
            }
        }
    }
    if (map_debug > 1)
        sys_log(LOG_DEBUG, "islocal (2): %d", islocal);

    if (islocal) {
        if (map_debug > 0)
            sys_log(LOG_DEBUG, "%s: skipped excluded user: %s",
                nssname, name);
            return 2;
    }
    if (map_debug > 1) {
        if (mapped_users)
            sys_log(LOG_DEBUG, "Mapped users (not NULL)");
        else
            sys_log(LOG_DEBUG, "Mapped users (NULL)");
    }

    if (mapped_users && mappeduser != NULL){
        if (map_debug > 0)
            sys_log(LOG_DEBUG, "Mapped user is: %s", mappeduser);
        pbuf.name = (char *)mappeduser;
        pbuf.pw = pw;
        pbuf.buf = buffer;
        pbuf.buflen = buflen;
        pbuf.errnop = errnop;
        if (map_debug > 1)
            sys_log(LOG_DEBUG, "Calling make_mapuser");
        if (make_mapuser(&pbuf, mappeduser) == 0){
            if (map_debug > 1)
                sys_log(LOG_DEBUG, "make_mapuser succeeded");
            status = NSS_STATUS_SUCCESS;
        } else {
            if (map_debug > 1)
                sys_log(LOG_DEBUG, "make_mapuser failed");
        }
        if (map_debug > 1)
            sys_log(LOG_DEBUG, "make_mapuser ended. Status: %d (success = %d)", status, NSS_STATUS_SUCCESS);
    } else {
        if (map_debug > 0)
            sys_log(LOG_DEBUG, "Could not map: %s", name);
        status = NSS_STATUS_NOTFOUND;
    }

    if (map_debug > 0)
        sys_log(LOG_DEBUG, "_nss_mapiamname_getpwnam_r on return: %d (success = %d)", status, NSS_STATUS_SUCCESS);
    return status;
}
