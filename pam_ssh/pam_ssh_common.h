#ifndef PAM_SSH_COMMON_H
#define PAM_SSH_COMMON_H

#include <security/pam_modules.h>
#include <security/_pam_macros.h>
#include <syslog.h>
#include <stdint.h>

#define INCORRECT "INCORRECT"
#define AUTH_BEARER "Authorization: Bearer "
#define SIZE 64
#define MAX_GROUPS 6
#define BUF_SIZE 256
#define CONF_VAR_NAME "pam_nss_conf="

static const char *pam_ssh = "PAM-SSH";  /* for syslogs */
/*
   sub": "38bf61bb-d1db-45e6-a36d-670e63aed301",
  "name": "FirstName LastName",
  "preferred_username": "someusername",
  "given_name": "FirstName",
  "family_name": "LastName",
  "updated_at": "Sat Oct 06 08:59:21 CEST 2018",
  "email": "some@email.com",
  "email_verified": true,
  "groups": [],
  "organisation_name": "deep-hdc"
};
*/

/* Data object to model */
struct userinfo {
    char sub[SIZE];
    char name[SIZE];
    char preferred_username[SIZE];
    char given_name[SIZE];
    char family_name[SIZE];
    char picture[4*SIZE-1];
    int updated_at;
    char email[SIZE];
    bool email_verified;
    char *groupsptrs[MAX_GROUPS];
    char groupsstore[SIZE*MAX_GROUPS];
    int groupscount;
    char organisation_name[SIZE];
 };

//extern void pam_log(int err, const char *format, ...);
extern int json_userinfo_read(const char *buf, struct userinfo *ui);
extern bool traverse_url(const char* domain, char** host);


#endif
