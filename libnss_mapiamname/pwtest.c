#include <sys/types.h>
#include <pwd.h>
#include <stdio.h>

int
main(void)
{
    struct passwd *pwd;

    while ((pwd = getpwent()) != NULL) {
        printf("user = `%s', uid = %d, gid = %d, name = `%s'\n",
               pwd->pw_name, pwd->pw_uid, pwd->pw_gid, pwd->pw_gecos);
    }

    return 0;
}
