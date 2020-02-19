#include <stdlib.h>
#include <string.h>
#include <libconfig.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <stddef.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/types.h>
#include "map.h"

#define MAP_BY_VAL 0
#define MAP_BY_REF 1

// Based on https://github.com/soywod/c-map/blob/master/map.c

/*
 * Create a map
 */
M* map_new()
{
    M* map;

    map = malloc(sizeof(M));
    map->size = 0;
    map->items = NULL;

    return map;
}

/*
 * Allocate items for a map
 */

U* map_items_new()
{
    U* users;

    users = malloc(sizeof(U));
    users->size = 0;
    users->items = NULL;

    return users;
}

/*
 * Add item to map; maps user from libconfig structure (config_setting_t) into map structure
 * users_from: config_setting_t element taken from config
 * users_to: output element of struct user type
 */


void map_item_add(config_setting_t* users_from, struct user** users_to)
{    
    int i;
    int count_users = (config_setting_t *)users_from ? config_setting_length((config_setting_t *)users_from): 0;
    if (map_debug > 1)
        syslog(LOG_DEBUG, "map_item_add start, count: %d", count_users);
    for(i = 0; i < count_users; ++i){
        config_setting_t *user = config_setting_get_elem(users_from, i);
        const char *from, *to;
        if (!(config_setting_lookup_string(user, (char*)"from", &from)
              && config_setting_lookup_string(user, (char*)"to", &to)))
               continue;
        if ((*users_to)->size == 0)
        {
            (*users_to)->items = malloc(sizeof(UI));
        }
        else
        {
            (*users_to)->items = realloc((*users_to)->items, sizeof(UI) * ((*users_to)->size + 1) );
        }
        ((*users_to)->items + (*users_to)->size)->from = strdup(from);
        ((*users_to)->items + (*users_to)->size++)->to = strdup(to);
    }
    if (map_debug > 1)
        syslog(LOG_DEBUG, "map_item_add end, size: %d", (*users_to)->size);
}

/*
 * Add item to map
 * name: section/group name to add
 * url: section/group authentication url
 */
void map_add(const char* name, const char* url, struct user* users, M** map)
{
    char* newname, *newurl;
    int cnt;
    if (map_debug > 1)
        syslog(LOG_DEBUG, "map_add start");
    if (!*map || !name || !url)
        return;
    newname = (char*)calloc(strlen(name) + 1, sizeof(char));
    cnt = snprintf(newname, strlen(name) + 1, "%s", name);
    if (cnt < 1) return;
    newurl = (char*)calloc(strlen(url) + 1, sizeof(char));
    cnt = snprintf(newurl, strlen(url) + 1, "%s", url);
    if (cnt < 1) return;
    if ((*map)->size == 0)
        (*map)->items = malloc(sizeof(MI));
    else
        (*map)->items = realloc((*map)->items, sizeof(MI) * ((*map)->size + 1) );

    ((*map)->items + (*map)->size)->name = newname;
    ((*map)->items + (*map)->size)->url = newurl;
    ((*map)->items + (*map)->size)->users = users;
    ((*map)->items + (*map)->size++)->type = MAP_BY_VAL;
    if (map_debug > 1)
        syslog(LOG_DEBUG, "map_add end, size: %d", (*map)->size);
}


/*
 * Get map key
 */


void* map_get_key(const char* name, M* map)
{
    int i;
    if (!map || ! name)
        return NULL;
    for (i = 0; i < map->size; i++)
    {
        if (strcmp((map->items + i)->name, name) == 0) // == 0
            return (map->items + i);
    }
    return NULL;
}

/*
 * Check if user name if unique within the map
 */

bool map_check_uniqueness_and_set(const char* username, M* map, char** name, int option)
{
    int i, j = 0;
    bool unique = true;
    bool found = false;
    if (!map)
        return false;
    if (!*name)
        return false;
    for (i = 0; i < map->size; i++)
    {
        struct mapitem* item = (struct mapitem*)(map->items + i);
        if (!item) continue;
        int j = 0;
        int len = 0;
        for(; j < item->users->size; j++)
        {
            if (strcmp((item->users->items + j)->from, username) == 0){ 
                if (found) unique = false;
                found = true;

                if (option == UNUSED_IN_PAM){
                    *name = strdup((item->users->items + j)->to);
                    /*
                    len = strlen((item->users->items + j)->to);
                    if (len != strlen(*name)){
                        *name = realloc(*name, sizeof(char)*(len + 1));
                        snprintf(*name, len + 1, "%s", (item->users->items + j)->to);
                    }
                    */
                }
                else {
                    *name = strdup(item->url);
                    /*
                    len = strlen(item->url);
                    if (len != strlen(*name)){
                        *name = realloc(*name, sizeof(char)*(len + 1));
                        snprintf(*name, len + 1, "%s", item->url);
                    }*/
                }
            }
        }
    }
    if (map_debug > 1)
        syslog(LOG_DEBUG, "map_check_uniqueness_and_set: unique: %d, found: %d\n", unique, found);
    return unique && found;
}

/*
 * Close map and free pointers
 */
void map_close(M** map) {
    int i = 0;
    if (!*map) {
        if (map_debug > 1)
            syslog(LOG_DEBUG, "Map is null");
        return;
    }
    if (map_debug > 1)
        syslog(LOG_DEBUG, "map_close start, size: %d", (*map)->size);

    for (; i < (*map)->size; i++) {
        if (map_debug > 2)
            syslog(LOG_DEBUG, "free(((*map)->items + %d)->name: %s)", i, ((*map)->items + i)->name);
        if (((*map)->items + i)->name) {
            free(((*map)->items + i)->name);
            ((*map)->items + i)->name = NULL;
        }

        if (map_debug > 2)
            syslog(LOG_DEBUG, "free(((*map)->items + %d)->url: %s)", i, ((*map)->items + i)->url);
        if (((*map)->items + i)->url) {
            free(((*map)->items + i)->url);
            ((*map)->items + i)->url = NULL;
        }
        int j = 0;

        if (map_debug > 2)
            syslog(LOG_DEBUG, "((*map)->items + %d)->users->size: %d", i, ((*map)->items + i)->users->size);
        for (; j < ((*map)->items + i)->users->size; j++) {
            if (map_debug > 2)
                syslog(LOG_DEBUG, "(((*map)->items + %d)->users->items + %d)->from: %s", i, j, (((*map)->items + i)->users->items + j)->from);
            if ((((*map)->items + i)->users->items + j)->from) {
                free((((*map)->items + i)->users->items + j)->from);
                (((*map)->items + i)->users->items + j)->from = NULL;
            }

            if (map_debug > 2)
                syslog(LOG_DEBUG, "(((*map)->items + %d)->users->items + %d)->to: %s", i, j, (((*map)->items + i)->users->items + j)->to);
            if ((((*map)->items + i)->users->items + j)->to) {
                free((((*map)->items + i)->users->items + j)->to);
                (((*map)->items + i)->users->items + j)->to = NULL;
            }
        }

        if (map_debug > 2)
            syslog(LOG_DEBUG, "free(((*map)->items + %d)->users->items, size: %d", i, ((*map)->items + i)->users->size);
        if (((*map)->items + i)->users->items) {
            free(((*map)->items + i)->users->items);
            ((*map)->items + i)->users->items = NULL;
        }

        if (map_debug > 2)
            syslog(LOG_DEBUG, "free(((*map)->items + %d)->users", i);
        if ((*map)->items->users) {
            free(((*map)->items + i)->users);
            ((*map)->items + i)->users = NULL;
        }
    }

        if (map_debug > 1)
            syslog(LOG_DEBUG, "free((*map)->items)");
        if ((*map)->items) {
            free((*map)->items);
            (*map)->items = NULL;
        }
           if (map_debug > 1)
            syslog(LOG_DEBUG, "free(*map)");
        if (*map) {
            free(*map);
            *map = NULL;
        }

    if (map_debug > 1)
        syslog(LOG_DEBUG, "map_close end");
}
