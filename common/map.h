#ifndef MAP_H
#define MAP_H

#define USED_IN_PAM 1
#define UNUSED_IN_PAM 0

typedef struct useritem
{
    char* from;
    char* to;
} UI;

typedef struct user
{
    int size;
    UI* items;	
} U;

typedef struct mapitem
{
    char* name;
    char* url;
    U* users;
    int type;
} MI;

typedef struct map
{
    int size;
    MI* items;
} M;


extern int map_debug;
struct map* map_new();
struct user* map_items_new();
void map_add(const char* name, const char* url, struct user* users, struct map** map);
void map_item_add(config_setting_t* users_from, struct user** users_to);
void* map_get_key(const char* key, struct map* map);
void map_close(struct map** map);
bool map_check_uniqueness_and_set(const char* username, struct map* map, char** mapped_name, int option);

#endif
