#ifndef LIST_H
#define LIST_H


typedef struct listitem
{
    char* data;
} LI;

typedef struct list
{
    int size;
    LI* items;
} L;

extern int map_debug;
struct list* list_new();
void list_add(const char* data, L** list);
LI* list_get(const char* data, struct list* list);
void list_close(struct list** list);

#endif
