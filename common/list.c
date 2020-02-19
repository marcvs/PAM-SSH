#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <syslog.h>
#include <stdio.h>
#include "list.h"

L* list_new()
{
    L* list;

    list = malloc(sizeof(L));
    list->size = 0;
    list->items = NULL;

    return list;
}


void list_add(const char* data, L** list)
{
    int cnt;
    size_t len = strlen(data) + 1;
    char* newdata = (char*)malloc(len);
    if (!newdata) return;
    //strcpy(newdata, data);
    cnt = snprintf(newdata, len, "%s", data);
    if (cnt < 1) return;
        if ((*list)->size == 0)
    {
        (*list)->items = malloc(sizeof(LI));
    }
    else
    {
        (*list)->items = realloc((*list)->items, sizeof(LI) * ((*list)->size + 1) );
    }
    ((*list)->items + (*list)->size++)->data = newdata;
}

LI* list_get(const char* data, L* list)
{
    int i;
    if (!list)
        return NULL;
    for (i = 0; i < list->size; i++)
    {
        if (strcmp((list->items + i)->data, data) == 0) // == 0
        {
            return (list->items + i);
        }
    }
    return NULL;
}

void list_close(L** list)
{
    int i = 0;
    if (!*list)
    {
        if (map_debug > 1)
            syslog(LOG_DEBUG, "List is null");
        return;
    }
 
    for(; i < (*list)->size; i++)
    {
        if (map_debug > 2)
            syslog(LOG_DEBUG, "free(((*list)->items + %d)->data: %s)", i, ((*list)->items + i)->data);
        if (((*list)->items + i)->data){            
            free(((*list)->items + i)->data);
            ((*list)->items + i)->data = NULL;
        }
    }
    if (map_debug > 1)
        syslog(LOG_DEBUG, "free((*list)->items)");
    if ((*list)->items){
        free((*list)->items);
        (*list)->items = NULL;
    }
    if (map_debug > 1)
        syslog(LOG_DEBUG, "free(*list)");
    if (*list){
        free(*list);
        *list = NULL;
    }
} 
