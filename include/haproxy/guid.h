#ifndef _HAPROXY_GUID_H
#define _HAPROXY_GUID_H

#include <haproxy/guid-t.h>

struct server;

int guid_insert(enum obj_type *obj_type, const char *uid);
void guid_remove(struct guid_node *guid);
struct guid_node *guid_lookup(const char *uid);
void guid_name(const struct guid_node *guid, char **msg);

struct server *guid_find_srv(const char *uid);

#endif /* _HAPROXY_GUID_H */
