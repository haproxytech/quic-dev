#ifndef _HAPROXY_GUID_H
#define _HAPROXY_GUID_H

#include <haproxy/guid-t.h>

int guid_insert(enum obj_type *obj_type, const char *uid);
void guid_remove(struct guid_node *guid);
struct guid_node *guid_lookup(const char *uid);
void guid_name(const struct guid_node *guid, char **msg);

#endif /* _HAPROXY_GUID_H */
