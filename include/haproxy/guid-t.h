#ifndef _HAPROXY_GUID_T_H
#define _HAPROXY_GUID_T_H

#include <import/ebtree-t.h>
#include <haproxy/obj_type-t.h>

struct guid_node {
	struct ebpt_node node;
	enum obj_type *obj_type;
};

#endif /* _HAPROXY_GUID_T_H */
