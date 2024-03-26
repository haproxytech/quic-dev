#include <haproxy/guid.h>

#include <import/ebistree.h>
#include <haproxy/proxy.h>
#include <haproxy/obj_type.h>
#include <haproxy/server-t.h>
#include <haproxy/tools.h>

static struct eb_root guid_tree = EB_ROOT_UNIQUE;

/* Insert <objt> into GUID tree with key <uid>.
 *
 * Returns 0 on success else non-zero.
 */
int guid_insert(enum obj_type *objt, const char *uid)
{
	struct guid_node *guid;

	switch (obj_type(objt)) {
	case OBJ_TYPE_PROXY:
		guid = &__objt_proxy(objt)->guid;
		break;
	case OBJ_TYPE_SERVER:
		guid = &__objt_server(objt)->guid;
		break;
	default:
		ABORT_NOW();
		return 0;
	}

	guid->node.key = strdup(uid);
	if (ebis_insert(&guid_tree, &guid->node) != &guid->node)
		return 1;

	guid->obj_type = objt;
	return 0;
}

void guid_remove(struct guid_node *guid)
{
	ebpt_delete(&guid->node);
}

struct guid_node *guid_lookup(const char *uid)
{
	struct ebpt_node *node = NULL;
	struct guid_node *guid = NULL;

	node = ebis_lookup(&guid_tree, uid);
	if (node)
		guid = ebpt_entry(node, struct guid_node, node);

	return guid;
}

void guid_name(const struct guid_node *guid, char **msg)
{
	struct proxy *px;
	struct server *srv;

	switch (obj_type(guid->obj_type)) {
	case OBJ_TYPE_PROXY:
		px = __objt_proxy(guid->obj_type);
		memprintf(msg, "%s %s", proxy_cap_str(px->cap), px->id);
		break;

	case OBJ_TYPE_SERVER:
		srv = __objt_server(guid->obj_type);
		memprintf(msg, "server %s/%s", srv->proxy->id, srv->id);
		break;

	default:
		break;
	}
}

/* Retrieve a server instance with key <uid> into GUID tree.
 *
 * Returns server instance or NULL if not found.
 */
struct server *guid_find_srv(const char *uid)
{
	struct server *srv = NULL;
	struct guid_node *guid;

	guid = guid_lookup(uid);
	if (guid)
		srv = objt_server(guid->obj_type);

	return srv;
}
