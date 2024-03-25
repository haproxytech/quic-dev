#include <haproxy/guid.h>

#include <import/ebistree.h>
#include <haproxy/obj_type.h>

static struct eb_root guid_tree = EB_ROOT_UNIQUE;

/* Insert <objt> into GUID tree with key <uid>.
 *
 * Returns 0 on success else non-zero.
 */
int guid_insert(enum obj_type *objt, const char *uid)
{
	struct guid_node *guid;

	switch (obj_type(objt)) {
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
	switch (obj_type(guid->obj_type)) {
	default:
		break;
	}
}
