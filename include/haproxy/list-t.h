/*
 * include/haproxy/list-t.h
 * Circular list manipulation types definitions
 *
 * Copyright (C) 2002-2020 Willy Tarreau - w@1wt.eu
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation, version 2.1
 * exclusively.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef _HAPROXY_LIST_T_H
#define _HAPROXY_LIST_T_H


/* these are circular or bidirectionnal lists only. Each list pointer points to
 * another list pointer in a structure, and not the structure itself. The
 * pointer to the next element MUST be the first one so that the list is easily
 * cast as a single linked list or pointer.
 */
struct list {
    struct list *n;	/* next */
    struct list *p;	/* prev */
};

/* This is similar to struct list, but we want to be sure the compiler will
 * yell at you if you use macroes for one when you're using the other. You have
 * to expicitely cast if that's really what you want to do.
 */
struct mt_list {
    struct mt_list *next;
    struct mt_list *prev;
};


/* a back-ref is a pointer to a target list entry. It is used to detect when an
 * element being deleted is currently being tracked by another user. The best
 * example is a user dumping the session table. The table does not fit in the
 * output buffer so we have to set a mark on a session and go on later. But if
 * that marked session gets deleted, we don't want the user's pointer to go in
 * the wild. So we can simply link this user's request to the list of this
 * session's users, and put a pointer to the list element in ref, that will be
 * used as the mark for next iteration.
 */
struct bref {
	struct list users;
	struct list *ref; /* pointer to the target's list entry */
};

/* Similar to bref. Used to list elements which currently tracks a target.
 * Contrary to bref, when target is removed, each elements pointers are updated
 * to the next entry or NULL if target was the last one.
 */
struct bref_ptr {
	struct mt_list el; /* attach point into target list */
	void **pptr;       /* pointer to element which points to target */
	void *(*next_cb)(const void *target); /* callback to retrieve next target when current one is deleted */
};

/* a word list is a generic list with a pointer to a string in each element. */
struct wordlist {
	struct list list;
	char *s;
};

/* this is the same as above with an additional pointer to a condition. */
struct cond_wordlist {
	struct list list;
	void *cond;
	char *s;
};

#endif /* _HAPROXY_LIST_T_H */
