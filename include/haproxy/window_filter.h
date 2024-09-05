#ifndef _HAPROXY_WINDOW_FILTER_H
#define _HAPROXY_WINDOW_FILTER_H

/* Window filter sample */
struct wf_smp {
	uint64_t v;
	uint32_t t;
};

/* Window filter */
struct wf {
	size_t len;
	struct wf_smp smp[3];
};

static inline void wf_init(struct wf *wf, size_t len)
{
	wf->len = len;
	memset(wf->smp, 0xff, sizeof(wf->smp));
}

static inline void wf_reset(struct wf *wf, uint64_t v, uint32_t t)
{
	struct wf_smp smp = { .v = v, .t = t };

	wf->smp[2] = wf->smp[1] = wf->smp[0] = smp;
}

/* Updates best estimates with |v| sample value, and expires and updates best
 * estimates as necessary.
 * Similar to minmax_subwin_update() linux kernel function (see lib/win_minmax.c
 * function).
 */
static inline void wf_update(struct wf *wf, uint64_t v, uint32_t t)
{
	/* Reset all estimates if they have not yet been initialized, if new
	   sample is a new best, or if the newest recorded estimate is too
	   old. */
	if (wf->smp[0].v == UINT64_MAX || v > wf->smp[0].v || t - wf->smp[2].t > wf->len) {
		wf_reset(wf, v, t);
		return;
	}

	if (v > wf->smp[1].v) {
		wf->smp[1].v = v;
		wf->smp[1].t = t;
		wf->smp[2] = wf->smp[1];
	} else if (v > wf->smp[2].v) {
		wf->smp[2].v = v;
		wf->smp[2].t = t;
	}

	/* Expire and update smp as necessary. */
	if (t - wf->smp[0].t > wf->len) {
		/* The best estimate hasn't been updated for an entire window, so
		   promote second and third best smp. */
		wf->smp[0] = wf->smp[1];
		wf->smp[1] = wf->smp[2];
		wf->smp[2].v = v;
		wf->smp[2].t = t;

		/* Need to iterate one more time.  Check if the new best estimate
		   is outside the window as well, since it may also have been
		   recorded a long time ago.  Don't need to iterate once more
		   since we cover that case at the beginning of the method. */
		if (t - wf->smp[0].t > wf->len) {
			wf->smp[0] = wf->smp[1];
			wf->smp[1] = wf->smp[2];
		}
		return;
	}

	if (wf->smp[1].v == wf->smp[0].v && t - wf->smp[1].t > wf->len >> 2) {
		/* A quarter of the window has passed without a better sample, so
		   the second-best estimate is taken from the second quarter of
		   the window. */
		wf->smp[2].v = v;
		wf->smp[2].t = t;
		wf->smp[1] = wf->smp[2];
		return;
	}

	if (wf->smp[2].v == wf->smp[1].v && t - wf->smp[2].t > wf->len >> 1) {
		/* We've passed a half of the window without a better estimate, so
		   take a third-best estimate from the second half of the
		   window. */
		wf->smp[2].v = v;
		wf->smp[2].t = t;
	}
}

static inline uint64_t wf_get_best(struct wf *wf)
{
	return wf->smp[0].v;
}

#endif /* _HAPROXY_WINDOW_FILTER_H */
