#include <haproxy/api.h>
#include <haproxy/cfgparse.h>
#include <haproxy/global-t.h>
#include <haproxy/listener.h>
#include <haproxy/proxy-t.h>
#include <haproxy/tools.h>

static int bind_parse_quic_force_retry(char **args, int cur_arg, struct proxy *px, struct bind_conf *conf, char **err)
{
	conf->quic_force_retry = 1;
	return 0;
}

/* Parse "quic-max-idle-timeout" keyword */
static int bind_parse_quic_max_idle_timeout(char **args, int cur_arg, struct proxy *px,
                                            struct bind_conf *conf, char **err)
{
	const char *res, *name;
	unsigned timeout;

	name = args[cur_arg++];
	res = parse_time_err(args[cur_arg], &timeout, TIME_UNIT_MS);
	if (res == PARSE_TIME_OVER) {
		memprintf(err, "timer overflow in argument '%s' to '%s' "
		          "(maximum value is 2147483647 ms or ~24.8 days)", args[cur_arg], name);
		return -1;
	}
	else if (res == PARSE_TIME_UNDER) {
		memprintf(err, "timer underflow in argument '%s' to '%s' "
		          "(minimum non-null value is 1 ms)", args[cur_arg], name);
		return -1;
	}
	else if (res) {
		memprintf(err, "unexpected character '%c' in '%s'", *res, name);
		return -1;
	}

	conf->quic_params.max_idle_timeout = timeout;

	return 0;
}

static struct bind_kw_list bind_kws = { "QUIC", { }, {
	{ "quic-force-retry", bind_parse_quic_force_retry, 0 },
	{ "quic-max-idle-timeout", bind_parse_quic_max_idle_timeout, 1 },
	{ NULL, NULL, 0 },
}};

INITCALL1(STG_REGISTER, bind_register_keywords, &bind_kws);

static int cfg_parse_quic_conn_buf_limit(char **args, int section_type,
                                         struct proxy *curpx,
                                         const struct proxy *defpx,
                                         const char *file, int line, char **err)
{
	unsigned int arg = 0;

	if (too_many_args(1, args, err, NULL))
		return -1;

	if (*(args[1]) != 0)
		arg = atoi(args[1]);

	if (arg < 1) {
		memprintf(err, "'%s' expects a positive integer.", args[0]);
		return -1;
	}

	global.tune.quic_streams_buf = arg;

	return 0;
}

static struct cfg_kw_list cfg_kws = {ILH, {
	{ CFG_GLOBAL, "tune.quic.conn-buf-limit", cfg_parse_quic_conn_buf_limit },
	{ 0, NULL, NULL }
}};

INITCALL1(STG_REGISTER, cfg_register_keywords, &cfg_kws);
