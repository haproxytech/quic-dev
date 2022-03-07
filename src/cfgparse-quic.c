#include <haproxy/api.h>
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
