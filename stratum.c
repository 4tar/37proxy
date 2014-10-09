/* Copyright 37pool.com. All rights reserved.
 *
 * Maintainer:
 *     Huang Le <4tar@37pool.com>
 *
 * The software is published under GNU Affero General Public License version 3,
 * or GNU AGPL v3.  The GNU AGPL is based on the GNU GPL, but has an additional
 * term to allow users who interact with the licensed software over a network to
 * receive the source for that program.  For more information, please refer to:
 *
 *     http://www.gnu.org/licenses/agpl.html
 *     http://www.gnu.org/licenses/why-affero-gpl.html
 *
 * WARN: THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#ifdef WIN32
#define alloca		_alloca
#define snprintf	_snprintf
#else
#include <alloca.h>
#endif
#include <jansson.h>
#include "defs.h"
#include "stratum.h"

extern const char *app_name;

/* caller ensures the buf has enough room for subscribe & authorize requests */
int stratum_init( stratum_ctx *sctx, char *buf, const char* user,
	const char* passwd )
{
	if (!sctx->cx)
		memset(sctx, 0, sizeof(*sctx));

	ASSERT(buf && user && passwd);

	sctx->isServer = 1;
	sctx->msgid = 3;
	sctx->authorized = 0;

	return sprintf(buf,
		"{\"id\":1,\"method\":\"mining.subscribe\",\"params\":[\"%s/%g\"]}"
		"\n"
		"{\"id\":2,\"method\":\"mining.authorize\",\"params\":[\"%s\",\"%s\"]}"
		"\n"
		,
		app_name, (double)PROXY_VER, user, passwd);
}

int stratum_create_share( stratum_ctx *sctx, char *share, const char *miner,
	const char *jobid, const char *xn2, const char *ntime, const char* nonce )
{
	int len = sprintf(share,
		"{\"method\":\"mining.submit\","
		"\"params\":[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"],"
		"\"id\":%u}\n",
		miner, jobid, xn2, ntime, nonce, sctx->msgid++);
	if (!sctx->msgid)
		sctx->msgid = 3;

	return len;
}

int stratum_build_reconnect( stratum_ctx *sctx, char *reconn )
{
	miner_ctx *mx = sctx->cx;
	proxy_config *pxx = mx->pxx;
	return sprintf(reconn,
		"{\"method\":\"client.reconnect\","
		"\"params\":[\"%s\",%hu],\"id\":null}\n",
		pxx->outip[0] ? pxx->outip : mx->bind,
		pxx->outport ? pxx->outport : pxx->port);
}

static const char *get_session_id( json_t *val, char *sid, size_t size )
{
	json_t *arr_val;
	int i, n;
	const char *s;

	arr_val = json_array_get(val, 0);
	if (!arr_val || !json_is_array(arr_val))
		return NULL;

	n = (int)json_array_size(arr_val);
	for (i = 0; i < n; ++i) {
		json_t *arr = json_array_get(arr_val, i);
		if (!arr || !json_is_array(arr))
			break;

		s = json_string_value(json_array_get(arr, 0));
		if (!s)
			continue;

		if (!strcmp(s, "mining.notify")) {
			size_t len;
			s = json_string_value(json_array_get(arr, 1));
			if (s && (len = strlen(s)) && len < size) {
				memcpy(sid, s, len + 1);
				return sid;
			}
			return NULL;
		}
	}

	return NULL;
}

static unsigned int get_extranonce1( json_t *val, char *xn1, size_t size )
{
	size_t len;
	const char *s = json_string_value(json_array_get(val, 1));
	if (!s || !(len = strlen(s)) || (len % 2) || len >= size)
		return 0;
	memcpy(xn1, s, len + 1);
	return (unsigned int)len / 2;
}

static json_t *get_result( json_t *val )
{
	json_t *res_val = json_object_get(val, "error");
	if (res_val && !json_is_null(res_val)) {
		char *err = json_dumps(res_val, 0);
		pr_warn("JSON-RPC result error: %s", err);
		free(err);
		return NULL;
	}

	res_val = json_object_get(val, "result");
	if (!res_val || (!json_is_true(res_val) && !json_is_array(res_val))) {
		pr_warn("JSON-RPC result not true");
		return NULL;
	}

	return res_val;
}

static int setup_context( stratum_ctx *sctx, json_t *val )
{
	json_t *res_val;

	res_val = json_object_get(val, "id");
	if (!res_val || json_integer_value(res_val) != 1) {
		pr_err("Stratum subscribe rep error: no response");
		return -1;
	}

	if (!(res_val = get_result(val)))
		return -2;

	if (!get_session_id(res_val, sctx->sid, sizeof(sctx->sid))) {
		pr_err("Stratum subscribe rep error: invalid session id");
		return -4;
	}

	sctx->xn1size = get_extranonce1(res_val, sctx->xn1, sizeof(sctx->xn1));
	if (!sctx->xn1size) {
		pr_err("Stratum subscribe rep error: invalid extranonce1");
		return -5;
	}

	sctx->xn2size = (int)json_integer_value(json_array_get(res_val, 2));
	if (sctx->xn2size <= 0 || sctx->xn2size > 100) {
		pr_err("Stratum subscribe rep error: invalid extranonce2size");
		return -6;
	}

	return 0;
}

int parse_authorize_result( stratum_ctx *sctx, json_t *val )
{
	json_t *res_val;

	res_val = json_object_get(val, "id");
	if (!res_val || json_integer_value(res_val) != 2) {
		pr_err("Stratum authorize error: no response");
		return -1;
	}

	if (!(res_val = get_result(val)))
		return -2;

	sctx->authorized = 1;

	return 0;
}

static int parse_submit_response( stratum_ctx *sctx, json_t *val,
	unsigned long long id )
{
	if (!(get_result(val))) {
		pool_ctx *px = sctx->cx;
		if (px) {
			pr_warn("Pool %s/%s:%hu refuse share submission %llu",
				px->conf->host, px->addr, px->conf->port, id);

			sctx->sdiff -= sctx->diff;
			++sctx->denyCount;
		}
	}

	return 0;
}

static int check_coinbase( stratum_ctx *sctx, unsigned char *coinbase,
	unsigned int cbsize )
{
	int i;
	uint16_t pos;
	uint64_t len, total, target, amount, script_len;
	int found_target = 0, ret = -4;
	pool_config *conf;

	if (cbsize < 62 || cbsize > 1024) {
		pr_err("Coinbase check: invalid length: %u", cbsize);
		return -1;
	}
	pos = 4;

	if (coinbase[pos] != 1) {
		pr_err("Coinbase check: multiple inputs: 0x%02x", coinbase[pos]);
		return -2;
	}
	pos += 37;

	if (coinbase[pos] < 2 || coinbase[pos] > 100) {
		pr_err("Coinbase check: invalid input script sig length: 0x%02x",
			coinbase[pos]);
		return -3;
	}
	pos += 1 + coinbase[pos] + 4;

	if (cbsize <= pos) {
incomplete_cb:
		pr_err("Coinbase check: incomplete coinbase for payout check");
		return ret;
	}

	total = target = 0;

	i = varint_decode(coinbase + pos, cbsize - pos, &len);
	if (!i) {
		ret = -5;
		goto incomplete_cb;
	}
	pos += i;

	if (likely(sctx->cx))
		conf = ((pool_ctx *)(sctx->cx))->conf;
	else
		conf = NULL;

	while (len-- > 0) {
		char addr[64];

		if ((uint16_t)cbsize <= pos + 8) {
			ret = -6;
			goto incomplete_cb;
		}

		amount = upk_u64le(coinbase, pos);
		pos += 8;

		total += amount;

		i = varint_decode(coinbase + pos, cbsize - pos, &script_len);
		if (!i || cbsize <= pos + i + script_len) {
			ret = -7;
			goto incomplete_cb;
		}
		pos += i;

		i = script_to_address(addr, sizeof(addr), coinbase + pos,
				(unsigned int)script_len, 0);
		if (i && i <= sizeof(addr)) {
			if (likely(conf) && !(i = strcmp(addr, conf->cbaddr))) {
				found_target = 1;
				target += amount;
			}
			pr_info("Coinbase output: %10llu -- %34s%c", amount, addr,
				i ? '\0' : '*');
		} else {
			char *hex = addr;
			if (script_len * 2 >= sizeof(addr))
				hex = alloca(script_len * 2 + 1);
			bin2hex(hex, coinbase + pos, (size_t)script_len, 0);
			pr_info("Coinbase output: %10llu PK %34s", amount, hex);
		}

		pos += (unsigned int)script_len;
	}
	if (likely(conf) && total < conf->cbtotal) {
		pr_err("Coinbase check: lopsided total output amount = %llu, "
			"expecting >=%llu", total, conf->cbtotal);
		return -8;
	}
	if (likely(conf) && conf->cbaddr[0]) {
		if (conf->cbperc && 
			!(total && (float)((double)target / total) >= conf->cbperc)) {
			pr_err("Coinbase check: lopsided target/total = %g(%llu/%llu), "
				"expecting >=%g", (total ? (double)target / total : 0),
				target, total, conf->cbperc);
			return -9;
		} else if (!found_target) {
			pr_err("Coinbase check: not found any target addr");
			return -10;
		}
	}

	pos += 4;
	if (cbsize < pos) {
		pr_err("Coinbase check: No room for locktime");
		return -11;
	} else if (cbsize > pos) {
		pr_err("Coinbase check: extra data %u bytes", cbsize - pos);
		return -12;
	}

	pr_debug("Coinbase: (size, target, total) = (%u, %llu, %llu)", cbsize,
		target, total);

	return 0;
}

int parse_job( stratum_ctx *sctx, json_t *val )
{
	const char *s;
	unsigned char cb[256], *p;
	unsigned int len;

	if (!val || !json_is_array(val) || json_array_size(val) != 9 ||
		!json_is_boolean(json_array_get(val, 8))) {
		pr_err("Parse job error: no or invalid params");
		return -1;
	}

	s = json_string_value(json_array_get(val, 1));
	if (!s || 64 != strlen(s)) {
		pr_err("Parse job error: invalid prevhash");
		return -2;
	}

	s = json_string_value(json_array_get(val, 0));
	if (!s || !(len = (unsigned int)strlen(s)) || len >= sizeof(sctx->jobid)) {
		pr_err("Parse job error: invalid job id");
		return -3;
	}
	if (strcmp(sctx->jobid, s)) {
		sctx->jobUpdated = 1;
		memcpy(sctx->jobid, s, len + 1);
	}

	s = json_string_value(json_array_get(val, 7));
	if (!s || 8 != strlen(s)) {
		pr_err("Parse job error: invalid ntime");
		return -4;
	}
	hex2bin(cb, s, 8);
	sctx->ntime = be32toh(*(uint32_t *)cb);

	s = json_string_value(json_array_get(val, 2));
	if (!s || !(len = (unsigned int)strlen(s)) || len % 2) {
		pr_err("Parse job error: invalid coinbase first half");
		return -5;
	}
	hex2bin(cb, s, len);
	p = cb + len / 2 + sctx->xn1size + sctx->xn2size;

	s = json_string_value(json_array_get(val, 3));
	if (!s || !(len = (unsigned int)strlen(s)) || len % 2) {
		pr_err("Parse job error: invalid coinbase second half");
		return -6;
	}
	hex2bin(p, s, len);

	if (check_coinbase(sctx, cb, (unsigned int)(p - cb) + len / 2))
		return -7;

	return 0;
}

int get_diff( stratum_ctx *sctx, json_t *val )
{
	double diff;

	if (!val || !json_is_array(val) || !(val = json_array_get(val, 0))) {
		pr_err("Parse set_difficulty error: no params");
		return -1;
	}

	if (!json_is_number(val)) {
		pr_err("Parse set_difficulty error: not a number");
		return -2;
	}

	diff = sctx->diff;
	if (json_is_integer(val))
		sctx->diff = (double)json_integer_value(val);
	else
		sctx->diff = json_real_value(val);
	if (sctx->diff <= 0) {
		pr_err("Parse set_difficulty error: invalid diff");
		return -3;
	}

	if (diff != sctx->diff)
		sctx->diffUpdated = 1;

	return 0;
}

static int do_reconnect( stratum_ctx *sctx, json_t *val )
{
	pool_ctx *px;
	const char *s;
	size_t len;
	int port;

	if (!val || !json_is_array(val) || 2 != json_array_size(val)) {
		pr_err("Reconnect req error: invalid params");
		return -1;
	}

	s = json_string_value(json_array_get(val, 0));
	if (!s || !(len = strlen(s)) || len >= sizeof(px->addr)) {
		pr_err("Reconnect req error: invalid ip");
		return -2;
	}

	port = (int)json_integer_value(json_array_get(val, 1));
	if (port < 0 || port > 65535) {
		pr_err("Reconect req error: invalid port");
		return -3;
	}

	px = sctx->cx;
	memcpy(px->addr, s, len + 1);
	px->conf->port = port;

	return 0;
}

static int show_message( stratum_ctx *sctx, json_t *val )
{
	pool_ctx *px;
	size_t len;
	const char *msg;

	if (!val) {
		pr_err("Retrieve message error: no params");
		return -1;
	}

	if (json_is_array(val))
		msg = json_string_value(json_array_get(val, 0));
	else
		msg = json_string_value(val);
	if (!msg || !(len = strlen(msg)) || len > 1024) {
		pr_err("Retrieve message error: null or too long message");
		return -2;
	}

	px = sctx->cx;
	pr_info("Message from pool %s/%s:%hu:\n\n*** *******\n%s\n******* ***\n\n",
		px->conf->host, px->addr, px->conf->port, msg);

	/* A response should be sent according to JSON-RPC call standard,
	   but we can safely ignore it since no pool would care:) */

	return 0;
}

static int parse_share( stratum_ctx *sctx, json_t *val )
{
	miner_ctx *mx;
	const char *miner, *jobid, *xn2, *ntime, *nonce;
	char xn[64];
	int ret = 0;

	if (!val || !json_is_array(val) || 5 != json_array_size(val)) {
		pr_err("Parse share error: no or invalid params");
		return -1;
	}

	miner = json_string_value(json_array_get(val, 0));
	jobid = json_string_value(json_array_get(val, 1));
	xn2 = json_string_value(json_array_get(val, 2));
	ntime = json_string_value(json_array_get(val, 3));
	nonce = json_string_value(json_array_get(val, 4));

	if (!miner || !jobid || !xn2 || !ntime || !nonce) {
		pr_err("Parse share error: lack of share elements");
		return -2;
	}
	if (sizeof(xn) == snprintf(xn, sizeof(xn), "%s%s", sctx->xn1, xn2)) {
		pr_err("Parse share error: too long extranonce");
		return -3;
	}

	sctx->sdiff += sctx->diff;
	++sctx->shareCount;

	if ((mx = sctx->cx))
		mx->px->ss(mx, miner, jobid, xn, ntime, nonce);

	sctx->jobLen += sprintf(mx->outbuf + sctx->jobLen,
		"{\"id\":%u,\"result\":true,\"error\":null}\n",
		sctx->msgid);

	return ret;
}

static int send_txnlist( stratum_ctx *sctx, json_t *val )
{
	/* no txn list support in this edition. 
	   Instead of sending the below error response, just ignore now. */
	/*
	sctx->jobLen += sprintf(mx->outbuf + sctx->jobLen,
		"{\"id\":%d,\"result\":false,\"error\":[26,\"no-txlist\",null]}\n",
		sctx->msgid);
	*/

	return 0;
}

static int parse_subscribe( stratum_ctx *sctx, json_t *val )
{
	int len;
	const char *msg;
	miner_ctx *mx = (miner_ctx *)sctx->cx;

	if (!val || !json_is_array(val) ||
		!(msg = json_string_value(json_array_get(val, 0)))) {
		pr_err("Stratum subscribe req error: no params");
		return -1;
	}

	if (!(len = (int)strlen(msg)) || len >= sizeof(mx->agent)) {
		pr_err("Stratum subscribe req error: too long agent info");
		return -2;
	}

	memcpy(mx->agent, msg, len + 1);

	sctx->jobLen += sprintf(mx->outbuf + sctx->jobLen,
		"{\"id\":1,\"result\":[[[\"mining.set_difficulty\",\"\"],"
		"[\"mining.notify\",\"%s\"]],\"%s\",%d],\"error\":null}\n"
		"%s%s",
		sctx->sid, sctx->xn1, sctx->xn2size, sctx->diffstr, sctx->jobstr);

	return 0;
}

static int parse_authorize( stratum_ctx *sctx, json_t *val )
{
	int len;
	const char *msg;
	miner_ctx *mx = (miner_ctx *)sctx->cx;

	if (!val || !json_is_array(val) ||
		!(msg = json_string_value(json_array_get(val, 0)))) {
		pr_err("Stratum authorize req error: no params");
		return -1;
	}

	if (!(len = (int)strlen(msg)) || len >= sizeof(mx->miner)) {
		pr_err("Stratum subscribe req error: too long miner name");
		return -2;
	}

	memcpy(mx->miner, msg, len + 1);

	sctx->jobLen += sprintf(mx->outbuf + sctx->jobLen,
		"{\"id\":2,\"result\":true,\"error\":null}\n");

	sctx->authorized = 1;

	return 0;
}


#define copy_message(str, len, buf, size) { \
	memcpy(str, buf, size - 1);	len = size; \
	str[size - 1] = '\n', str[size] = '\0'; }

int stratum_parse( stratum_ctx *sctx, char *buf, unsigned int len )
{
	char *c;
	json_t *val = NULL, *meth_val, *id_val;
	json_error_t err;
	const char *method;
	unsigned int size;
	unsigned long long id;
	int r = 0;

	for (; !r && len > 0 && (c = strchr(buf, '\n')); len -= size, buf = c) {
		size = (unsigned int)(c - buf + 1);
		if (size > len)
			break;

		*c++ = '\0';
		if (unlikely(!sctx->cx))
			pr_debug("stratum_parse: %s", buf);
		else if (sctx->isServer) {
			pool_ctx *px = sctx->cx;
			pr_debug("<%s/%s:%hu: %s", px->conf->host, px->addr,
				px->conf->port, buf);
		} else {
			miner_ctx *mx = sctx->cx;
			pr_debug("<%s/%s@%s:%hu: %s", mx->miner, mx->agent,
				mx->addr, mx->port, buf);
		}

		val = json_loads(buf, 0, &err);
		if (unlikely(!val)) {
			pr_err("JSON decode failed(%d): %s", err.line, err.text);
			r = -1;
			break;
		}

		meth_val = json_object_get(val, "method");
		if (meth_val) {
			method = json_string_value(meth_val);
			if (unlikely(!method)) {
				pr_err("JSON-RPC error: null method");
				r = -2;
			} else if (sctx->isServer) {
				if (!strcmp(method, "mining.notify")) {
					if (parse_job(sctx, json_object_get(val, "params")))
						r = -3;
					else if (sctx->jobUpdated && sctx->jobstr)
						copy_message(sctx->jobstr, sctx->jobLen, buf, size);
				} else if (!strcmp(method, "mining.set_difficulty")) {
					if (get_diff(sctx, json_object_get(val, "params")))
						r = -4;
					else if (sctx->diffUpdated && sctx->diffstr)
						copy_message(sctx->diffstr, sctx->diffLen, buf, size);
				} else if (!strcmp(method, "client.reconnect")) {
					do_reconnect(sctx, json_object_get(val, "params"));
					r = -5;
				} else if (!strcmp(method, "mining.set_extranonce")) {
					/* no set_extranonce support in this edition. */
				} else if (!strcmp(method, "client.show_message")) {
					if (show_message(sctx, json_object_get(val, "params")))
						r = -7;
				} else if (!strcmp(method, "client.get_version")) {
					/* no get_version support in this edition.  And we always
					   send UA during initialization so a normal pool should
					   not ask for it again. */
				} else {
					pr_err("JSON-RPC pool error: unknown method '%s'", method);
					r = -9;
				}
			} else {
				id_val = json_object_get(val, "id");
				if (!id_val || json_is_null(id_val) ||
					!(sctx->msgid = (unsigned int)json_integer_value(id_val))) {
					pr_err("JSON-RPC miner error: null id");
					r = -10;
				} else if (!strcmp(method, "mining.submit")) {
					if (parse_share(sctx, json_object_get(val, "params")))
						r = -11;
				} else if (!strcmp(method, "mining.get_transactions")) {
					if (send_txnlist(sctx, json_object_get(val, "params")))
						r = -12;
				} else if (!strcmp(method, "mining.subscribe")) {
					if (parse_subscribe(sctx, json_object_get(val, "params")))
						r = -13;
				} else if (!strcmp(method, "mining.authorize")) {
					if (parse_authorize(sctx, json_object_get(val, "params")))
						r = -14;
				} else {
					pr_err("JSON-RPC miner error: unknown method '%s'", method);
					r = -15;
				}
			}
		} else if (sctx->isServer) {
			id_val = json_object_get(val, "id");
			if (!id_val || json_is_null(id_val)) {
				pr_err("JSON-RPC response error: null id");
				r = -16;
			} else if ((id = json_integer_value(id_val)) >= sctx->msgid) {
				pr_err("JSON-RPC response error: wrong id");
				r = -17;
			} else if (id > 2) {
				if (parse_submit_response(sctx, val, id))
					r = -18;
			} else if (id == 1) {
				if (setup_context(sctx, val))
					r = -19;
			} else if (id == 2) {
				if (parse_authorize_result(sctx, val))
					r = -20;
			} else
				ASSERT(0);
		} else {
			pr_err("JSON-RPC error: unknown message");
			r = -21;
		}

		json_decref(val);
	}

	return r ? r : len;
}
