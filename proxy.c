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

#include "defs.h"
#ifndef WIN32
#include <netinet/in.h>  /* INET6_ADDRSTRLEN */
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef INET6_ADDRSTRLEN
# define INET6_ADDRSTRLEN 63
#endif

typedef struct {
	uv_getaddrinfo_t gar_req;
	pool_config *conf;
} gar_state;

static void pool_resolved( uv_getaddrinfo_t *req, int status,
	struct addrinfo *addrs )
{
	gar_state *state;
	pool_config *conf;
	struct addrinfo *ai;
	const void *addrv;
	uv_loop_t *loop;
	pool_ctx *px;
	int n;
	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	} s;

	state = CONTAINER_OF(req, gar_state, gar_req);
	conf = state->conf;
	loop = conf->conf->loop;

	if (status) {
		pr_err("getaddrinfo(%s): %s", conf->host, uv_strerror(status));
		uv_freeaddrinfo(addrs);
		return;
	}

	for (n = 0, ai = addrs; ai != NULL; ai = ai->ai_next)
		if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6)
			++n;
	if (!n) {
		pr_err("%s has no IPv4/6 addresses", conf->host);
		uv_freeaddrinfo(addrs);
		return;
	}

	conf->px = xmalloc(sizeof(*conf->px));
	memset(conf->px, 0, sizeof(*conf->px));
	n = rand() % n;

	for (ai = addrs; ai != NULL; ai = ai->ai_next) {
		if (ai->ai_family == AF_INET) {
			s.addr4 = *(const struct sockaddr_in *)ai->ai_addr;
			s.addr4.sin_port = htons(conf->port);
			addrv = &s.addr4.sin_addr;
		} else if (ai->ai_family == AF_INET6) {
			s.addr6 = *(const struct sockaddr_in6 *)ai->ai_addr;
			s.addr6.sin6_port = htons(conf->port);
			addrv = &s.addr6.sin6_addr;
		} else
			continue;

		if (n-- == 0) {
			px = conf->px;
			uv_inet_ntop(s.addr.sa_family, addrv, px->addr, sizeof(px->addr));
			px->conf = conf;
			px->loop = loop;

			pool_connect(px, &s.addr);
			break;
		}
	}

	uv_freeaddrinfo(addrs);
}

extern void miner_connected( uv_stream_t *proxy_tcp_handle, int status );

pool_ctx *pool_pickup( proxy_config *conf )
{
	pool_ctx *px, *cpx;
	unsigned short i;

	for (px = NULL, i = 0; i < conf->count; ++i) {
		cpx = conf->pools[i].px;
		if (cpx->status == p_working && cpx->count < countof(cpx->mx) &&
				(!px || (px->conf->priority > cpx->conf->priority) ||
					(px->conf->priority == cpx->conf->priority &&
						px->count > cpx->count)))
			px = cpx;
	}

	return px;
}

void attach_miner_to_pool( pool_ctx *px, miner_ctx *mx )
{
	unsigned short i, j;

	mx->px = px;

	for (i = px->count, j = 0;
		px->mx[i] && j < countof(px->mx);
		++j, i = (i + 1) % countof(px->mx));
	px->mx[i] = mx;
	++px->count;

	memcpy(&mx->sctx, &px->sctx, STRATUM_SESSION_SIZE);
	memset(STRATUM_SESSION_POS(&mx->sctx), 0,
		sizeof(mx->sctx) - STRATUM_SESSION_SIZE);

	mx->sctx.xn1size += 2;
	mx->sctx.xn2size -= 2;
	mx->sctx.isServer = mx->sctx.authorized = 0;
	mx->sctx.jobUpdated = mx->sctx.diffUpdated = 0;
	mx->sctx.sdiff = mx->sctx.shareCount = mx->sctx.denyCount = 0;
	mx->sctx.jobLen = 0;
#ifdef WORDS_BIGENDIAN
	sprintf(&mx->sctx.xn1[px->sctx.xn1size * 2], "%04x", i);
#else
	sprintf(&mx->sctx.xn1[px->sctx.xn1size * 2], "%02x%02x", i & 0xff, i >> 8);
#endif
	mx->sctx.cx = mx;

	mx->pxreconn = 0;
	mx->writeShareLen = mx->lastShareLen = mx->shareLen = 0;
}

void detach_miner_from_pool( miner_ctx *mx )
{
	unsigned short i;
	pool_ctx *px = mx->px;

	mx->px = NULL;

	hex2bin((unsigned char *)&i, &mx->sctx.xn1[px->sctx.xn1size * 2], 4);
	ASSERT(px->mx[i] == mx);
	px->mx[i] = NULL;
	--px->count;
}

int proxy_run( proxy_config *conf )
{
	struct addrinfo hints;
	gar_state p_state[8];
	int i, err;
	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	} s;

	if (!uv_ip4_addr(conf->host, conf->port, &s.addr4));
	else if (!(err = uv_ip6_addr(conf->host, conf->port, &s.addr6)));
	else {
		pr_err("Invalid proxy listen addr: %s:%hu", conf->host, conf->port);
		return err;
	}

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = 0;

	for (i = 0; i < (int)conf->count; ++i) {
		p_state[i].conf = &conf->pools[i];
		err = uv_getaddrinfo(conf->loop, &p_state[i].gar_req, pool_resolved,
				conf->pools[i].host, NULL, &hints);
		if (err) {
			pr_err("getaddrinfo: %s", uv_strerror(err));
			return err;
		}
	}

	uv_tcp_init(conf->loop, &conf->handle.tcp);
	if ((err = uv_tcp_bind(&conf->handle.tcp, &s.addr, 0))) {
		pr_err("uv_tcp_bind(%s:%hu): %s", conf->host, conf->port,
			uv_strerror(err));
		return err;
	}
	if ((err = uv_listen(&conf->handle.stream, 128, miner_connected))) {
		pr_err("uv_tcp_bind(%s:%hu): %s", conf->host, conf->port,
			uv_strerror(err));
		return err;
	}
	pr_info("Listening on %s:%hu", conf->host, conf->port);

	if (uv_run(conf->loop, UV_RUN_DEFAULT))
		abort();

	uv_loop_delete(conf->loop);

	for (i = 0; i < (int)conf->count; ++i)
		free(conf->pools[i].px);

	return 0;
}
