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
#include <errno.h>
#include <stdio.h>
#include <string.h>

static void pool_timeout( uv_timer_t *timer );

static void pool_broadcast( pool_ctx *px, uv_buf_t buf[], size_t count )
{
	unsigned int i, j;

	if (!px->count)
		return;

	px->scount = 0;

	pr_info("Pool %s/%s:%hu broadcast (%lu %g/%u %s/%u) to %u miners",
		px->conf->host, px->addr, px->conf->port, count,
		px->sctx.diff, px->sctx.diffLen, px->sctx.jobid, px->sctx.jobLen,
		px->count);

	for (i = j = 0; j < px->count && i < countof(px->mx); ++i)
		if (px->mx[i]) {
			miner_ctx *mx = px->mx[i];
			uv_write(&mx->write_req[1], &mx->handle.stream, buf, count, NULL);
			mx->sctx.diff = px->sctx.diff;
			++j;
		}
	ASSERT(j == px->count);
}

static void pool_close_done( uv_handle_t *handle )
{
	pool_ctx *px = (pool_ctx *)handle->data;
	ASSERT(handle == &px->handle.h);

	px->status = p_disconnected;
	pr_info("Pool %s/%s:%hu connection closed", px->conf->host, px->addr,
		px->conf->port);

	if (!uv_is_closing((uv_handle_t *)&px->timer))
		uv_timer_start(&px->timer, pool_timeout, 1000, 0);
}

static void pool_close( pool_ctx *px, int retry )
{
	if (retry)
		uv_timer_stop(&px->timer);
	else
		uv_close((uv_handle_t *)&px->timer, NULL);

	px->status = p_disconnecting;
	px->disc_time = uv_now(px->loop);
	uv_close(&px->handle.h, pool_close_done);
}

static void pool_timeout( uv_timer_t *timer )
{
	pool_ctx *px = CONTAINER_OF(timer, pool_ctx, timer);

	if (px->status == p_initializing || px->status == p_working) {
		pr_err("Pool %s/%s:%hu timeout %d", px->conf->host, px->addr,
			px->conf->port, px->conf->timeout);

		pool_close(px, 1);
	} else
		pool_connect(px, NULL);
}

static void pool_alloc( uv_handle_t *handle, size_t size, uv_buf_t *buf )
{
	pool_ctx *px = CONTAINER_OF(handle, pool_ctx, handle);
	buf->base = px->buf + px->pos;
	buf->len = sizeof(px->buf) - px->pos;
}

static void pool_read_done( uv_stream_t *stream, ssize_t nread,
	const uv_buf_t *buf )
{
	int left_bytes;
	size_t len;
	uv_buf_t bufUpdate[2];

	pool_ctx *px = CONTAINER_OF(stream, pool_ctx, handle.stream);
	ASSERT(px->buf + px->pos == buf->base);

	if (nread < 0) {
		pr_err("Pool %s/%s:%hu disconnected", px->conf->host, px->addr,
			px->conf->port);
		pool_close(px, 1);
		return;
	} else if (!nread) {
		pr_warn("Pool %s/%s:%hu idle", px->conf->host, px->addr,
			px->conf->port);
		return;
	}

	len = px->pos + nread;
	px->buf[len] = '\0';

	left_bytes = stratum_parse(&px->sctx, px->buf, len);
	if (left_bytes < 0 || left_bytes >= sizeof(px->buf)) {
		pr_err("Disconnect pool %s/%s:%hu", px->conf->host, px->addr,
			px->conf->port);
		pool_close(px, 1);
		return;
	}

	if (left_bytes > 0) {
		if (left_bytes != len)
			memmove(px->buf, px->buf + len - left_bytes, left_bytes);
		px->pos = left_bytes;
	} else
		px->pos = 0;

	if (px->status == p_initializing && px->sctx.authorized &&
		px->diff[0] && px->job[0]) {
		px->status = p_working;
		pr_info("Pool %s/%s:%hu start working with stratum context: "
			"xn1 = %d/%s xn2 = %d sid = %s",
			px->conf->host, px->addr, px->conf->port,
			px->sctx.xn1size, px->sctx.xn1, px->sctx.xn2size, px->sctx.sid
		);
	}

	len = 0;
	if (px->sctx.diffUpdated) {
		bufUpdate[len].base = px->diff;
		bufUpdate[len++].len = px->sctx.diffLen;
		px->sctx.diffUpdated = 0;
	}
	if (px->sctx.jobUpdated) {
		bufUpdate[len].base = px->job;
		bufUpdate[len++].len = px->sctx.jobLen;
		px->sctx.jobUpdated = 0;
	}
	if (len)
		pool_broadcast(px, bufUpdate, len);

	uv_timer_start(&px->timer, pool_timeout, px->conf->timeout, 0);
}

void pool_connected( uv_connect_t *req, int status )
{
	pool_ctx *px = CONTAINER_OF(req, pool_ctx, req.conn_req);
	uv_buf_t buf;

	if (status) {
		pr_err("pool_connected(%s/%s:%hu) error: %s", px->conf->host, px->addr,
			px->conf->port, uv_strerror(status));

		px->status = p_disconnected;
		uv_timer_start(&px->timer, pool_timeout, 1000, 0);

		return;
	}

	pr_info("Pool %s/%s:%hu connected", px->conf->host, px->addr, px->conf->port);

	buf.base = px->buf;
	buf.len = stratum_init(&px->sctx, px->buf, px->conf->miner, px->conf->passwd);
	if (px->sctx.cx != px) {
		px->sctx.cx = px;
		px->sctx.diffstr = px->diff;
		px->sctx.jobstr = px->job;
	}

	px->status = p_initializing;
	uv_write(&px->req.write_req, &px->handle.stream, &buf, 1, NULL);

	px->pos = 0;
	uv_read_start(&px->handle.stream, pool_alloc, pool_read_done);
	uv_timer_start(&px->timer, pool_timeout, px->conf->timeout, 0);
}

void pool_connect( pool_ctx *px, struct sockaddr *addr )
{
	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	} s;
	int err;

	if (addr) {
		if ((err = uv_timer_init(px->loop, &px->timer))) {
			pr_err("Initialize timer for pool %s/%s:%hu failed: %s",
				px->conf->host, px->addr, px->conf->port, uv_strerror(err));
			return;
		}
		px->timer.data = px;

		px->sctx.cx = NULL;
		memset(px->mx, 0, sizeof(px->mx));
	} else {
		addr = &s.addr;

		if (!uv_ip4_addr(px->addr, px->conf->port, &s.addr4));
		else if (!(err = uv_ip6_addr(px->addr, px->conf->port, &s.addr6)));
		else {
			uv_close((uv_handle_t *)&px->timer, NULL);

			px->disc_time = 0;
			pr_err("Invalid pool addr: %s/%s:%hu - %s", px->conf->host, px->addr,
				px->conf->port, uv_strerror(err));
			return;
		}
	}

	if ((err = uv_tcp_init(px->loop, &px->handle.tcp))) {
		pr_err("Initialize tcp handle for pool %s/%s:%hu failed: %s",
			px->conf->host, px->addr, px->conf->port, uv_strerror(err));
		uv_timer_start(&px->timer, pool_timeout, 1000, 0);
		return;
	}
	px->handle.tcp.data = px;

	px->status = p_connecting;

	if ((err = uv_tcp_connect(&px->req.conn_req, &px->handle.tcp, addr,
				pool_connected))) {
		px->status = p_disconnected;
		pr_err("uv_tcp_connect %s/%s:%hu error: %s", px->conf->host, px->addr,
			px->conf->port, uv_strerror(err));
		uv_timer_start(&px->timer, pool_timeout, 1000, 0);
		return;
	}

	pr_debug("connecting to %s/%s:%hu", px->conf->host, px->addr,
		px->conf->port);
}

static void share_submitted( uv_write_t *req, int status )
{
	miner_ctx *mx = CONTAINER_OF(req, miner_ctx, write_req[2]);
	pool_ctx *px = mx->px;
	uv_buf_t buf;

	if (status) {
		pr_err("Pool %s/%s:%hu write error", px->conf->host, px->addr,
			px->conf->port);
		pool_close(px, 1);
		return;
	}

	if (mx->lastShareLen == mx->shareLen) {
		mx->shareLen = 0;
		return;
	}

	ASSERT(mx->lastShareLen < mx->shareLen);

	buf.base = mx->share + mx->lastShareLen;
	buf.len = mx->shareLen - mx->lastShareLen;
	mx->lastShareLen = mx->shareLen;
	uv_write(&mx->write_req[2], &px->handle.stream, &buf, 1, share_submitted);
}

void pool_submit_share( miner_ctx *mx, const char *miner, const char* jobid,
		const char *xn, const char *ntime, const char *nonce )
{
	pool_ctx *px = mx->px;
	uv_buf_t buf;

	if (mx->shareLen > sizeof(mx->share) - 128) {
		mx->sctx.sdiff -= mx->sctx.diff;
		--mx->sctx.shareCount;

		pr_warn("Miner %s/%s@%s:%hu submitted too fast, dropping one share",
			mx->miner, mx->agent, mx->addr, mx->port);
		return;
	}

	px->sctx.sdiff += px->sctx.diff;
	if (++px->sctx.shareCount % 1000 == 0)
		pr_info("Pool %s:%s:%hu got %u shares, refused %u, sdiff %g",
			px->conf->host, px->addr, px->conf->port,
			px->sctx.shareCount, px->sctx.denyCount, px->sctx.sdiff);

	buf.base = mx->share + mx->shareLen;
	buf.len = stratum_create_share(&px->sctx, buf.base, miner, jobid,
		&xn[px->sctx.xn1size * 2], ntime, nonce);

	if (mx->shareLen || px->status != p_working)
		mx->shareLen += buf.len;
	else {
		mx->lastShareLen = mx->shareLen;
		uv_write(&mx->write_req[2], &px->handle.stream, &buf, 1,
			share_submitted);
	}
}
