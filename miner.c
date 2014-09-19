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
#include <stdlib.h>
#include <string.h>

static void miner_close_done( uv_handle_t *handle )
{
	miner_ctx *mx = (miner_ctx *)handle->data;
	ASSERT(handle == &mx->handle.h);

	pr_info("Miner %s:%hu connection closed, submitted shares %d/%g",
		mx->addr, mx->port, mx->sctx.shareCount, mx->sctx.sdiff);

	detach_miner_from_pool(mx->px, mx);
	free(mx);
}

static void miner_close( miner_ctx *mx )
{
	if (mx->px)
		uv_close(&mx->handle.h, miner_close_done);
	else {
		uv_close(&mx->handle.h, NULL);
		free(mx);
	}
}

static void miner_alloc( uv_handle_t *handle, size_t size, uv_buf_t *buf )
{
	miner_ctx *mx = CONTAINER_OF(handle, miner_ctx, handle);
	buf->base = mx->buf + mx->pos;
	buf->len = sizeof(mx->buf) - mx->pos;
}

static void miner_write_done( uv_write_t *req, int status );

static void miner_read_done( uv_stream_t *stream, ssize_t nread,
	const uv_buf_t *buf )
{
	int left_bytes;

	miner_ctx *mx = CONTAINER_OF(stream, miner_ctx, handle.stream);
	ASSERT(mx->buf + mx->pos == buf->base);

	if (nread < 0) {
		pr_debug("Miner %s/%s@%s:%hu read error: %s", mx->miner, mx->agent,
			mx->addr, mx->port, uv_strerror(nread));
		miner_close(mx);
		return;
	}

	mx->pos += nread;

	if (mx->sctx.outbufLen) {
		pr_warn("Miner %s/%s@%s:%hu still writting...", mx->miner, mx->agent,
			mx->addr, mx->port);
		return;
	}

	mx->buf[mx->pos] = '\0';
	left_bytes = stratum_parse(&mx->sctx, mx->buf, mx->pos);
	if (left_bytes < 0 || left_bytes >= sizeof(mx->buf)) {
		pr_err("Disconnect miner %s/%s@%s:%hu", mx->miner, mx->agent, mx->addr,
			mx->port);
		miner_close(mx);
		return;
	}

	if (left_bytes && left_bytes != mx->pos)
		memmove(mx->buf, mx->buf + mx->pos - left_bytes, left_bytes);
	mx->pos = left_bytes;

	if (mx->sctx.outbufLen) {
		uv_buf_t buf;
		buf.base = mx->outbuf;
		buf.len = mx->sctx.outbufLen;

		mx->wpos = mx->pos;
		uv_write(&mx->write_req[0], &mx->handle.stream, &buf, 1, miner_write_done);

		pr_debug(">%s/%s@%s:%hu: %s", mx->miner, mx->agent, mx->addr, mx->port,
			mx->outbuf);
	}
}

static void miner_write_done( uv_write_t *req, int status )
{
	miner_ctx *mx = CONTAINER_OF(req, miner_ctx, write_req[0]);
	pool_ctx *px, *npx;
	int do_switch;
	uv_buf_t buf;

	if (status) {
		pr_warn("Miner %s/%s@%s:%hu write error", mx->miner, mx->agent,
			mx->addr, mx->port);
		miner_close(mx);
		return;
	}

	mx->sctx.outbufLen = 0;
	if (mx->wpos != mx->pos) {
		buf.base = mx->buf + mx->pos;
		miner_read_done(&mx->handle.stream, 0, &buf);
		return;
	}

	px = mx->px;
	if ((px->status == p_disconnected || px->status == p_disconnected) &&
			uv_now(px->loop) - px->disc_time > 10 * 1000)
		do_switch = 1;
	else if (px->scount < 10 && (npx = pool_pickup(mx->pxx)) && px != npx &&
				(px->conf->priority > npx->conf->priority ||
					(px->conf->priority == npx->conf->priority &&
						px->count > npx->count + 10))) {
		do_switch = 2;
		++px->scount;
	} else
		do_switch = 0;
	if (do_switch) {
		buf.base = mx->outbuf;
		buf.len = mx->sctx.outbufLen =
			stratum_build_reconnect(&mx->sctx, mx->outbuf);

		uv_write(&mx->write_req[0], &mx->handle.stream, &buf, 1, NULL);

		pr_debug("Try switching miner %s/%s@%s:%hu from %s/%s:%hu to %s/%s:%hu",
			mx->miner, mx->agent, mx->addr, mx->port,
			px->conf->host, px->addr, px->conf->port,
			npx->conf->host, npx->addr, npx->conf->port);
	}
}

void miner_connected( uv_stream_t *proxy_tcp_handle, int status )
{
	proxy_config *pxx;
	pool_ctx *px;
	miner_ctx *mx;
	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	} s;
	int len = sizeof(s);

	pxx = CONTAINER_OF(proxy_tcp_handle, proxy_config, handle.tcp);

	if (status) {
		pr_warn("miner_connected error: %s", uv_strerror(status));
		return;
	}

	mx = xmalloc(sizeof(*mx));

	if ((status = uv_tcp_init(pxx->loop, &mx->handle.tcp))) {
		free(mx);
		pr_err("uv_tcp_init() failed: %s", uv_strerror(status));
		return;
	}
	if ((status = uv_accept(proxy_tcp_handle, &mx->handle.stream))) {
		miner_close(mx);
		pr_err("uv_accept() failed: %s", uv_strerror(status));
		return;
	}
	if ((status = uv_tcp_getsockname(&mx->handle.tcp, &s.addr, &len))) {
		miner_close(mx);
		pr_err("uv_tcp_getsockname() failed: %s", uv_strerror(status));
		return;
	}
	if (s.addr.sa_family == AF_INET)
		uv_ip4_name(&s.addr4, mx->bind, sizeof(mx->bind));
	else
		uv_ip6_name(&s.addr6, mx->bind, sizeof(mx->bind));
	if ((status = uv_tcp_getpeername(&mx->handle.tcp, &s.addr, &len))) {
		miner_close(mx);
		pr_err("uv_tcp_getpeername() failed: %s", uv_strerror(status));
		return;
	}
	if (s.addr.sa_family == AF_INET) {
		uv_ip4_name(&s.addr4, mx->addr, sizeof(mx->addr));
		mx->port = ntohs(s.addr4.sin_port);
	} else {
		uv_ip6_name(&s.addr6, mx->addr, sizeof(mx->addr));
		mx->port = ntohs(s.addr6.sin6_port);
	}
	mx->miner[0] = mx->agent[0] = '\0';
	mx->pxx = pxx;
	mx->handle.h.data = mx;

	px = pool_pickup(pxx);
	if (!px) {
		pr_err("No pool available, drop miner from %s:%hu",
			mx->addr, mx->port);
		miner_close(mx);
		return;
	}
	attach_miner_to_pool(px, mx);

	mx->sctx.sdiff = mx->sctx.shareCount = 0;
	mx->sctx.cx = mx;
	mx->shareLen = mx->sctx.outbufLen = mx->sctx.isServer = 0;

	mx->pos = 0;
	uv_read_start(&mx->handle.stream, miner_alloc, miner_read_done);

	pr_info("Attach miner from %s:%hu on %s to %s/%s:%hu with xn1=%s",
		mx->addr, mx->port, mx->bind, px->conf->host, px->addr, px->conf->port,
		mx->sctx.xn1);
}
