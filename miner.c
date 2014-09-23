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

int miner_clear( miner_ctx *mx )
{
	if (mx->writeShareLen != mx->lastShareLen || mx->sctx.jobLen) {
		if (mx->closing == 2)
			pr_warn("Miner %s/%s@%s:%hu is still here", mx->miner, mx->agent,
				mx->addr, mx->port);
		else
			mx->closing = 2;

		return 1;
	}

	detach_miner_from_pool(mx);

	pr_info("Miner %s/%s@%s:%hu cleared with shares %u/%u/%g",
		mx->miner, mx->agent, mx->addr, mx->port,
		mx->sctx.shareCount, mx->sctx.denyCount, mx->sctx.sdiff);

	free(mx);

	return 0;
}

static void miner_close_done( uv_handle_t *handle )
{
	miner_ctx *mx = (miner_ctx *)handle->data;
	ASSERT(handle == &mx->handle.h);

	if (mx->px)
		miner_clear(mx);
	else
		free(mx);
}

static void miner_close( miner_ctx *mx )
{
	if (mx->closing)
		return;

	mx->closing = 1;
	uv_close(&mx->handle.h, miner_close_done);
}

static void miner_alloc( uv_handle_t *handle, size_t size, uv_buf_t *buf )
{
	miner_ctx *mx = CONTAINER_OF(handle, miner_ctx, handle);
	buf->base = mx->buf + mx->pos;
	buf->len = sizeof(mx->buf) - mx->pos;
}

void miner_write_done( uv_write_t *req, int status );

static void miner_read_done( uv_stream_t *stream, ssize_t nread,
	const uv_buf_t *buf )
{
	int left_bytes;

	miner_ctx *mx = CONTAINER_OF(stream, miner_ctx, handle.stream);
	if (mx->closing)
		return;

	if (nread < 0) {
		pr_debug("Miner %s/%s@%s:%hu read error: %s", mx->miner, mx->agent,
			mx->addr, mx->port, uv_strerror((int)nread));
		miner_close(mx);
		return;
	}

	mx->pos += (unsigned int)nread;

	if (mx->sctx.jobLen) {
		pr_warn("Miner %s/%s@%s:%hu still writting...", mx->miner, mx->agent,
			mx->addr, mx->port);
		return;
	}

	if (strncmp(mx->px->sctx.xn1, mx->sctx.xn1, mx->px->sctx.xn1size * 2)) {
		miner_close(mx);

		pr_warn("Miner %s/%s@%s:%hu context changed: %s -> %s %u",
			mx->miner, mx->agent, mx->addr, mx->port,
			mx->sctx.xn1, mx->px->sctx.xn1, mx->sctx.xn1size);
		return;
	}

	mx->buf[mx->pos] = '\0';
	left_bytes = stratum_parse(&mx->sctx, mx->buf, mx->pos);
	if (left_bytes < 0 || left_bytes >= sizeof(mx->buf)) {
		mx->sctx.jobLen = 0;
		miner_close(mx);

		pr_err("Disconnect miner %s/%s@%s:%hu", mx->miner, mx->agent, mx->addr,
			mx->port);
		return;
	}

	if (left_bytes && left_bytes != mx->pos)
		memmove(mx->buf, mx->buf + mx->pos - left_bytes, left_bytes);
	mx->pos = left_bytes;

	if (mx->sctx.jobLen) {
		uv_buf_t buf;
		buf.base = mx->outbuf;
		buf.len = mx->sctx.jobLen;

		mx->wpos = mx->pos;
		uv_write(&mx->m_req, &mx->handle.stream, &buf, 1, miner_write_done);

		pr_debug(">%s/%s@%s:%hu: %s", mx->miner, mx->agent, mx->addr, mx->port,
			mx->outbuf);
	}
}

void miner_write_done( uv_write_t *req, int status )
{
	miner_ctx *mx = CONTAINER_OF(req, miner_ctx, m_req);
	pool_ctx *px, *npx;
	uv_buf_t buf[2];

	mx->sctx.jobLen = 0;

	if (mx->closing) {
		miner_clear(mx);
		return;
	}

	if (status) {
		pr_warn("Miner %s/%s@%s:%hu write error: %s", mx->miner, mx->agent,
			mx->addr, mx->port, uv_strerror(status));
		miner_close(mx);
		return;
	}

	px = mx->px;
	if (mx->sctx.diffUpdated) {
		buf[status].base = px->diff;
		buf[status++].len = px->sctx.diffLen;
		mx->sctx.diffUpdated = 0;
		mx->sctx.diff = px->sctx.diff;
	}
	if (mx->sctx.jobUpdated) {
		buf[status].base = px->job;
		buf[status++].len = px->sctx.jobLen;
		mx->sctx.jobUpdated = 0;
		strcpy(mx->sctx.jobid, px->sctx.jobid);
	}
	if (status) {
		mx->sctx.jobLen = status;
		uv_write(&mx->m_req, &mx->handle.stream, buf, status,
			miner_write_done);
		return;
	}

	if (mx->wpos != mx->pos) {
		miner_read_done(&mx->handle.stream, 0, NULL);
		return;
	}

	if ((px->status == p_disconnecting || px->status == p_disconnected) &&
			(uv_now(px->loop) - px->disc_time > 10 * 1000 ||
				mx->shareLen - mx->lastShareLen > 128 * 3)) {
		miner_close(mx);
		pr_debug("Switch miner %s/%s@%s:%hu for broken pool %s/%s:%hu",
			mx->miner, mx->agent, mx->addr, mx->port,
			px->conf->host, px->addr, px->conf->port);
	} else if (px->scount < 10 && (npx = pool_pickup(mx->pxx)) && px != npx &&
				(px->conf->priority > npx->conf->priority ||
					(px->conf->priority == npx->conf->priority &&
						px->count > npx->count + 10))) {
		miner_close(mx);
		++px->scount;
		pr_debug("Try switch miner %s/%s@%s:%hu from pool %s/%s:%hu "
			"to a better one %s/%s:%hu",
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
	mx->px = NULL;
	mx->closing = 0;

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
	pr_info("Attach miner from %s:%hu on %s to %s/%s:%hu with xn1=%s",
		mx->addr, mx->port, mx->bind, px->conf->host, px->addr, px->conf->port,
		mx->sctx.xn1);

	mx->pos = 0;
	uv_read_start(&mx->handle.stream, miner_alloc, miner_read_done);
}
