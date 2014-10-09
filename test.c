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
#include <stdio.h>
#include <string.h>
#include <time.h>

const char *app_name = "37proxy-test";

char *arg0, ip[INET6_ADDRSTRLEN] = "127.0.0.1", user[16] = "";
unsigned short port = 3737;
log_level log_level_t = level_info;
uint64_t start_time;
unsigned int idx = 0, c_count = 4096, idle = 0;
uv_loop_t *loop;
unsigned int timeout = 5000, interval = 0, waitrep = 1;
unsigned char shareCount = 1;

typedef struct client_ctx {
	unsigned int id;
	char bind[INET6_ADDRSTRLEN];
	unsigned short port;
	union {
		uv_connect_t conn;
		uv_write_t write;
	} req;
	union {
		uv_handle_t h;
		uv_tcp_t tcp;
		uv_stream_t stream;
	} handle;
	uv_timer_t timer;
	stratum_ctx sctx;
	uint64_t conn_time, log_time;
	unsigned int rpos:12, wpos:12, wlen:9, connected:1, initialized:1;
	char rbuf[2048], wbuf[2048];
} client_ctx;


void proxy_connect( client_ctx *cx );

static void client_close_done( uv_handle_t *handle )
{
	unsigned int count;
	client_ctx *cx = handle->data;
	ASSERT(handle == &cx->handle.h);

	if ((cx->sctx.msgid - 3)) {
		count = cx->sctx.repid - 2;
		pr_info("Client %u closed, %u shares submitted, %u responses received,"
			"avg %g/s", cx->id, cx->sctx.msgid - 3, count,
			(double)count * 1000 / (uv_now(loop) - cx->conn_time));
	}

	proxy_connect(cx);
}

static void client_close( client_ctx *cx )
{
	if (!cx->connected)
		return;

	cx->connected = 0;

	uv_timer_stop(&cx->timer);

	cx->handle.h.data = cx;
	uv_close(&cx->handle.h, client_close_done);
}

static void client_timeout( uv_timer_t *timer )
{
	client_ctx *cx = CONTAINER_OF(timer, client_ctx, timer);
	client_close(cx);
	pr_debug("Client %u timeout", cx->id);
}

static void client_write_done( uv_write_t *req, int status );

static void client_submit_share( client_ctx *cx )
{
	char miner[32], xn2[17], ntime[9], nonce[9];
	uv_buf_t buf;
	unsigned char i;
	unsigned int count = cx->sctx.repid - 2;
	uint64_t now = uv_now(loop);

	sprintf(miner, "%s.%u", user, cx->id);
	sprintf(xn2, "%0*x", cx->sctx.xn2size * 2, rand());
	sprintf(ntime, "%08x", cx->sctx.ntime);

	if (now - cx->log_time > 1000 * (c_count > 10 ? 10 : c_count)) {
		pr_info("Client %u to submit share %u/%s/%u, avgs %g/s", cx->id,
			cx->sctx.msgid, cx->sctx.jobid, cx->sctx.ntime,
			(double)count * 1000 / (now - cx->conn_time));
		cx->log_time = now;
	}

	ASSERT(cx->wlen == 0);
	for (i = 0; i < shareCount; ++i) {
		sprintf(nonce, "%08x", rand());
		cx->wlen += stratum_create_share(&cx->sctx, cx->wbuf + cx->wlen,
			miner, cx->sctx.jobid, xn2, ntime, nonce);
	}
	pr_debug("<Client %u/%u/%u: %s", cx->id, cx->sctx.msgid, cx->wlen,
		cx->wbuf);

	buf.base = cx->wbuf;
	buf.len = cx->wlen;
	cx->wpos = cx->rpos;
	uv_write(&cx->req.write, &cx->handle.stream, &buf, 1, client_write_done);
	uv_timer_start(&cx->timer, client_timeout, timeout, 0);
}

static void client_s_timeout( uv_timer_t *timer )
{
	client_ctx *cx = CONTAINER_OF(timer, client_ctx, timer);
	client_submit_share(cx);
}

static void client_alloc( uv_handle_t *handle, size_t size, uv_buf_t *buf )
{
	client_ctx *cx = CONTAINER_OF(handle, client_ctx, handle);
	buf->base = cx->rbuf + cx->rpos;
	buf->len = sizeof(cx->rbuf) - cx->rpos;
}

static void client_read_done( uv_stream_t *stream, ssize_t nread,
	const uv_buf_t *bufDone )
{
	int left_bytes;

	client_ctx *cx = CONTAINER_OF(stream, client_ctx, handle.stream);

	if (nread < 0) {
		pr_err("Client %u read error %s", cx->id, uv_strerror((int)nread));
		client_close(cx);
		return;
	} else if (!nread && bufDone) {
		pr_warn("Client %u idle/nobuf?", cx->id);
		return;
	}

	cx->rpos += (unsigned int)nread;

	left_bytes = stratum_parse(&cx->sctx, cx->rbuf, cx->rpos);
	if (left_bytes < 0 || left_bytes >= sizeof(cx->rbuf)) {
		pr_err("Client %u disconnect", cx->id);
		client_close(cx);
		return;
	}

	if (left_bytes && left_bytes != cx->rpos)
		memmove(cx->rbuf, cx->rbuf + cx->rpos - left_bytes, left_bytes);
	cx->rpos = left_bytes;

	if (cx->wlen) {
		pr_debug("Client %u is writting when received data", cx->id);
		return;
	}

	if (!cx->sctx.authorized || !cx->sctx.jobid[0]) {
		pr_debug("Client %u hasn't get authorized", cx->id);
		return;
	}
	if (waitrep && cx->sctx.repid < cx->sctx.msgid - 1) {
		pr_debug("Client %u is pending on message: %u/%u", cx->id,
			cx->sctx.repid, cx->sctx.msgid);
		return;
	}

	if (interval)
		uv_timer_start(&cx->timer, client_s_timeout, rand() % interval, 0);
	else
		client_submit_share(cx);
}

static void client_write_done( uv_write_t *req, int status )
{
	client_ctx *cx = CONTAINER_OF(req, client_ctx, req.write);

	if (status) {
		pr_warn("Client %u write error", cx->id);
		client_close(cx);
		return;
	}

	cx->wlen = 0;

	if (cx->wpos != cx->rpos) {
		pr_debug("Client %u call read_done", cx->id);
		client_read_done(&cx->handle.stream, 0, NULL);
	}
}

void proxy_connected( uv_connect_t *req, int status )
{
	client_ctx *cx = CONTAINER_OF(req, client_ctx, req.conn);
	char miner[32];
	uv_buf_t buf;
	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	} s;
	int len;

	if (!uv_tcp_getsockname(&cx->handle.tcp, &s.addr, &len)) {
		if (s.addr.sa_family == AF_INET) {
			uv_ip4_name(&s.addr4, cx->bind, sizeof(cx->bind));
			cx->port = ntohs(s.addr4.sin_port);
		} else {
			uv_ip6_name(&s.addr6, cx->bind, sizeof(cx->bind));
			cx->port = ntohs(s.addr6.sin6_port);
		}
	} else
		cx->bind[0] = 0;

	if (status) {
		pr_err("Client %u/%s:%hu connected error: %s", cx->id,
			cx->bind, cx->port, uv_strerror(status));
		uv_timer_start(&cx->timer, client_timeout, 1000, 0);
		return;
	}

	cx->connected = 1;
	cx->log_time = cx->conn_time = uv_now(loop);

	pr_info("Client %u connected", cx->id);

	cx->sctx.cx = NULL;

	sprintf(miner, "%s.%u", user, cx->id);

	buf.base = cx->wbuf;
	buf.len = cx->wlen = stratum_init(&cx->sctx, cx->wbuf, miner, "");

	cx->wpos = cx->rpos = 0;
	uv_write(&cx->req.write, &cx->handle.stream, &buf, 1,
		client_write_done);
	uv_timer_start(&cx->timer, client_timeout, timeout, 0);

	uv_read_start(&cx->handle.stream, client_alloc, client_read_done);
}

void proxy_connect( client_ctx *cx )
{
	union {
		struct sockaddr addr;
		struct sockaddr_in addr4;
		struct sockaddr_in6 addr6;
	} s;
	int err;

	if (!uv_ip4_addr(ip, port, &s.addr4));
	else if (!(err = uv_ip6_addr(ip, port, &s.addr6)));
	else {
		free(cx);
		pr_err("Invalid proxy addr: %s:%hu - %s", ip, port, uv_strerror(err));
		return;
	}

	if (!cx->initialized) {
		if ((err = uv_timer_init(loop, &cx->timer))) {
			pr_err("Initialize timer for client %u failed: %s",
				cx->id, uv_strerror(err));
			free(cx);
			return;
		}
	}

	if ((err = uv_tcp_init(loop, &cx->handle.tcp))) {
		pr_err("Initialize tcp handle failed: %s", uv_strerror(err));
		uv_timer_start(&cx->timer, client_timeout, 1000, 0);
		return;
	}

	if ((err = uv_tcp_connect(&cx->req.conn, &cx->handle.tcp, &s.addr,
				proxy_connected))) {
		pr_err("Client %u connect failed: %s", cx->id, uv_strerror(err));
		uv_timer_start(&cx->timer, client_timeout, 1000, 0);
		return;
	}

	pr_debug("Client %u connect event fired", cx->id);
}

static void on_idle( uv_idle_t *idler )
{
	client_ctx *cx = malloc(sizeof(*cx));
	if (!cx) {
		pr_err("Memory allocation failed");
		abort();
	}
	cx->id = idx++;
	cx->connected = 0;
	cx->initialized = 0;
	proxy_connect(cx);

	if (idx == c_count) {
		uv_idle_stop(idler);
		pr_info("%u clients created, stop the idler", c_count);
	}
}

static void Usage( const char *arg0 )
{
	fprintf(stderr, "Usage: %s -p pool_ip pool_port -u user -l level -n nowait "
		"-c count -t timeout -i interval -s shareCountInOneTime\n", arg0);
	exit(1);
}

int main( int argc, char *argv[] )
{
	int i = 0;
	uv_idle_t idler;

	arg0 = argv[0];
	loop = uv_default_loop();
	start_time = time64(NULL) * 1000 - uv_now(loop);

	setbuf(stdout, NULL);
	setbuf(stderr, NULL);
#ifndef WIN32
	signal(SIGPIPE, SIG_IGN);
#endif
	while (++i < argc) {
		if (!strcmp(argv[i], "-p") && ++i < argc - 1) {
			strncpy(ip, argv[i++], sizeof(ip));
			if ((port = atoi(argv[i])))
				continue;
		} else if (!strcmp(argv[i], "-u") && ++i < argc) {
			strncpy(user, argv[i], sizeof(user));
			user[sizeof(user) - 1] = '\0';
			continue;
		} else if (!strcmp(argv[i], "-l") && ++i < argc) {
			log_level_t = -1;
			if (!strcmp(argv[i], "debug"))
				log_level_t = level_debug;
			else if (!strcmp(argv[i], "info"))
				log_level_t = level_info;
			else if (!strcmp(argv[i], "warn"))
				log_level_t = level_warn;
			else if (!strcmp(argv[i], "error"))
				log_level_t = level_err;
			if ((int)log_level_t != -1)
				continue;
		} else if (!strcmp(argv[i], "-c") && ++i < argc) {
			c_count = atoi(argv[i]);
			if (c_count)
				continue;
		} else if (!strcmp(argv[i], "-t") && ++i < argc) {
			timeout = atoi(argv[i]) * 1000;
			if (timeout)
				continue;
		} else if (!strcmp(argv[i], "-i") && ++i < argc) {
			interval = atoi(argv[i]) * 1000;
			if (interval)
				continue;
		} else if (!strcmp(argv[i], "-s") && ++i < argc) {
			shareCount = atoi(argv[i]);
			if (shareCount)
				continue;
		} else if (!strcmp(argv[i], "-n")) {
			waitrep = 0;
			continue;
		}

		Usage(arg0);
	}
	if (!user[0])
		strcpy(user, app_name);
	if (timeout < 2 * interval) {
		pr_err("Timeout value should not be less than 2 times of interval");
		return 2;
	}
	if (shareCount > 15) {
		pr_err("Should not submit more than 15 shares in one time");
		return 3;
	}

	pr_info("To do stress test against %s:%hu with %u clients",
		ip, port, c_count);

	uv_idle_init(loop, &idler);
	uv_idle_start(&idler, on_idle);

	return uv_run(loop, UV_RUN_DEFAULT);
}
