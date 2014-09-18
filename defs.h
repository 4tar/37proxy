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

#ifndef _DEFS_H_
#define _DEFS_H_

#include <assert.h>
#include <uv.h>
#include "stratum.h"

struct pool_ctx;
struct proxy_config;

typedef struct pool_config {
	struct proxy_config *conf;
	char host[64];
	unsigned int port:16;
	int priority:3;
	unsigned int weight:20;
	unsigned int timeout:25;
	char miner[32];
	char passwd[32];
	struct pool_ctx *px;
} pool_config;

typedef enum {
	p_disconnected,
	p_connecting,
	p_initializing,
	p_working,
	p_disconnecting,
} pool_status;

struct miner_ctx;

typedef struct pool_ctx {
	char addr[INET6_ADDRSTRLEN];
	union {
		uv_connect_t conn_req;
		uv_write_t write_req;
	} req;
	unsigned long disc_time;
	pool_config *conf;
	uv_loop_t *loop;
	union {
		uv_handle_t h;
		uv_tcp_t tcp;
		uv_stream_t stream;
	} handle;
	uv_timer_t timer;
	stratum_ctx sctx;
	unsigned int count:14;
	unsigned int scount:4;
	unsigned int pos:12;
	unsigned int status:3;
	char buf[2048], dummy;
	char diff[128], job[1536];
	struct miner_ctx *mx[8192];
} pool_ctx;

typedef struct proxy_config {
	char host[INET6_ADDRSTRLEN];
	char outip[INET6_ADDRSTRLEN];
	unsigned short port, outport;
	unsigned int timeout:28;
	unsigned int count:4;
	uv_loop_t *loop;
	union {
		uv_tcp_t tcp;
		uv_stream_t stream;
	} handle;
	pool_config pools[8];
} proxy_config;

typedef struct miner_ctx {
	char bind[INET6_ADDRSTRLEN];
	char addr[INET6_ADDRSTRLEN];
	unsigned short port;
	char miner[32];
	char agent[16];
	proxy_config *pxx;
	pool_ctx *px;
	union {
		uv_handle_t h;
		uv_tcp_t tcp;
		uv_stream_t stream;
	} handle;
	uv_write_t write_req[3];
	stratum_ctx sctx;
	char outbuf[2048];
	char share[2048];
	char buf[256];
	unsigned char dummy, pos, wpos;
	unsigned short shareLen, lastShareLen;
} miner_ctx;

/* proxy.c */
int proxy_run();
pool_ctx *pool_pickup( proxy_config *conf );
void attach_miner_to_pool( pool_ctx *px, miner_ctx *mx );
void detach_miner_from_pool( pool_ctx *px, miner_ctx *mx );

/* pool.c */
void pool_connect( pool_ctx *px, struct sockaddr *addr );
void pool_submit_share( miner_ctx *px, const char *miner, const char* jobid,
		const char *xn2, const char *ntime, const char *nonce );

/* conf.c */
int parse_config( const char* file, proxy_config *conf );

/* util.c */
#if defined(__GNUC__)
# define ATTRIBUTE_FORMAT_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
# define ATTRIBUTE_FORMAT_PRINTF(a, b)
#endif
typedef enum {
	level_debug,
	level_info,
	level_warn,
	level_err,
} log_level;
void pr_debug( const char *fmt, ... ) ATTRIBUTE_FORMAT_PRINTF(1, 2);
void pr_info( const char *fmt, ... ) ATTRIBUTE_FORMAT_PRINTF(1, 2);
void pr_warn( const char *fmt, ... ) ATTRIBUTE_FORMAT_PRINTF(1, 2);
void pr_err( const char *fmt, ... ) ATTRIBUTE_FORMAT_PRINTF(1, 2);
void *xmalloc(size_t size);
void hex2bin( unsigned char *b, const char *h, size_t len );

#if defined(NDEBUG)
# define ASSERT(exp)
# define CHECK(exp)   do { if (!(exp)) abort(); } while (0)
# define DEBUG_CHECKS (0)
#else
# define ASSERT(exp)  assert(exp)
# define CHECK(exp)   assert(exp)
# define DEBUG_CHECKS (1)
#endif

#define CONTAINER_OF(ptr, type, field) \
  ((type *)((char *)(ptr) - ((char *)&((type *)0)->field)))

#define countof(a) (sizeof(a) / sizeof(a[0]))

#if defined(__GNUC__) && (__GNUC__ > 2)
#define unlikely(expr) (__builtin_expect(!!(expr), 0))
#define likely(expr) (__builtin_expect(!!(expr), 1))
#else
#define unlikely(expr) (expr)
#define likely(expr) (expr)
#endif

#endif  /* DEFS_H_ */
