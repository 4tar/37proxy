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

#ifndef _STRATUM_H_
#define _STRATUM_H_

typedef struct {
	unsigned int xn1size:4, xn2size:4;
	unsigned int isServer:1, authorized:1;
	unsigned int jobUpdated:1, diffUpdated:1;
	unsigned int jobLen:11, diffLen:8;

	/* 04h */ unsigned int ntime;
	/* 08h */ char xn1[16];
	/* 18h */ char sid[48];
	/* 48h */ double diff;
	/* 50h */ char jobid[32];
	/* 70h */ char *diffstr, *jobstr;

	/* 80h */ unsigned int msgid;
	/* 84h */ unsigned int shareCount, denyCount;
	/* 90h */ double sdiff;
	/* 98h */ void* cx;
} stratum_ctx;

#define struct_pos(s, e)			((size_t)&(((s *)NULL)->e))
#define STRATUM_SESSION_SIZE		struct_pos(stratum_ctx, msgid)
#define STRATUM_SESSION_POS(sctx)	(&(sctx)->msgid)

typedef enum {
	stratum_server,
	stratum_client,
} stratum_type;

int stratum_init( stratum_ctx *sctx, char *buf, const char* user, const char* passwd );
int stratum_parse( stratum_ctx *sctx, char *buf, unsigned int len );
int stratum_create_share( stratum_ctx *sctx, char *share, const char *miner,
	const char *jobid, const char *xn2, const char *ntime, const char* nonce );
int stratum_build_reconnect( stratum_ctx *sctx, char *reconn );

#endif  /* _STRATUM_H */
