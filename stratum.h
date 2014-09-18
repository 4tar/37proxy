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
	unsigned char xn1size, xn2size;
	char xn1[16];

	char sid[48];
	double diff;
	char jobid[32];
	char *diffstr;
	char *jobstr;

	unsigned int msgid;
	unsigned int shareCount, denyCount;
	double sdiff;
	void* cx;

	unsigned int isServer:1;
	unsigned int authorized:1;
	unsigned int jobUpdated:1;
	unsigned int diffUpdated:1;
	unsigned int jobLen:11;
	unsigned int outbufLen:11;
	unsigned int diffLen:8;
} stratum_ctx;

#define STRATUM_SESSION_SIZE ((size_t)&((stratum_ctx*)NULL)->msgid)

typedef enum {
	stratum_server,
	stratum_client,
} stratum_type;

int stratum_init( stratum_ctx *sctx, char *buf, const char* user, const char* passwd );
int stratum_parse( stratum_ctx *sctx, char *buf, unsigned int len );
size_t stratum_create_share( stratum_ctx *sctx, char *share, const char *miner,
	const char *jobid, const char *xn2, const char *ntime, const char* nonce );

#endif  /* _STRATUM_H */
