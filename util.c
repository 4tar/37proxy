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
#include "sha2.h"
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef WIN32
#define alloca	_alloca
#else
#include <alloca.h>
#endif

extern log_level log_level_t;
extern uint64_t start_time;

static void pr_do( FILE *stream, const char *label, const char *fmt,
	va_list va )
{
	char fmtbuf[2048 + 256];
	uint64_t elapsed = uv_now(uv_default_loop());
	uint64_t now = start_time + elapsed;
#ifdef WIN32
	int i = vsprintf(fmtbuf, fmt, va);
#else
	int i = vsnprintf(fmtbuf, sizeof(fmtbuf), fmt, va);
#endif
	unsigned short ms = now % 1000;
	struct tm t;

	now /= 1000;

#ifdef WIN32
	_localtime64_s(&t, (__time64_t *)&now);
#else
	localtime_r((time_t *)&now, &t);
#endif

	fprintf(stream, "%02d/%02d %02d:%02d:%02d.%03hu %-5s %s%c",
		t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec, ms,
		label, fmtbuf, fmtbuf[i - 1] == '\n' ? '\0' : '\n');
}

void pr_debug( const char *fmt, ... )
{
	if (log_level_t > level_debug)
		return;

	va_list va;
	va_start(va, fmt);
	pr_do(stdout, "DEBUG", fmt, va);
	va_end(va);
}

void pr_info( const char *fmt, ... )
{
	if (log_level_t > level_info)
		return;

	va_list va;
	va_start(va, fmt);
	pr_do(stdout, "INFO", fmt, va);
	va_end(va);
}

void pr_warn( const char *fmt, ... )
{
	if (log_level_t > level_warn)
		return;

	va_list va;
	va_start(va, fmt);
	pr_do(stderr, "WARN", fmt, va);
	va_end(va);
}

void pr_err( const char *fmt, ... )
{
	va_list va;
	va_start(va, fmt);
	pr_do(stderr, "ERROR", fmt, va);
	va_end(va);
}

void *xmalloc( unsigned int size )
{
	void *ptr = malloc(size);
	if (!ptr) {
		pr_err("out of memory(%u bytes)", size);
		exit(1);
	}
	return ptr;
}

int h2b( const char h )
{
	if (h >= '0' && h <= '9')
		return h - '0';
	if (h >= 'a' && h <= 'f')
		return (h - 'a') + 10;
	if (h >= 'A' && h <= 'F')
		return (h - 'A') + 10;

	return -1;
}

/* Caller ensure bin has enough room and hex is valid */
int hex2bin( unsigned char *bin, const char *h, size_t len )
{
	if ((len % 2))
		return -1;

	for (; len; ++bin, h += 2, len -= 2) {
		int b1 = h2b(h[0]), b2 = h2b(h[1]);
		if (b1 < 0 || b2 < 0)
			return -2;
		*bin = (unsigned char)((b1 << 4) | b2);
	}

	return 0;
}

static const char _hexchars[] = "0123456789abcdef0123456789ABCDEF";

/* Caller ensure hex has enough room and bin is valid */
void bin2hex( char *hex, const void *bin, size_t len, int up )
{
	const unsigned char *p = bin;
	const char *h = _hexchars + (up ? 0x10 : 0);
	while (len--) {
		*hex++ = h[*p >> 4];
		*hex++ = h[*p++ & 0xf];
	}
	hex[0] = '\0';
}

unsigned int varint_decode( const unsigned char *p, size_t size, uint64_t *n )
{
	if (size > 8 && p[0] == 0xff) {
		*n = upk_u64le(p, 0);
		return 9;
	}
	if (size > 4 && p[0] == 0xfe) {
		*n = upk_u32le(p, 0);
		return 5;
	}
	if (size > 2 && p[0] == 0xfd) {
		*n = upk_u16le(p, 0);
		return 3;
	}
	if (size > 0) {
		*n = p[0];
		return 1;
	}
	return 0;
}

static const char b58digits[] =
	"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int b58enc( char *b58, unsigned int *b58sz, const uint8_t *bin, unsigned int binsz )
{
	int i, j, carry, high, zcount = 0;
	unsigned int size;
	uint8_t *buf;

	while (zcount < (int)binsz && !bin[zcount]) ++zcount;

	size = (binsz - zcount) * 138 / 100 + 1;
	buf = alloca(size);
	if (!buf)
		return -1;
	memset(buf, 0, size);

	for (i = zcount, high = size - 1; i < (int)binsz; ++i, high = j) {
		for (carry = bin[i], j = size - 1; (j > high) || carry; --j) {
			carry += 256 * buf[j];
			buf[j] = carry % 58;
			carry /= 58;
		}
	}

	for (j = 0; j < (int)size && !buf[j]; ++j);

	if (*b58sz <= zcount + size - j) {
		*b58sz = zcount + size - j + 1;
		return -2;
	}

	if (zcount)
		memset(b58, '1', zcount);
	for (i = zcount; j < (int)size; ++i, ++j)
		b58[i] = b58digits[buf[j]];
	b58[i] = '\0';
	*b58sz = i + 1;

	return 0;
}

static const int b58tobin_tbl[] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
	-1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
	22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
	-1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
	47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57
};

/* Caller ensures bin & b58 are valid */
void b58dec( unsigned char *bin, const char *b58 )
{
	uint32_t c, bin32[7];
	int len, i, j;
	uint64_t t;

	memset(bin32, 0, 7 * sizeof(uint32_t));
	len = (int)strlen(b58);
	for (i = 0; i < len; i++) {
		c = b58[i];
		c = b58tobin_tbl[c];
		for (j = 6; j >= 0; j--) {
			t = ((uint64_t)bin32[j]) * 58 + c;
			c = (t & 0x3f00000000ull) >> 32;
			bin32[j] = t & 0xffffffffull;
		}
	}
	*(bin++) = bin32[0] & 0xff;
	for (i = 1; i < 7; ++i) {
		*((uint32_t *)bin) = htobe32(bin32[i]);
		bin += sizeof(uint32_t);
	}
}

/* Caller ensure the pkhash is 20 bytes */
static int pubkeyhash_to_address( char *addr, unsigned int *addrsz,
	const uint8_t ver, const uint8_t *pkhash )
{
	uint8_t buf[25], hret[32];

	buf[0] = ver;
	memcpy(buf + 1, pkhash, 20);
	sha256(buf, 21, hret);
	sha256(hret, 32, hret);
	memcpy(buf + 21, hret, 4);

	if (b58enc(addr, addrsz, buf, 25) || (*addrsz != 35 && *addrsz != 34))
		return 1;

	b58dec(buf, addr);
	return (buf[0] != ver || memcmp(buf + 1, pkhash, 20));
}

unsigned int script_to_address( char *out, unsigned int outsz,
	const uint8_t *script, unsigned int scriptsz, int testnet )
{
	char addr[35];
	unsigned int size = sizeof(addr);
	int ret = -1;

	if (scriptsz == 25 && script[0] == 0x76 &&
		script[1] == 0xa9 && script[2] == 0x14 &&
		script[23] == 0x88 && script[24] == 0xac)
		ret = pubkeyhash_to_address(addr, &size, testnet ? 0x6f : 0x00,
				script + 3);
	else if (scriptsz == 23 && script[0] == 0xa9 && script[1] == 0x14 &&
			script[22] == 0x87)
		ret = pubkeyhash_to_address(addr, &size, testnet ? 0xc4 : 0x05,
			script + 2);
	if (ret)
		return 0;
	if (outsz >= size)
		strcpy(out, addr);
	return size;
}
