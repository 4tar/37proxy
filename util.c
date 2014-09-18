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
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

extern log_level log_level_t;
extern time_t start_time;
extern uint64_t start_timestamp;

static void pr_do( FILE *stream, const char *label, const char *fmt,
	va_list va )
{
	char fmtbuf[2048 + 256];
	struct tm t;
	unsigned long elapsed = uv_now(uv_default_loop());
	time_t now = start_time + elapsed / 1000;
	unsigned short ms = elapsed % 1000;
	int i = vsnprintf(fmtbuf, sizeof(fmtbuf), fmt, va);

	localtime_r((time_t *)&now, &t);
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

void *xmalloc( size_t size )
{
	void *ptr = malloc(size);
	if (!ptr) {
		pr_err("out of memory(%lu bytes)", size);
		exit(1);
	}
	return ptr;
}

unsigned char h2b( const char h )
{
	if (h >= '0' && h <= '9')
		return h - '0';
	if (h >= 'a' && h <= 'f')
		return (h - 'a') + 10;
	if (h >= 'A' && h <= 'F')
		return (h - 'A') + 10;

	ASSERT(0);
	return 0xFF;
}

void hex2bin( unsigned char *b, const char *h, size_t len )
{
	ASSERT(!(len % 2));

	for (; len; ++b, h += 2, len -= 2)
		*b = h2b(h[0]) << 4 | h2b(h[1]);
}
