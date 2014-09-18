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
#include <stdlib.h>
#include <string.h>

const char *proxy_name = "37proxy";
const char *proxy_ver = "2";

log_level log_level_t = -1;
time_t start_time;

static void Usage()
{
	fprintf(stderr, "Usage: %s [-c config_file] [-h]\n", proxy_name);
	exit(1);
}

int main( int argc, char *argv[] )
{
	proxy_config config;
	char *config_file = "37proxy.conf";
	int i = 0;

	start_time = time(NULL) - uv_now((uv_default_loop())) / 1000;

	setbuf(stderr, NULL);

	while (++i < argc) {
		if (!strcmp(argv[i], "-c") && ++i < argc) {
			config_file = argv[i];
			continue;
		}
		Usage();
	}

	i = parse_config(config_file, &config);
	if (!i) {
		config.loop = uv_default_loop();
		i = proxy_run(&config);
	}

	return i;
}
