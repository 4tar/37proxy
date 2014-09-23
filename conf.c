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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "defs.h"

#define DEFAULT_PROXY_HOST		"0.0.0.0"
#define DEFAULT_PROXY_PORT		3737

#define DEFAULT_POOL_PORT		3333
#define DEFAULT_POOL_PRIORITY	1
#define DEFAULT_POOL_WEIGHT		100
#define DEFAULT_POOL_TIMEOUT	120000
#define DEFAULT_POOL_CBTOTAL	2500000000

extern log_level log_level_t;

int parse_config( const char* file, proxy_config *conf )
{
	unsigned int i = 0, pool_disabled = 1;
	char line[128];
	FILE* fConf = fopen(file, "r");
	if (!fConf) {
		pr_err("Cannot open configuration file: %s", file);
		return 1;
	}

	memset(conf, 0, sizeof(*conf));

	while (fgets(line, sizeof(line), fConf)) {
		char *p, *name, *value = NULL;

		++i;

		for (p = line; *p && *p != '#'; ++p);
		if (*p)
			*p = '\0';

		for (--p; p >= line &&
				(*p == '\r' || *p == '\n' || *p == ' ' || *p == '\t'); --p);
		if (p < line)
			continue;
		if (p - line >= 80) {
			pr_err("Invalid line (%d): (too long)\n", i);
			i = 0;
			break;
		}
		p[1] = '\0';

		for (p = line; *p && (*p == ' ' || *p == '\t'); ++p);
		if (*p == '#')
			continue;
		if (p[1] == '\0') {
unknown_line:
			pr_err("Invalid line (%d): %s\n", i, line);
			i = 0;
			break;
		}
		name = p;

		for (++p; *p && (*p != ' ' && *p != '\t' && *p != '='); ++p);
		*p = '\0';

		for (++p; *p && (*p == ' ' || *p == '\t' || *p == '='); ++p);
		if (*p)
			value = p;

		if (!strcmp(name, "proxy.host")) {
			if (conf->host[0]) {
duplicate_key:			
				pr_err("Invalid line (%d): (duplicate key '%s')", i, name);
				i = 0;
				break;
			}
			if (!value) {
empty_value:
				pr_err("Invalid line (%d): (empty value)", i);
				i = 0;
				break;
			}
			if (strlen(value) >= sizeof(conf->host)) {
too_long_value:
				pr_err("Invalid line (%d): (too long value)", i);
				i = 0;
				break;
			}
			strcpy(conf->host, value);
		} else if (!strcmp(name, "proxy.port")) {
			if (conf->port)
				goto duplicate_key;
			if (value)
				conf->port = atoi(value);
		} else if (!strcmp(name, "proxy.outip")) {
			if (conf->outip[0])
				goto duplicate_key;
			if (!value)
				continue;
			if (strlen(value) >= sizeof(conf->outip))
				goto too_long_value;
			strcpy(conf->outip, value);
		} else if (!strcmp(name, "proxy.outport")) {
			if (conf->outport)
				goto duplicate_key;
			if (value)
				conf->outport = atoi(value);
		} else if (!strcmp(name, "proxy.timeout")) {
			if (conf->timeout)
				goto duplicate_key;
			if (value)
				conf->timeout = atoi(value);
		} else if (!strcmp(name, "proxy.loglevel")) {
			if ((int)log_level_t >= 0)
				goto duplicate_key;
			if (value) {
				if (!strcmp(value, "debug"))
					log_level_t = level_debug;
				else if (!strcmp(value, "info"))
					log_level_t = level_info;
				else if (!strcmp(value, "warn"))
					log_level_t = level_warn;
				else if (!strcmp(value, "error"))
					log_level_t = level_err;
				else
					goto unknown_line;
			}
		} else if (!strcmp(name, "pool.enable")) {
			pool_disabled = (value && strcmp(value, "true"));
			if (pool_disabled)
				continue;
			conf->pools[conf->count++].priority = -1;
		} else if (!strcmp(name, "pool.priority")) {
			if (pool_disabled)
				continue;
			if (conf->pools[conf->count - 1].priority >= 0)
				goto duplicate_key;
			if (value)
				conf->pools[conf->count - 1].priority = atoi(value);
		} else if (!strcmp(name, "pool.weight")) {
			if (pool_disabled)
				continue;
			if (conf->pools[conf->count - 1].weight)
				goto duplicate_key;
			if (value)
				conf->pools[conf->count - 1].weight = atoi(value);
		} else if (!strcmp(name, "pool.host")) {
			if (pool_disabled)
				continue;
			if (conf->pools[conf->count - 1].host[0])
				goto duplicate_key;
			if (!value)
				goto empty_value;
			if (strlen(value) >= sizeof(conf->pools[0].host))
				goto too_long_value;
			strcpy(conf->pools[conf->count - 1].host, value);
		} else if (!strcmp(name, "pool.port")) {
			if (pool_disabled)
				continue;
			if (conf->pools[conf->count - 1].port)
				goto duplicate_key;
			if (value)
				conf->pools[conf->count - 1].port = atoi(value);
		} else if (!strcmp(name, "pool.miner")) {
			if (pool_disabled)
				continue;
			if (conf->pools[conf->count - 1].miner[0])
				goto duplicate_key;
			if (!value)
				goto empty_value;
			if (strlen(value) >= sizeof(conf->pools[0].miner))
				goto too_long_value;
			strcpy(conf->pools[conf->count - 1].miner, value);
		} else if (!strcmp(name, "pool.passwd")) {
			if (pool_disabled)
				continue;
			if (conf->pools[conf->count - 1].passwd[0])
				goto duplicate_key;
			if (value) {
				if (strlen(value) >= sizeof(conf->pools[0].passwd))
					goto too_long_value;
				strcpy(conf->pools[conf->count - 1].passwd, value);
			}
		} else if (!strcmp(name, "pool.timeout")) {
			if (pool_disabled)
				continue;
			if (conf->pools[conf->count - 1].timeout)
				goto duplicate_key;
			if (value)
				conf->pools[conf->count - 1].timeout = 1000 * atoi(value);
		} else if (!strcmp(name, "pool.cbaddr")) {
			if (pool_disabled)
				continue;
			if (conf->pools[conf->count - 1].cbaddr[0])
				goto duplicate_key;
			if (!value)
				continue;
			if (strlen(value) >= sizeof(conf->pools[0].cbaddr))
				goto too_long_value;
			strcpy(conf->pools[conf->count - 1].cbaddr, value);
		} else if (!strcmp(name, "pool.cbtotal")) {
			if (pool_disabled)
				continue;
			if (conf->pools[conf->count - 1].cbtotal)
				goto duplicate_key;
			if (value)
				conf->pools[conf->count - 1].cbtotal = strtoul(value, NULL, 10);
		} else if (!strcmp(name, "pool.cbperc")) {
			if (pool_disabled)
				continue;
			if (conf->pools[conf->count - 1].cbperc)
				goto duplicate_key;
			if (value)
				conf->pools[conf->count - 1].cbperc = atof(value);
		} else
			goto unknown_line;
	}

	fclose(fConf);

	if (!i)
		return 1;

	if ((int)log_level_t < 0)
		log_level_t = level_info;
	if (log_level_t <= level_info)
		setbuf(stdout, NULL);

	if (!conf->host[0])
		strcpy(conf->host, DEFAULT_PROXY_HOST);
	if (!conf->port)
		conf->port = DEFAULT_PROXY_PORT;

	pr_debug("proxy config: %s:%d/%d", conf->host, conf->port, conf->timeout);

	for (i = 0; i < conf->count; ++i) {
		if (!conf->pools[i].host[0]) {
			pr_err("Invalid pool %d configuration: no host", i + 1);
			i = 0;
			break;
		}
		if (!conf->pools[i].miner[0]) {
			pr_err("Invalid pool %d configuration: no miner", i + 1);
			i = 0;
			break;
		}
		conf->pools[i].conf = conf;
		if (!conf->pools[i].port)
			conf->pools[i].port = DEFAULT_POOL_PORT;
		if (conf->pools[i].priority < 0)
			conf->pools[i].priority = DEFAULT_POOL_PRIORITY;
		if (!conf->pools[i].weight)
			conf->pools[i].weight = DEFAULT_POOL_WEIGHT;
		if (!conf->pools[i].timeout)
			conf->pools[i].timeout = DEFAULT_POOL_TIMEOUT;
		if (!conf->pools[i].cbtotal)
			conf->pools[i].cbtotal = DEFAULT_POOL_CBTOTAL;

		pool_config *p = &conf->pools[i];
		pr_debug("Pool %d: prio: %d  stratum: %s:%d  login: %s/%s  timeout: %d",
			i, p->priority, p->host, p->port, p->miner, p->passwd, p->timeout);
	}

	return (i == 0);
}
