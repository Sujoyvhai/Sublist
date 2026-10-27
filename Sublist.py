#!/usr/bin/env python3
"""
Sublist - a simple subdomain enumeration tool
Author : Sujoy Karmakar
License: MIT

Use only on domains you own or have written permission to test.
"""

import argparse
import concurrent.futures as cf
import csv
import itertools
import json
import os
import random
import re
import shutil
import socket
import ssl
import string
import struct
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request

__version__ = "1.3.0"
__author__ = "Sujoy Karmakar"

# ---- update settings -------------------------------------------------------
# Used by `Sublist -update` when the tool was NOT installed with `git clone`.
# Change this to your GitHub "username/repository" before publishing.
REPO = "YOUR_GITHUB_USERNAME/Sublist"
BRANCH = "main"
SCRIPT_NAME = "Sublist.py"
RAW_URL = "https://raw.githubusercontent.com/{repo}/{branch}/{script}"
# ----------------------------------------------------------------------------

# ---- optional API keys -------------------------------------------------------
# Keys are optional, but each one adds a big extra data source (most have a
# free tier). Set them as environment variables OR in ~/.sublist.json:
#   {"virustotal": "KEY", "securitytrails": "KEY", "chaos": "KEY"}
CONFIG_PATH = os.path.expanduser("~/.sublist.json")
KEY_ENV = {
    "virustotal": "VIRUSTOTAL_API_KEY",
    "securitytrails": "SECURITYTRAILS_API_KEY",
    "chaos": "CHAOS_API_KEY",
    "shodan": "SHODAN_API_KEY",
    "fullhunt": "FULLHUNT_API_KEY",
    "bevigil": "BEVIGIL_API_KEY",
}
API_KEYS = {}
# Sublist also reuses the keys from subfinder's provider-config.yaml (if present)
SUBFINDER_CFG = os.path.expanduser("~/.config/subfinder/provider-config.yaml")
# ----------------------------------------------------------------------------

BANNER = r"""
 ____        _     _ _     _
/ ___| _   _| |__ | (_)___| |_
\___ \| | | | '_ \| | / __| __|
 ___) | |_| | |_) | | \__ \ |_
|____/ \__,_|_.__/|_|_|___/\__|
        v{ver}  |  by {author}
""".format(ver=__version__, author=__author__)

UA = "Mozilla/5.0 (compatible; Sublist/{})".format(__version__)
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?$")

_BASE_WORDS = """
www www1 www2 www3 mail mail1 mail2 mail3 email mailer mailgate relay ftp ftp2 sftp smtp smtp1 smtp2
pop pop3 imap webmail exchange owa autodiscover autoconfig lyncdiscover sip webex meet meeting
conference zoom ns ns1 ns2 ns3 ns4 dns dns1 dns2 mx mx1 mx2 admin administrator adm admin1 admin2
api api1 api2 api3 apis rest graphql ws soap rpc grpc dev dev1 dev2 develop development devel test
test1 test2 testing tst qa qas staging stage stg beta alpha demo demo2 preview sandbox uat prod
production pre preprod pre-prod live lab labs research training learn lms portal blog shop store
shop2 app app1 app2 apps application mobile m wap mobile-api web web1 web2 server servers host hosts
cdn cdn1 cdn2 static assets asset img image images media media2 video videos stream streaming radio
tv files file download downloads upload uploads docs doc documentation help helpdesk support status
monitor monitoring metrics grafana kibana prometheus nagios zabbix elk logs log splunk sentry
analytics stats stat statistics tracking track ads ad adserver tag tags pixel report reports
reporting bi data datalake warehouse etl airflow spark hadoop ml ai search solr elastic
elasticsearch es kafka rabbitmq mq queue db db1 db2 database mysql sql mssql postgres postgresql
pgsql oracle mongo mongodb redis memcache cache backup backups bak backup2 dr failover old new v1
v2 v3 intranet internal intra private corp corporate extranet secure ssl login signin signup
register registration auth oauth sso saml ldap ad adfs idp id identity accounts account profile
user users member members my dashboard panel cpanel whm plesk webmin directadmin control manager
manage console backend backoffice back-office office cms drupal wordpress wp joomla magento
forum forums community board news press events event calendar cal careers jobs job partners
partner affiliates affiliate vendor vendors supplier client clients customer customers b2b b2c
vpn vpn1 vpn2 remote rdp ras citrix terminal desktop ts gateway gw proxy proxy1 lb loadbalancer
router firewall fw ssh cloud storage nas san s3 share sharepoint onedrive drive box git gitlab
github bitbucket svn cvs repo repos code ci cd jenkins build builds bamboo teamcity travis drone
artifactory nexus registry docker k8s kubernetes rancher consul vault terraform ansible puppet
chef jira confluence wiki kb knowledge tracker issues bugs bugzilla redmine trac crm erp hr hris
payroll billing invoice invoices pay payment payments checkout cart orders order wallet bank
banking mdm intune pbx voip phone maps map geo gis location tools tool util utils utility service
services svc us eu uk de fr asia in au ca sg jp br origin edge cache1 cache2 mirror mirror1
status2 health ping time ntp host1 host2 node1 node2 node3 master slave primary secondary
standby test-env dev-api api-dev api-test api-staging api-prod staging-api student students
library edu school hospital
"""

_EXTRA_WORDS = """
apm api-gateway apigw appdev appstore archive aws azure gcp bastion bounce campus career cas
catalog chat chatbot check cluster connect content customer-portal cust dc dc1 dc2 dealer devops
dev-portal dhcp direct dmz domain domains e-learning elearning ecommerce edge1 edge2 emp employee
employees enterprise expo faq feed feeds finance forms front frontend home hub iam info infra
ingress inside insight int inventory iot jump jumpbox kiosk lb1 lb2 legacy link links list lists
local mailing marketing net network office365 ops pages pki pos print printer promo public pub rds
reset resources review rss sales scan schedule scm sdk security selfservice site sites sms snmp
social solutions sp spa survey sync syslog team teams tech ticket tickets trust update updates
vdi view vm waf webapp webdav webhooks websocket webservice whois win wireless www4 xml zone
mail4 mx3 smtp3 imap2 pop2 relay2 ns5 ns6 vpn3 gw1 gw2 node4 node5 app3 web3 api4 cdn3 static1
static2 img1 img2 media1 files1 old2 new2 test3 dev3 stage2 staging2 uat2 prod2 beta2 demo3
admin3 portal2 portal3 login2 sso2 auth2 oauth2 ssl2 secure2 pay2 shop3 store2 blog2 news2 wiki2
"""

DEFAULT_WORDS = list(dict.fromkeys((_BASE_WORDS + " " + _EXTRA_WORDS).split()))

# small list used for the second level (-R / --recursive): x.<found-sub>.domain
RECURSIVE_WORDS = """
www mail api dev test staging stage beta admin portal app web intranet internal vpn cdn static
assets db ftp smtp ns1 ns2 git ci jenkins monitor grafana kibana login auth sso old new demo qa
uat prod preprod int stg v1 v2 backend console panel manage
""".split()

# prefixes used by the permutation engine (-p)
PERM_PREFIXES = ["dev", "test", "stage", "staging", "prod", "uat", "beta", "old", "new",
                 "internal", "int", "qa", "pre", "demo", "api", "admin", "v1", "v2", "backup", "stg"]

# SRV records often point at hidden hosts (sip, xmpp, ldap, autodiscover ...)
SRV_LABELS = ["_sip._tcp", "_sip._udp", "_sips._tcp", "_xmpp-server._tcp", "_xmpp-client._tcp",
              "_autodiscover._tcp", "_ldap._tcp", "_kerberos._tcp", "_imaps._tcp",
              "_imap._tcp", "_submission._tcp", "_pop3s._tcp", "_caldavs._tcp",
              "_carddavs._tcp", "_h323cs._tcp", "_minecraft._tcp", "_matrix._tcp"]


# ------------------------------------------------------------------ helpers
def log(msg, quiet=False):
    if not quiet:
        print(msg, file=sys.stderr)


class Spinner:
    """Shows 'Loading |/-\\' while work is running (errors stay hidden)."""

    def __init__(self, text="Loading", quiet=False):
        self.text = text
        self.quiet = quiet
        self._stop = threading.Event()
        self._thread = None

    def _spin(self):
        for ch in itertools.cycle("|/-\\"):
            if self._stop.is_set():
                break
            sys.stderr.write("\r[*] {} {}   ".format(self.text, ch))
            sys.stderr.flush()
            time.sleep(0.1)

    def __enter__(self):
        if self.quiet:
            return self
        if sys.stderr.isatty():
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        else:
            print("[*] {}...".format(self.text), file=sys.stderr)
        return self

    def __exit__(self, *exc):
        if self._thread:
            self._stop.set()
            self._thread.join()
            sys.stderr.write("\r" + " " * 79 + "\r")
            sys.stderr.flush()
        return False


def http_get(url, timeout=20, headers=None):
    h = {"User-Agent": UA}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, headers=h)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="ignore")


def clean(names, domain):
    """Normalize names and keep only valid subdomains of `domain`."""
    out = set()
    for n in names:
        if not isinstance(n, str):
            continue
        n = n.strip().lower().rstrip(".")
        n = re.sub(r"^\*\.", "", n)
        if n.endswith("." + domain) and DOMAIN_RE.match(n):
            out.add(n)
    return out


def _keys_from_subfinder():
    """Tiny parser for subfinder's provider-config.yaml (no PyYAML needed)."""
    keys = {}
    cur = None
    try:
        with open(SUBFINDER_CFG, encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.rstrip()
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                m = re.match(r"^([A-Za-z0-9_]+):\s*(.*)$", line)
                if m:
                    cur = m.group(1).lower()
                    rest = m.group(2).strip()
                    if cur in KEY_ENV and rest.startswith("[") and rest != "[]":
                        v = rest.strip("[]").split(",")[0].strip().strip("'\"")
                        if v:
                            keys[cur] = v
                    continue
                m = re.match(r"^\s*-\s*(.+)$", line)
                if m and cur in KEY_ENV and cur not in keys:
                    v = m.group(1).strip().strip("'\"")
                    if v:
                        keys[cur] = v
    except OSError:
        pass
    return keys


def load_keys():
    """Read API keys from subfinder's config, ~/.sublist.json and environment
    variables (later ones win: environment > ~/.sublist.json > subfinder)."""
    keys = _keys_from_subfinder()
    try:
        with open(CONFIG_PATH, encoding="utf-8") as f:
            cfg = json.load(f)
        src = cfg.get("api_keys", cfg)
        for k in KEY_ENV:
            v = src.get(k)
            if isinstance(v, str) and v.strip():
                keys[k] = v.strip()
    except (OSError, ValueError, AttributeError):
        pass
    for k, env in KEY_ENV.items():
        v = os.environ.get(env, "").strip()
        if v:
            keys[k] = v
    return keys


def _scrape(html, domain):
    return re.findall(r"([a-z0-9][a-z0-9.\-]*\.{})".format(re.escape(domain)), html.lower())


# ------------------------------------------------------------ passive sources
# ---- no key needed ----
def src_crtsh(domain):
    data = json.loads(http_get("https://crt.sh/?q=%25.{}&output=json".format(domain), 45))
    names = []
    for row in data:
        names.extend(row.get("name_value", "").split("\n"))
    return names


def src_certspotter(domain):
    names = []
    after = ""
    for page in range(6):                       # up to ~600 certificates
        url = ("https://api.certspotter.com/v1/issuances?domain={}"
               "&include_subdomains=true&expand=dns_names".format(domain))
        if after:
            url += "&after=" + after
        try:
            data = json.loads(http_get(url, 25))
        except Exception:
            if names:                           # keep what we already have
                break
            raise
        if not data:
            break
        for row in data:
            names.extend(row.get("dns_names", []))
        after = str(data[-1].get("id", ""))
        if not after or len(data) < 100:
            break
    return names


def src_digitorus(domain):
    return _scrape(http_get("https://certificatedetails.com/{}".format(domain), 25), domain)


def src_hackertarget(domain):
    text = http_get("https://api.hackertarget.com/hostsearch/?q={}".format(domain), 20)
    if "error" in text.lower()[:50] or "api count exceeded" in text.lower():
        return []
    return [line.split(",")[0] for line in text.splitlines()]


def src_otx(domain):
    data = json.loads(http_get(
        "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns".format(domain), 25))
    return [r.get("hostname", "") for r in data.get("passive_dns", [])]


def src_otx_urls(domain):
    """AlienVault OTX also stores URLs - their hostnames reveal more subdomains."""
    names = []
    for page in (1, 2, 3):
        try:
            data = json.loads(http_get(
                "https://otx.alienvault.com/api/v1/indicators/domain/{}/url_list"
                "?limit=500&page={}".format(domain, page), 25))
        except Exception:
            if names:
                break
            raise
        rows = data.get("url_list", [])
        for r in rows:
            names.append(r.get("hostname", ""))
        if not data.get("has_next"):
            break
    return names


def src_anubis(domain):
    return json.loads(http_get("https://jldc.me/anubis/subdomains/{}".format(domain), 20))


def src_wayback(domain):
    url = ("https://web.archive.org/cdx/search/cdx?url={}&matchType=domain&output=text"
           "&fl=original&collapse=urlkey&limit=50000".format(domain))
    names = []
    for line in http_get(url, 40).splitlines():
        m = re.match(r"^[a-z]+://([^/:?#@]*@)?([^/:?#]+)", line.strip().lower())
        if m:
            names.append(m.group(2))
    return names


def src_urlscan(domain):
    data = json.loads(http_get(
        "https://urlscan.io/api/v1/search/?q=domain:{}&size=100".format(domain), 25))
    names = []
    for r in data.get("results", []):
        names.append(r.get("page", {}).get("domain", ""))
        names.append(r.get("task", {}).get("domain", ""))
    return names


def src_rapiddns(domain):
    return _scrape(http_get("https://rapiddns.io/subdomain/{}?full=1".format(domain), 25), domain)


def src_threatminer(domain):
    data = json.loads(http_get(
        "https://api.threatminer.org/v2/domain.php?q={}&rt=5".format(domain), 25))
    return data.get("results", [])


def src_threatcrowd(domain):
    data = json.loads(http_get(
        "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={}".format(domain), 20))
    return data.get("subdomains", [])


def src_sublist3r(domain):
    data = json.loads(http_get("https://api.sublist3r.com/search.php?domain={}".format(domain), 20))
    return data if isinstance(data, list) else []


def src_columbus(domain):
    data = json.loads(http_get(
        "https://columbus.elmasy.com/api/subdomains/{}".format(domain), 25))
    return ["{}.{}".format(x, domain) for x in data if isinstance(x, str)]


# ---- need a (free) API key ----
def src_virustotal(domain):
    key = API_KEYS["virustotal"]
    names = []
    url = "https://www.virustotal.com/api/v3/domains/{}/subdomains?limit=40".format(domain)
    for _ in range(5):                          # free tier: 4 requests / minute
        try:
            data = json.loads(http_get(url, 25, {"x-apikey": key}))
        except Exception:
            if names:
                break
            raise
        names.extend(i.get("id", "") for i in data.get("data", []))
        url = data.get("links", {}).get("next")
        if not url:
            break
    return names


def src_securitytrails(domain):
    data = json.loads(http_get(
        "https://api.securitytrails.com/v1/domain/{}/subdomains"
        "?children_only=false&include_inactive=true".format(domain),
        30, {"APIKEY": API_KEYS["securitytrails"]}))
    return ["{}.{}".format(s, domain) for s in data.get("subdomains", [])]


def src_chaos(domain):
    data = json.loads(http_get(
        "https://dns.projectdiscovery.io/dns/{}/subdomains".format(domain),
        25, {"Authorization": API_KEYS["chaos"]}))
    return ["{}.{}".format(s, domain) for s in data.get("subdomains", [])]


def src_shodan(domain):
    data = json.loads(http_get(
        "https://api.shodan.io/dns/domain/{}?key={}".format(domain, API_KEYS["shodan"]), 25))
    names = ["{}.{}".format(s, domain) for s in data.get("subdomains", [])]
    for rec in data.get("data", []):
        sub = rec.get("subdomain")
        if sub:
            names.append("{}.{}".format(sub, domain))
    return names


def src_fullhunt(domain):
    data = json.loads(http_get(
        "https://fullhunt.io/api/v1/domain/{}/subdomains".format(domain),
        25, {"X-API-KEY": API_KEYS["fullhunt"]}))
    return data.get("hosts", [])


def src_bevigil(domain):
    data = json.loads(http_get(
        "https://osint.bevigil.com/api/{}/subdomains/".format(domain),
        25, {"X-Access-Token": API_KEYS["bevigil"]}))
    return data.get("subdomains", [])


SOURCES = {
    "crtsh": src_crtsh,
    "certspotter": src_certspotter,
    "digitorus": src_digitorus,
    "hackertarget": src_hackertarget,
    "otx": src_otx,
    "otx-urls": src_otx_urls,
    "anubis": src_anubis,
    "wayback": src_wayback,
    "urlscan": src_urlscan,
    "rapiddns": src_rapiddns,
    "threatminer": src_threatminer,
    "threatcrowd": src_threatcrowd,
    "sublist3r": src_sublist3r,
    "columbus": src_columbus,
}

# only used when the matching API key is configured
KEY_SOURCES = {
    "virustotal": src_virustotal,
    "securitytrails": src_securitytrails,
    "chaos": src_chaos,
    "shodan": src_shodan,
    "fullhunt": src_fullhunt,
    "bevigil": src_bevigil,
}

# crt.sh is the biggest source but often slow/flaky, so it gets more tries
RETRY = {"crtsh": 3}
RETRY_ON_TIMEOUT = {"crtsh"}


def active_sources():
    srcs = dict(SOURCES)
    for name, fn in KEY_SOURCES.items():
        if name in API_KEYS:
            srcs[name] = fn
    return srcs


def _run_source(name, fn, domain):
    """Run one source. Returns (names, error_text_or_None)."""
    attempts = RETRY.get(name, 2)
    err = "failed"
    for attempt in range(1, attempts + 1):
        try:
            return fn(domain), None
        except urllib.error.HTTPError as e:
            err = "HTTP {}".format(e.code)
            if e.code in (400, 401, 403, 404):
                break
        except Exception as e:
            timed_out = isinstance(e, (socket.timeout, TimeoutError)) or \
                isinstance(getattr(e, "reason", None), socket.timeout)
            err = "timeout" if timed_out else type(e).__name__
            if timed_out and name not in RETRY_ON_TIMEOUT:
                break
        if attempt < attempts:
            time.sleep(1.5 * attempt)
    return [], err


def passive_enum(domain, quiet=False, deadline=60, verbose=False):
    """Query all passive sources in parallel. Slow sources are cut off at
    `deadline` seconds so one bad source can't block the whole scan."""
    srcs = active_sources()
    found = set()
    stats = {}
    lock = threading.Lock()

    def worker(name, fn):
        try:
            raw, err = _run_source(name, fn, domain)
            names = clean(raw, domain)
        except Exception as e:
            names, err = set(), type(e).__name__
        with lock:
            found.update(names)
            stats[name] = (len(names), err)

    threads = [threading.Thread(target=worker, args=(n, fn), daemon=True)
               for n, fn in srcs.items()]
    for t in threads:
        t.start()

    t0 = time.time()
    with Spinner("Loading", quiet) as sp:
        while time.time() - t0 < deadline and any(t.is_alive() for t in threads):
            with lock:
                n = len(found)
            sp.text = "Loading ({} found)".format(n) if n else "Loading"
            time.sleep(0.2)

    with lock:
        result = set(found)
        snap = dict(stats)
    log("[+] Passive sources: {} candidates".format(len(result)), quiet)
    if verbose:
        for name in srcs:
            if name in snap:
                n, err = snap[name]
                state = "FAILED ({})".format(err) if err else "{} names".format(n)
            else:
                state = "too slow, skipped (raise --timeout)"
            log("    {:<15} {}".format(name, state), quiet)
    return result


# ------------------------------------------------------------ active: brute
def load_words(path):
    if not path:
        return DEFAULT_WORDS
    with open(path, encoding="utf-8", errors="ignore") as f:
        words = [w.strip().lower() for w in f if w.strip() and not w.startswith("#")]
    return [w for w in dict.fromkeys(words) if LABEL_RE.match(w)]


def permutations(subs, domain, limit=50000):
    """Alterations of the left-most label: dev-api, api-dev, api2, api-3 ...
    (built under the same parent, so a.b.example.com -> dev-a.b.example.com)."""
    known = set(subs)
    out = set()
    for s in sorted(known):
        if "." not in s:
            continue
        label, parent = s.split(".", 1)
        if not parent.endswith(domain):
            continue
        for p in PERM_PREFIXES:
            out.add("{}-{}.{}".format(p, label, parent))
            out.add("{}-{}.{}".format(label, p, parent))
        m = re.match(r"^(.*?)(\d+)$", label)
        base = m.group(1) if m else label
        for i in range(1, 6):
            out.add("{}{}.{}".format(base, i, parent))
            out.add("{}-{}.{}".format(base.rstrip("-"), i, parent))
    out = [h for h in out - known if LABEL_RE.match(h.split(".", 1)[0])]
    random.shuffle(out)
    return set(out[:limit])


# ------------------------------------------------------------ DNS (fast, raw UDP)
DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "8.8.4.4", "1.0.0.1"]
RESOLVERS = list(DEFAULT_RESOLVERS)
USE_RAW = False


def _build_query(name, qtype, qid):
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(struct.pack("B", len(p)) + p.encode("ascii")
                     for p in name.rstrip(".").split("."))
    return header + qname + b"\x00" + struct.pack(">HH", qtype, 1)


def _skip_name(buf, off):
    while True:
        length = buf[off]
        if length == 0:
            return off + 1
        if length & 0xC0 == 0xC0:
            return off + 2
        off += length + 1


def _read_name(buf, off):
    labels, hops = [], 0
    while True:
        length = buf[off]
        if length == 0:
            break
        if length & 0xC0 == 0xC0:
            off = ((length & 0x3F) << 8) | buf[off + 1]
            hops += 1
            if hops > 20:
                raise ValueError("compression loop")
            continue
        labels.append(buf[off + 1:off + 1 + length].decode("ascii", "ignore"))
        off += length + 1
    return ".".join(labels)


def _parse_response(buf):
    if len(buf) < 12:
        raise ValueError("short packet")
    _id, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", buf[:12])
    rcode = flags & 0x000F
    off = 12
    for _ in range(qd):
        off = _skip_name(buf, off) + 4
    toks = []
    for _ in range(an):
        off = _skip_name(buf, off)
        rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", buf[off:off + 10])
        off += 10
        rdata = buf[off:off + rdlen]
        if rtype == 1 and rdlen == 4:
            toks.append(socket.inet_ntoa(rdata))
        elif rtype == 28 and rdlen == 16:
            toks.append(socket.inet_ntop(socket.AF_INET6, rdata))
        elif rtype == 5:
            toks.append("cname:" + _read_name(buf, off).lower())
        elif rtype == 2:
            toks.append("ns:" + _read_name(buf, off).lower())
        elif rtype == 15 and rdlen > 2:
            toks.append("mx:" + _read_name(buf, off + 2).lower())
        elif rtype == 33 and rdlen > 6:
            toks.append("srv:" + _read_name(buf, off + 6).lower())
        off += rdlen
    return rcode, toks


def dns_query(host, qtype, server, timeout=2.0):
    qid = random.getrandbits(16)
    pkt = _build_query(host, qtype, qid)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.settimeout(timeout)
        s.sendto(pkt, (server, 53))
        while True:
            data, addr = s.recvfrom(4096)
            if addr[0] == server and len(data) >= 12 and \
                    struct.unpack(">H", data[:2])[0] == qid:
                return _parse_response(data)
    finally:
        s.close()


def resolve_raw(host, tries=3, timeout=2.0):
    """Returns a list (empty = does not exist) or None if resolvers failed."""
    for _ in range(tries):
        server = random.choice(RESOLVERS)
        try:
            rcode, toks = dns_query(host, 1, server, timeout)
            if rcode == 3:                      # NXDOMAIN
                return []
            if rcode != 0:                      # SERVFAIL / REFUSED -> retry
                continue
            if toks:
                return sorted(set(toks))
            rcode, toks = dns_query(host, 28, server, timeout)   # IPv6-only host?
            return sorted(set(toks)) if rcode == 0 else []
        except (OSError, ValueError, struct.error, IndexError):
            continue
    return None


def resolve_system(host):
    try:
        infos = socket.getaddrinfo(host, None)
        return sorted({i[4][0] for i in infos})
    except (socket.gaierror, socket.timeout, UnicodeError, OSError):
        return []


def resolve(host):
    if USE_RAW:
        r = resolve_raw(host)
        if r is not None:
            return r
    return resolve_system(host)


def init_dns(custom=None):
    """Pick working resolvers. Falls back to the system resolver if UDP/53
    to public resolvers is blocked."""
    global RESOLVERS, USE_RAW
    servers = []
    for s in (custom or DEFAULT_RESOLVERS):
        s = s.strip()
        try:
            socket.inet_aton(s)
            servers.append(s)
        except OSError:
            pass
    if not servers:
        servers = list(DEFAULT_RESOLVERS)

    def alive(s):
        try:
            return dns_query("example.com", 1, s, 1.5)[0] == 0
        except Exception:
            return False

    with cf.ThreadPoolExecutor(max_workers=len(servers)) as ex:
        flags = list(ex.map(alive, servers))
    good = [s for s, ok in zip(servers, flags) if ok]
    RESOLVERS = good or servers
    USE_RAW = bool(good)
    return USE_RAW


def wildcard_ips(domain):
    ips = set()
    for _ in range(3):
        rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
        ips |= set(resolve("{}.{}".format(rnd, domain)))
    return ips


def dns_record_names(domain):
    """Harvest hostnames from the domain's own DNS records: NS, MX and a set of
    common SRV records. Needs the raw resolver (UDP/53 to public resolvers)."""
    if not USE_RAW:
        return set()

    def q(job):
        host, qtype = job
        for _ in range(2):
            try:
                rcode, toks = dns_query(host, qtype, random.choice(RESOLVERS), 2.0)
                if rcode == 3:
                    return []
                if rcode == 0:
                    return toks
            except Exception:
                continue
        return []

    jobs = [(domain, 2), (domain, 15)]
    jobs += [("{}.{}".format(s, domain), 33) for s in SRV_LABELS]
    names = []
    with cf.ThreadPoolExecutor(max_workers=10) as ex:
        for toks in ex.map(q, jobs):
            for t in toks:
                if ":" in t and t.split(":", 1)[0] in ("ns", "mx", "srv", "cname"):
                    names.append(t.split(":", 1)[1])
    return clean(names, domain)


def cname_targets(results, domain):
    """In-scope hostnames that live hosts point to via CNAME."""
    out = set()
    for ips in results.values():
        for t in ips:
            if t.startswith("cname:"):
                out.add(t[6:])
    return clean(out, domain)


def recursive_candidates(live_hosts, domain, threads):
    """x.<found>.domain for a small wordlist, skipping parents that have
    wildcard DNS. Limited to 150 parents so it stays fast."""
    depth = domain.count(".")
    parents = [h for h in sorted(live_hosts) if h.count(".") - depth <= 2][:150]

    def check(p):
        return p, wildcard_ips(p)

    cands = set()
    with cf.ThreadPoolExecutor(max_workers=max(1, min(threads, 30))) as ex:
        for p, w in ex.map(check, parents):
            if not w:
                cands.update("{}.{}".format(x, p) for x in RECURSIVE_WORDS)
    return cands


def _shutdown_now(ex, futs):
    for f in futs:
        f.cancel()
    ex.shutdown(wait=False)


def resolve_all(hosts, threads, wild, sp=None, label="Resolving"):
    live = {}
    total = len(hosts)
    done = 0
    ex = cf.ThreadPoolExecutor(max_workers=threads)
    futs = {}
    try:
        futs = {ex.submit(resolve, h): h for h in hosts}
        for fut in cf.as_completed(futs):
            ips = fut.result()
            if ips and not (wild and set(ips) <= wild):
                live[futs[fut]] = ips
            done += 1
            if sp is not None and done % 25 == 0:
                sp.text = "{} {}/{} ({} live)".format(label, done, total, len(live))
    except KeyboardInterrupt:
        _shutdown_now(ex, futs)
        raise
    ex.shutdown(wait=False)
    return live


# ------------------------------------------------------------ HTTP probe
def probe(host, timeout=6):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for scheme in ("https", "http"):
        url = "{}://{}".format(scheme, host)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                body = r.read(60000).decode("utf-8", errors="ignore")
                return _info(url, r.status, r.headers.get("Server", ""), body)
        except urllib.error.HTTPError as e:
            body = e.read(60000).decode("utf-8", errors="ignore")
            return _info(url, e.code, e.headers.get("Server", ""), body)
        except Exception:
            continue
    return {"url": "", "status": None, "server": "", "title": ""}


def _info(url, status, server, body):
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    title = re.sub(r"\s+", " ", m.group(1)).strip()[:80] if m else ""
    return {"url": url, "status": status, "server": server, "title": title}


def probe_all(hosts, threads):
    res = {}
    ex = cf.ThreadPoolExecutor(max_workers=threads)
    futs = {}
    try:
        futs = {ex.submit(probe, h): h for h in hosts}
        for fut in cf.as_completed(futs):
            res[futs[fut]] = fut.result()
    except KeyboardInterrupt:
        _shutdown_now(ex, futs)
        raise
    ex.shutdown(wait=False)
    return res


# ------------------------------------------------------------ output
def save(path, rows):
    ext = path.rsplit(".", 1)[-1].lower() if "." in path else "txt"
    if ext == "json":
        with open(path, "w", encoding="utf-8") as f:
            json.dump(rows, f, indent=2, ensure_ascii=False)
    elif ext == "csv":
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["subdomain", "ips", "url", "status", "server", "title"])
            for r in rows:
                w.writerow([r["subdomain"], " ".join(r["ips"]), r.get("url", ""),
                            r.get("status", ""), r.get("server", ""), r.get("title", "")])
    else:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(r["subdomain"] for r in rows) + "\n")


# ------------------------------------------------------------ self-update
def _ver(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)) or (0,)


def _script_version(text):
    m = re.search(r'^__version__\s*=\s*"([^"]+)"', text, re.M)
    return m.group(1) if m else None


def do_update():
    """Update Sublist to the latest version from GitHub.
    - installed with `git clone`  -> git pull
    - otherwise                   -> download Sublist.py from REPO and replace it
    """
    me = os.path.realpath(os.path.abspath(__file__))
    folder = os.path.dirname(me)
    print("[*] Current version: v{}".format(__version__))

    # 1) git clone installs (the recommended way)
    if os.path.isdir(os.path.join(folder, ".git")) and shutil.which("git"):
        print("[*] Git repository detected, running 'git pull' ...")
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
        try:
            p = subprocess.run(["git", "-C", folder, "pull", "--ff-only"],
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL, universal_newlines=True,
                               timeout=120, env=env)
        except Exception as e:
            print("[!] git failed ({})".format(type(e).__name__))
            return 1
        print(p.stdout.strip())
        if p.returncode != 0:
            print("[!] Update failed. If you edited Sublist.py yourself, run "
                  "'git stash' (or 'git checkout Sublist.py') in {} and try again.".format(folder))
            return 1
        try:
            with open(me, encoding="utf-8", errors="ignore") as f:
                new = _script_version(f.read())
        except OSError:
            new = None
        if new and _ver(new) > _ver(__version__):
            print("[+] Updated: v{} -> v{}".format(__version__, new))
        else:
            print("[+] You already have the latest version (v{}).".format(__version__))
        return 0

    # 2) plain file installs: download the new Sublist.py
    if "YOUR_GITHUB_USERNAME" in REPO:
        print("[!] Update source is not configured.")
        print("    Open {} and set REPO = \"username/Sublist\" at the top.".format(me))
        return 1
    url = RAW_URL.format(repo=REPO, branch=BRANCH, script=SCRIPT_NAME)
    print("[*] Checking {} ...".format(url))
    try:
        code = http_get(url, 30)
    except Exception as e:
        print("[!] Could not download the update ({}).".format(type(e).__name__))
        return 1

    remote = _script_version(code)
    if not remote or "def main" not in code:
        print("[!] Downloaded file does not look like Sublist. Update cancelled.")
        return 1
    try:
        compile(code, SCRIPT_NAME, "exec")
    except SyntaxError:
        print("[!] Downloaded file is broken. Update cancelled.")
        return 1
    if _ver(remote) <= _ver(__version__):
        print("[+] You already have the latest version (v{}).".format(__version__))
        return 0

    try:
        shutil.copy2(me, me + ".bak")
        tmp = me + ".new"
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            f.write(code)
        try:
            shutil.copymode(me, tmp)
        except OSError:
            pass
        os.replace(tmp, me)
    except PermissionError:
        print("[!] Permission denied. Try: sudo {} -update".format(
            "python3 " + me if not os.access(me, os.X_OK) else me))
        return 1
    except OSError as e:
        print("[!] Update failed ({}).".format(e))
        return 1
    print("[+] Updated: v{} -> v{}  (backup: {}.bak)".format(__version__, remote, me))
    return 0


# ------------------------------------------------------------ main
class SublistParser(argparse.ArgumentParser):
    """Prints the Sublist banner above the help text."""

    def print_help(self, file=None):
        (file or sys.stdout).write(BANNER + "\n")
        super().print_help(file)


def build_parser():
    ap = SublistParser(
        prog="Sublist",
        description="Sublist - subdomain finder by Sujoy Karmakar. "
                    "Use only on domains you are authorized to test.",
        epilog="examples:\n"
               "  Sublist -d example.com\n"
               "  Sublist -d example.com -b -p -R --probe -o result.json\n"
               "  Sublist -d example.com -b -w words.txt -t 200 -q\n"
               "  Sublist -d example.com -a -v       (also keep names without live DNS)\n"
               "  Sublist -update\n"
               "\n"
               "more results with free API keys (env vars or ~/.sublist.json):\n"
               "  VIRUSTOTAL_API_KEY  SECURITYTRAILS_API_KEY  CHAOS_API_KEY\n"
               "  SHODAN_API_KEY  FULLHUNT_API_KEY  BEVIGIL_API_KEY",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-d", "--domain", help="target domain (example.com)")
    ap.add_argument("-b", "--brute", action="store_true", help="enable DNS brute-force (active)")
    ap.add_argument("-w", "--wordlist", help="custom wordlist file for brute-force")
    ap.add_argument("-p", "--permute", action="store_true", help="try permutations of found names")
    ap.add_argument("-R", "--recursive", action="store_true",
                    help="also brute-force a small wordlist under every found subdomain")
    ap.add_argument("-a", "--all", action="store_true",
                    help="also list passive names that do not resolve in DNS "
                         "(like subfinder does; marked [no DNS])")
    ap.add_argument("--no-passive", action="store_true", help="skip passive sources")
    ap.add_argument("--no-resolve", action="store_true", help="do not DNS-validate results")
    ap.add_argument("--probe", action="store_true", help="HTTP probe live hosts (status, title, server)")
    ap.add_argument("-t", "--threads", type=int, default=150, help="threads (default 150)")
    ap.add_argument("--timeout", type=int, default=60,
                    help="max seconds to wait for passive sources (default 60)")
    ap.add_argument("-r", "--resolvers",
                    help="comma-separated DNS resolvers (default 1.1.1.1,8.8.8.8,9.9.9.9)")
    ap.add_argument("-o", "--output", help="save results (.txt / .json / .csv)")
    ap.add_argument("-q", "--quiet", action="store_true", help="print only results")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="show how many names each source returned (and which ones failed)")
    ap.add_argument("-U", "-update", "--update", action="store_true", dest="update",
                    help="update Sublist to the latest version")
    ap.add_argument("-V", "--version", action="store_true", help="show version and exit")
    return ap


def main():
    ap = build_parser()

    # Just "python Sublist.py" with nothing else -> show full help
    if len(sys.argv) == 1:
        ap.print_help()
        sys.exit(0)

    args = ap.parse_args()

    if args.version:
        print("Sublist v{}".format(__version__))
        sys.exit(0)

    if args.update:
        log(BANNER)
        sys.exit(do_update())

    if not args.domain:
        ap.print_help()
        sys.exit("\nError: -d/--domain is required")

    domain = args.domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
    if not DOMAIN_RE.match(domain):
        sys.exit("Error: invalid domain '{}'".format(args.domain))

    threads = max(1, min(args.threads, 1000))
    API_KEYS.clear()
    API_KEYS.update(load_keys())

    log(BANNER, args.quiet)
    log("[*] Target: {}".format(domain), args.quiet)
    if args.verbose and API_KEYS:
        log("[*] API keys loaded: {}".format(", ".join(sorted(API_KEYS))), args.quiet)
    elif args.verbose:
        log("[*] No API keys set (adding free keys finds more subdomains, see -h)", args.quiet)
    start = time.time()
    found = set()
    passive_names = set()

    if not args.no_passive:
        passive_names = passive_enum(domain, args.quiet, max(5, args.timeout), args.verbose)
        found |= passive_names

    if args.brute:
        words = load_words(args.wordlist)
        log("[*] Brute-forcing {} words...".format(len(words)), args.quiet)
        found |= {"{}.{}".format(w, domain) for w in words}

    if args.no_resolve:
        if not found:
            sys.exit("No candidates found. Try --brute or check your internet connection.")
        if args.permute:
            extra = permutations(found, domain)
            log("[*] Permutations: {} extra candidates".format(len(extra)), args.quiet)
            found |= extra
        results = {h: [] for h in found}
    else:
        custom = args.resolvers.split(",") if args.resolvers else None
        raw_mode = init_dns(custom)
        if args.verbose:
            log("[*] DNS mode: {}".format(
                "fast raw UDP ({})".format(", ".join(RESOLVERS)) if raw_mode
                else "system resolver (UDP/53 to public resolvers is blocked)"), args.quiet)

        from_dns = dns_record_names(domain)
        if from_dns:
            log("[+] DNS records (NS/MX/SRV): {} names".format(len(from_dns)), args.quiet)
            found |= from_dns
            passive_names |= from_dns

        if not found:
            sys.exit("No candidates found. Try --brute or check your internet connection.")

        wild = wildcard_ips(domain)
        if wild:
            log("[!] Wildcard DNS detected, filtering fake results", args.quiet)

        known = set(found)
        with Spinner("Resolving {} candidates".format(len(found)), args.quiet) as sp:
            results = resolve_all(found, threads, wild, sp)

        # follow CNAME targets that point back into the target domain
        for _ in range(2):
            extra = cname_targets(results, domain) - known
            if not extra:
                break
            known |= extra
            log("[*] CNAME targets: {} new candidates".format(len(extra)), args.quiet)
            with Spinner("Resolving CNAME targets", args.quiet) as sp:
                results.update(resolve_all(extra, threads, wild, sp, "CNAME"))

        if args.permute and results:
            extra = permutations(list(results), domain) - known
            if extra:
                known |= extra
                log("[*] Permutations: {} extra candidates".format(len(extra)), args.quiet)
                with Spinner("Resolving permutations", args.quiet) as sp:
                    results.update(resolve_all(extra, threads, wild, sp, "Permutations"))

        if args.recursive and results:
            with Spinner("Preparing recursive scan", args.quiet):
                extra = recursive_candidates(list(results), domain, threads) - known
            if extra:
                known |= extra
                log("[*] Recursive: {} extra candidates".format(len(extra)), args.quiet)
                with Spinner("Resolving recursive", args.quiet) as sp:
                    results.update(resolve_all(extra, threads, wild, sp, "Recursive"))

    unresolved = set()
    if args.all and not args.no_resolve:
        unresolved = passive_names - set(results)
        if unresolved:
            log("[*] Keeping {} passive names without live DNS (-a)".format(len(unresolved)),
                args.quiet)

    probes = {}
    if args.probe and results:
        with Spinner("HTTP probing {} hosts".format(len(results)), args.quiet):
            probes = probe_all(list(results), min(threads, 50))

    rows = []
    for host in sorted(set(results) | unresolved):
        row = {"subdomain": host, "ips": results.get(host, [])}
        row.update(probes.get(host, {}))
        if host in unresolved:
            row["resolved"] = False
        rows.append(row)

    log("", args.quiet)
    for r in rows:
        line = r["subdomain"]
        if r.get("resolved") is False:
            line += "  [no DNS]"
        if args.probe and r.get("status"):
            line += "  [{}] {}  {}".format(r["status"], r.get("server", ""), r.get("title", ""))
        print(line)

    log("\n[*] Done: {} subdomains in {:.1f}s".format(len(rows), time.time() - start), args.quiet)
    if args.output:
        save(args.output, rows)
        log("[*] Saved to {}".format(args.output), args.quiet)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\n[!] Interrupted by user")
