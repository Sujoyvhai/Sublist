#!/usr/bin/env python3
"""
Sublist - a simple subdomain enumeration tool
Author : Sujoy Karmakar
License: MIT

Use only on domains you own or have written permission to test.
"""

import argparse
import base64
import concurrent.futures as cf
import csv
import html
import http.client
import itertools
import json
import os
import queue
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
import urllib.parse
import urllib.request

__version__ = "1.6.0"
__author__ = "Sujoy Karmakar"

# ---- update settings -------------------------------------------------------
# Used by `Sublist -update` when the tool was NOT installed with `git clone`.
# Change this to your GitHub "username/repository" before publishing.
REPO = "YOUR_GITHUB_USERNAME/Sublist"
WORDLIST_REPO = "Sujoyvhai/subdomin-wordlist"   # auto-downloaded wordlist
WORDLIST_CACHE = os.path.expanduser("~/.sublist/wordlist.txt")
WORDLIST_MAX_AGE = 7 * 86400                      # re-check GitHub every 7 days
BRANCH = "main"
SCRIPT_NAME = "sublist.py"
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
    "google_cse": "GOOGLE_CSE_KEY",      # optional: Google Custom Search API key (for --dork)
    "google_cx": "GOOGLE_CSE_CX",        # optional: Google Custom Search engine id (for --dork)
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
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
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



# ------------------------------------------------------------------ hacker colors
# Matrix-style palette: different shades of green plus a few neon colors.
# Every output line gets a random one, so the screen "flickers" like a terminal.
HACKER_COLORS = [46, 82, 118, 154, 40, 34, 48, 49, 51, 45, 226, 208, 201, 196]
USE_COLOR = True


def _color_ok(stream):
    if not USE_COLOR or os.environ.get("NO_COLOR"):
        return False
    try:
        return stream.isatty()
    except Exception:
        return False


def paint(text, stream=None, code=None):
    """Wrap text in a random hacker color (only when writing to a terminal)."""
    if not _color_ok(stream or sys.stdout):
        return text
    code = code if code is not None else random.choice(HACKER_COLORS)
    return "\033[1;38;5;{}m{}\033[0m".format(code, text)


def rainbow(text, stream=None):
    """Each line of a block gets its own random color (used for the banner)."""
    return "\n".join(paint(line, stream) for line in text.split("\n"))


if os.name == "nt":          # enable ANSI colors on Windows 10+
    os.system("")

# ------------------------------------------------------------------ helpers
def log(msg, quiet=False):
    if not quiet:
        if msg.lstrip().startswith(("[", "    ")) or msg == BANNER:
            msg = paint(msg, sys.stderr)
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
            sys.stderr.write("\r" + paint("[*] {} {}   ".format(self.text, ch), sys.stderr))
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


# ------------------------------------------------------------ search-engine dorking
# Google-dork style discovery (option --dork). Plain search-engine result pages
# are scraped, no API key needed:
#   1) site:domain -site:known1 -site:known2 ...   (repeated until nothing new)
#   2) site:<one of 100+ third-party sites> "domain"   (github, pastebin, trello ...)
#   3) a few generic dorks (inurl, filetype ...)
# Queries are spread over several engines. Google blocks scripts very fast, so it
# is only "best effort"; with a free Google Custom Search key (google_cse +
# google_cx in ~/.sublist.json) the main dork also runs through Google's real API.
DORK_SITES = """
github.com gist.github.com raw.githubusercontent.com gitlab.com bitbucket.org sourceforge.net
codeberg.org gitee.com launchpad.net npmjs.com pypi.org rubygems.org packagist.org nuget.org
crates.io hub.docker.com stackoverflow.com stackexchange.com serverfault.com superuser.com
askubuntu.com codepen.io jsfiddle.net replit.com glitch.com codesandbox.io stackblitz.com
observablehq.com kaggle.com huggingface.co postman.com swagger.io apiary.io readthedocs.io
gitbook.io pastebin.com paste.ee ideone.com hastebin.com controlc.com justpaste.it dpaste.com
rentry.co paste.debian.net pastie.io privatebin.net 0bin.net docs.google.com drive.google.com
sites.google.com trello.com notion.so notion.site airtable.com scribd.com slideshare.net
issuu.com academia.edu researchgate.net archive.org web.archive.org wikipedia.org medium.com
dev.to hashnode.com substack.com wordpress.com blogspot.com tumblr.com wixsite.com weebly.com
linkedin.com facebook.com twitter.com x.com instagram.com reddit.com quora.com youtube.com
pinterest.com t.me discord.com tiktok.com vk.com virustotal.com shodan.io censys.io urlscan.io
securitytrails.com crt.sh hackerone.com bugcrowd.com openbugbounty.org exploit-db.com
cvedetails.com otx.alienvault.com threatcrowd.org dnsdumpster.com who.is builtwith.com
wappalyzer.com similarweb.com netcraft.com robtex.com viewdns.info mxtoolbox.com intelx.io
leakix.net zoomeye.org fofa.info binaryedge.io greynoise.io s3.amazonaws.com amazonaws.com
blob.core.windows.net storage.googleapis.com firebaseio.com appspot.com herokuapp.com
netlify.app vercel.app pages.dev workers.dev azurewebsites.net cloudfront.net
digitaloceanspaces.com dropbox.com box.com onedrive.live.com mega.nz wetransfer.com
crunchbase.com glassdoor.com indeed.com
""".split()
DORK_SITES = list(dict.fromkeys(DORK_SITES))

DORK_EXTRA = [
    '"*.{d}" -www.{d}',
    'inurl:"{d}" -site:{d}',
    'intext:"{d}" -site:{d}',
    'filetype:txt "{d}"',
    'filetype:xml "{d}"',
    'filetype:json "{d}"',
    'filetype:log "{d}"',
    'filetype:conf "{d}"',
    'filetype:pdf "{d}" -site:{d}',
]


def _q(s):
    return urllib.parse.quote_plus(s)


# name -> (url builder(query, page), seconds to wait between requests)
DORK_ENGINES = {
    "bing": (lambda q, p: "https://www.bing.com/search?q={}&first={}&count=50".format(
        _q(q), p * 50 + 1), 1.0),
    "duckduckgo": (lambda q, p: "https://html.duckduckgo.com/html/?q={}&s={}".format(
        _q(q), p * 30), 2.5),
    "yahoo": (lambda q, p: "https://search.yahoo.com/search?p={}&b={}".format(
        _q(q), p * 10 + 1), 1.5),
    "brave": (lambda q, p: "https://search.brave.com/search?q={}&offset={}".format(
        _q(q), p), 2.0),
    "mojeek": (lambda q, p: "https://www.mojeek.com/search?q={}&s={}".format(
        _q(q), p * 10 + 1), 1.5),
    "google": (lambda q, p: "https://www.google.com/search?q={}&num=100&hl=en&start={}".format(
        _q(q), p * 100), 4.0),
    "googlecse": (lambda q, p: "https://www.googleapis.com/customsearch/v1?key={}&cx={}&q={}&start={}".format(
        API_KEYS.get("google_cse", ""), API_KEYS.get("google_cx", ""), _q(q), p * 10 + 1), 0.4),
}

_BLOCK_MARKERS = ("captcha", "unusual traffic", "/sorry/", "are you a robot",
                  "verify you are human", "enablejs", "anomaly", "access denied")
_DORK_LOCK = threading.Lock()
_DORK_ST = {}
_RR = itertools.count()


class _Blocked(Exception):
    pass


def _dork_reset():
    _DORK_ST.clear()
    for n in DORK_ENGINES:
        _DORK_ST[n] = {"next": 0.0, "bad": 0, "ok": 0, "fail": 0, "names": 0}


def _dork_usable(name, main_only=False):
    """main_only=True -> called for the site:domain loop (googlecse allowed)."""
    if _DORK_ST[name]["bad"] >= 3:
        return False
    if name == "googlecse":
        return main_only and "google_cse" in API_KEYS and "google_cx" in API_KEYS
    return True


def _dork_pick():
    with _DORK_LOCK:
        ok = [n for n in DORK_ENGINES if _dork_usable(n)]
    return ok[next(_RR) % len(ok)] if ok else None


def _dork_note(engine, ok, n=0):
    with _DORK_LOCK:
        st = _DORK_ST[engine]
        if ok:
            st["bad"] = 0
            st["ok"] += 1
            st["names"] += n
        else:
            st["bad"] += 1
            st["fail"] += 1


def _dork_extract(raw, domain):
    """Pull every hostname under `domain` out of a search-result page."""
    text = html.unescape(raw).lower()
    flat = urllib.parse.unquote(text)
    plain = re.sub(r"<[^>]+>", "", flat)
    rx = re.compile(r"((?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.){1,8}" + re.escape(domain)
                    + r")(?![a-z0-9\-]|\.[a-z0-9])")
    names = set(rx.findall(flat)) | set(rx.findall(plain))
    for m in re.finditer(r"[?&;]u=a1([a-z0-9_\-]+)", raw, re.I):     # Bing wraps links in base64
        try:
            b = m.group(1)
            dec = base64.urlsafe_b64decode(b + "=" * (-len(b) % 4)).decode("utf-8", "ignore")
            names.update(rx.findall(urllib.parse.unquote(dec).lower()))
        except Exception:
            pass
    return clean(names, domain)


def _dork_search(engine, query, domain, page=0):
    """One search request. Returns the set of subdomains seen on the page.
    Raises _Blocked when the engine shows a captcha / rate limit."""
    builder, gap = DORK_ENGINES[engine]
    with _DORK_LOCK:                              # polite, per-engine pacing
        st = _DORK_ST[engine]
        now = time.time()
        wait = max(0.0, st["next"] - now)
        st["next"] = now + wait + gap * random.uniform(1.0, 1.6)
    if wait:
        time.sleep(wait)
    headers = {"User-Agent": BROWSER_UA,
               "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
               "Accept-Language": "en-US,en;q=0.9"}
    if engine == "google":
        headers["Cookie"] = "CONSENT=YES+cb; SOCS=CAI"
    req = urllib.request.Request(builder(query, page), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read(800000).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        if e.code in (202, 403, 429, 503):
            raise _Blocked(str(e.code))
        raise
    names = _dork_extract(raw, domain)
    if not names and any(m in raw.lower() for m in _BLOCK_MARKERS):
        raise _Blocked("captcha")
    return names


def _dork_main_loop(engine, domain, found, lock, t_end):
    """site:domain -site:a -site:b ...  repeated, excluding what we already saw."""
    excl = ["www." + domain]
    seen = set(excl)
    for _ in range(10):
        if time.time() > t_end or not _dork_usable(engine, True):
            return
        q = "site:{} {}".format(domain, " ".join("-site:" + h for h in excl[-14:]))
        try:
            names = _dork_search(engine, q, domain)
        except Exception:
            _dork_note(engine, False)
            return
        new = names - seen
        _dork_note(engine, True, len(names))
        if not new:
            return
        seen |= new
        excl.extend(sorted(new))
        with lock:
            found.update(new)


def dork_enum(domain, quiet=False, deadline=120, verbose=False):
    """Search-engine dorking over several engines and 100+ sites."""
    _dork_reset()
    found = set()
    lock = threading.Lock()
    t_end = time.time() + deadline

    jobs = queue.Queue()
    for q in DORK_EXTRA:
        jobs.put(q.format(d=domain))
    for s in DORK_SITES:
        jobs.put('site:{} "{}"'.format(s, domain))
    total = jobs.qsize()

    def worker():
        while time.time() < t_end:
            try:
                qtext = jobs.get_nowait()
            except queue.Empty:
                return
            for _ in range(3):                    # try another engine if one is blocked
                eng = _dork_pick()
                if not eng:
                    return
                try:
                    names = _dork_search(eng, qtext, domain)
                except Exception:
                    _dork_note(eng, False)
                    continue
                _dork_note(eng, True, len(names))
                with lock:
                    found.update(names)
                break

    threads = []
    for eng in DORK_ENGINES:
        threads.append(threading.Thread(target=_dork_main_loop,
                                        args=(eng, domain, found, lock, t_end), daemon=True))
    for _ in range(6):
        threads.append(threading.Thread(target=worker, daemon=True))
    for t in threads:
        t.start()

    with Spinner("Dorking", quiet) as sp:
        while time.time() < t_end and any(t.is_alive() for t in threads):
            with lock:
                n = len(found)
            sp.text = "Dorking {}/{} queries ({} found)".format(total - jobs.qsize(), total, n)
            time.sleep(0.3)

    with lock:
        result = set(found)
    log("[+] Dorking ({} sites + {} generic dorks): {} candidates".format(
        len(DORK_SITES), len(DORK_EXTRA), len(result)), quiet)
    if verbose:
        for name, st in _DORK_ST.items():
            if name == "googlecse" and not (st["ok"] or st["fail"]):
                continue
            state = "{} ok, {} failed, {} hits".format(st["ok"], st["fail"], st["names"])
            if st["bad"] >= 3:
                state += "  (blocked / rate-limited, switched to other engines)"
            log("    {:<11} {}".format(name, state), quiet)
    return result


# ------------------------------------------------------------ active: brute
def _read_words(path):
    with open(path, encoding="utf-8", errors="ignore") as f:
        words = [w.strip().lower() for w in f if w.strip() and not w.startswith("#")]
    return [w for w in dict.fromkeys(words) if LABEL_RE.match(w)]


def _download_wordlist(quiet=False):
    """Find a .txt wordlist inside the GitHub repo (WORDLIST_REPO) and cache it."""
    import json as _json
    api = "https://api.github.com/repos/{}/contents/".format(WORDLIST_REPO)
    files = []
    stack = [api]
    while stack and len(files) < 40:
        raw = http_get(stack.pop(), 20, {"Accept": "application/vnd.github+json"})
        for it in _json.loads(raw):
            if it.get("type") == "dir":
                stack.append(it["url"])
            elif it.get("type") == "file" and it["name"].lower().endswith(".txt") \
                    and it["name"].lower() not in ("requirements.txt", "license.txt"):
                files.append(it)
    if not files:
        raise RuntimeError("no .txt wordlist found in repo")
    # use every list in the repo, merged (biggest first)
    files.sort(key=lambda x: -x.get("size", 0))
    words = []
    for it in files[:5]:
        words += http_get(it["download_url"], 60).splitlines()
    os.makedirs(os.path.dirname(WORDLIST_CACHE), exist_ok=True)
    with open(WORDLIST_CACHE, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(words))
    return len(files[:5])


def auto_wordlist(quiet=False):
    """Wordlist from your GitHub repo (cached). Falls back to the built-in list."""
    fresh = os.path.isfile(WORDLIST_CACHE) and \
        time.time() - os.path.getmtime(WORDLIST_CACHE) < WORDLIST_MAX_AGE
    if not fresh:
        try:
            with Spinner("Fetching wordlist from GitHub ({})".format(WORDLIST_REPO), quiet):
                n = _download_wordlist(quiet)
            log("[+] Wordlist updated ({} file(s))".format(n), quiet)
        except Exception as e:
            log("[!] Could not download wordlist ({}), using {}".format(
                type(e).__name__, "cached copy" if os.path.isfile(WORDLIST_CACHE)
                else "built-in list"), quiet)
    if os.path.isfile(WORDLIST_CACHE):
        words = _read_words(WORDLIST_CACHE)
        if words:
            # keep the built-in words too, so nothing is lost
            return list(dict.fromkeys(words + DEFAULT_WORDS))
    return DEFAULT_WORDS


def load_words(path, quiet=False):
    if not path:
        return auto_wordlist(quiet)
    return _read_words(path)


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


# ------------------------------------------------------------ HTTP probe (status codes)
# Built so the shown status code can be trusted:
#  * a real GET with a browser User-Agent (some servers answer bots differently)
#  * redirects are NOT hidden: [301 -> 200] = the host itself says 301, and the
#    page it redirects to finally answers 200 (final URL is printed too)
#  * flaky answers (429 / 502 / 503 / 504, timeouts, resets) are retried
#  * https is tried first, http only when https gives no answer at all
#  * a host that answers nothing is shown as [no response], never a made-up code
REDIRECT_CODES = (301, 302, 303, 307, 308)
RETRY_CODES = (429, 502, 503, 504)


def _request(scheme, host, port, path, timeout, ctx):
    """One raw GET. Redirects are NOT followed."""
    if scheme == "https":
        conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path or "/", headers={
            "User-Agent": BROWSER_UA,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Connection": "close"})
        r = conn.getresponse()
        try:
            body = r.read(60000).decode("utf-8", errors="ignore")
        except Exception:
            body = ""
        return {"status": r.status, "server": r.getheader("Server", "") or "",
                "location": r.getheader("Location", "") or "", "body": body}
    finally:
        conn.close()


def _get(scheme, host, port, path, timeout, ctx):
    """GET with retries. Returns the response dict or None if nothing answered."""
    errors = 0
    for attempt in range(3):
        try:
            res = _request(scheme, host, port, path, timeout, ctx)
        except Exception:
            errors += 1
            if errors >= 2:
                return None
            time.sleep(0.5)
            continue
        if res["status"] in RETRY_CODES and attempt < 2:
            time.sleep(1.0 + attempt)
            continue
        return res
    return None


def _title(body):
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    return html.unescape(re.sub(r"\s+", " ", m.group(1)).strip())[:80] if m else ""


def probe(host, timeout=8, follow=True):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    out = {"url": "", "status": None, "server": "", "title": "",
           "redirect": "", "final_url": "", "final_status": None}
    for scheme in ("https", "http"):
        url = "{}://{}/".format(scheme, host)
        res = _get(scheme, host, None, "/", timeout, ctx)
        if res is None:
            continue
        out["url"], out["status"] = url, res["status"]
        if res["status"] in REDIRECT_CODES and res["location"]:
            out["redirect"] = urllib.parse.urljoin(url, res["location"])

        cur, cur_url, failed = res, url, False
        seen = {url}
        hops = 0
        while follow and cur["status"] in REDIRECT_CODES and cur["location"] and hops < 6:
            nxt = urllib.parse.urljoin(cur_url, cur["location"])
            try:
                sp = urllib.parse.urlsplit(nxt)
                port = sp.port
            except ValueError:
                break
            if sp.scheme not in ("http", "https") or not sp.hostname or nxt in seen:
                break
            seen.add(nxt)
            hops += 1
            path = (sp.path or "/") + ("?" + sp.query if sp.query else "")
            nres = _get(sp.scheme, sp.hostname, port, path, timeout, ctx)
            if nres is None:                      # redirect target did not answer
                failed, cur_url = True, nxt
                break
            cur, cur_url = nres, nxt

        out["final_url"] = cur_url
        out["final_status"] = "ERR" if failed else cur["status"]
        out["server"] = res["server"] if failed else cur["server"]
        out["title"] = "" if failed else _title(cur["body"])
        return out
    return out


def probe_all(hosts, threads, follow=True):
    res = {}
    ex = cf.ThreadPoolExecutor(max_workers=threads)
    futs = {}
    try:
        futs = {ex.submit(probe, h, 8, follow): h for h in hosts}
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
            w.writerow(["subdomain", "ips", "url", "status", "redirect", "final_url",
                        "final_status", "server", "title"])
            for r in rows:
                w.writerow([r["subdomain"], " ".join(r["ips"]), r.get("url", ""),
                            r.get("status", ""), r.get("redirect", ""), r.get("final_url", ""),
                            r.get("final_status", ""), r.get("server", ""), r.get("title", "")])
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



# ------------------------------------------------------------ install as `sublist`
def do_install():
    """Install this script as a command named `sublist` (no 'python' needed)."""
    me = os.path.realpath(os.path.abspath(__file__))
    if os.name == "nt":
        folder = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "Sublist")
        os.makedirs(folder, exist_ok=True)
        dest = os.path.join(folder, "sublist.py")
        shutil.copy2(me, dest)
        bat = os.path.join(folder, "sublist.bat")
        with open(bat, "w") as f:
            f.write('@echo off\r\n"{}" "{}" %*\r\n'.format(sys.executable, dest))
        print("[+] Installed: {}".format(bat))
        print("[*] Add this folder to PATH once:  {}".format(folder))
        print("    Then open a NEW terminal and type:  sublist -d example.com")
        return 0
    targets = ["/usr/local/bin", os.path.expanduser("~/.local/bin")]
    for folder in targets:
        try:
            os.makedirs(folder, exist_ok=True)
            dest = os.path.join(folder, "sublist")
            code = open(me, encoding="utf-8").read()
            if not code.startswith("#!"):
                code = "#!/usr/bin/env python3\n" + code
            with open(dest, "w", encoding="utf-8", newline="\n") as f:
                f.write(code)
            os.chmod(dest, 0o755)
        except OSError:
            continue
        print("[+] Installed: {}".format(dest))
        if folder not in os.environ.get("PATH", "").split(os.pathsep):
            print("[!] {} is not in PATH. Run:  echo 'export PATH=$PATH:{}' >> ~/.bashrc".format(
                folder, folder))
        print("    Now just type:  sublist -d example.com")
        return 0
    print("[!] Permission denied. Try:  sudo python3 {} --install".format(me))
    return 1


# ------------------------------------------------------------ main
class SublistParser(argparse.ArgumentParser):
    """Prints the Sublist banner above the help text."""

    def print_help(self, file=None):
        (file or sys.stdout).write(rainbow(BANNER, file or sys.stdout) + "\n")
        super().print_help(file)


def build_parser():
    ap = SublistParser(
        prog="sublist",
        description="Sublist - subdomain finder by Sujoy Karmakar. "
                    "Use only on domains you are authorized to test.",
        epilog="examples:\n"
               "  sublist -d example.com             (auto mode: runs -a -b -p -R -v for you)\n"
               "  sublist -d example.com -o result.json\n"
               "  sublist -d example.com --passive   (passive sources only, fast)\n"
               "  sublist -d example.com --dork      (also dork search engines + 100+ sites)\n"
               "  sublist -d example.com -s          (status codes: [200], [301 -> 200], ...)\n"
               "  sublist -d example.com -b -w words.txt -t 200 -q   (manual mode)\n"
               "  sublist --install                  (install the 'sublist' command)\n"
               "  sublist -update\n"
               "\n"
               "more results with free API keys (env vars or ~/.sublist.json):\n"
               "  VIRUSTOTAL_API_KEY  SECURITYTRAILS_API_KEY  CHAOS_API_KEY\n"
               "  SHODAN_API_KEY  FULLHUNT_API_KEY  BEVIGIL_API_KEY\n"
               "  GOOGLE_CSE_KEY + GOOGLE_CSE_CX  (real Google results for --dork)",
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
    ap.add_argument("--passive", action="store_true",
                    help="passive sources only (turns off the automatic -a -b -p -R -v mode)")
    ap.add_argument("--no-color", action="store_true", help="turn off hacker colors")
    ap.add_argument("--install", action="store_true",
                    help="install as the 'sublist' command (no 'python' needed)")
    ap.add_argument("--no-passive", action="store_true", help="skip passive sources")
    ap.add_argument("--no-resolve", action="store_true", help="do not DNS-validate results")
    ap.add_argument("-s", "--status", "--probe", action="store_true", dest="probe",
                    help="HTTP probe live hosts: status code, redirect target, server, title")
    ap.add_argument("--no-follow", action="store_true",
                    help="with -s: do not follow redirects (show the raw 301/302 only)")
    ap.add_argument("-D", "--dork", action="store_true",
                    help="Google-dork style search: search engines + site: dorks on 100+ sites")
    ap.add_argument("--dork-timeout", type=int, default=120,
                    help="max seconds for --dork (default 120)")
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

    global USE_COLOR
    if args.no_color:
        USE_COLOR = False

    if args.version:
        print("Sublist v{}".format(__version__))
        sys.exit(0)

    if args.install:
        sys.exit(do_install())

    if args.update:
        log(rainbow(BANNER, sys.stderr))
        sys.exit(do_update())

    if not args.domain:
        ap.print_help()
        sys.exit("\nError: -d/--domain is required")

    domain = args.domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
    if not DOMAIN_RE.match(domain):
        sys.exit("Error: invalid domain '{}'".format(args.domain))

    # AUTO MODE: `sublist -d example.com` alone turns on -a -b -p -R -v by itself.
    # Giving any scan flag yourself (-b, -p, -R, -a, --no-passive, ...) or --passive
    # keeps full manual control.
    manual = (args.brute or args.permute or args.recursive or args.all
              or args.no_passive or args.no_resolve or args.wordlist or args.passive)
    if not manual:
        args.brute = args.permute = args.recursive = args.all = args.verbose = True
        log("[*] Auto mode: -a -b -p -R -v enabled", args.quiet)

    threads = max(1, min(args.threads, 1000))
    API_KEYS.clear()
    API_KEYS.update(load_keys())

    log(rainbow(BANNER, sys.stderr) if not args.quiet else "", args.quiet)
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

    if args.dork:
        dork_names = dork_enum(domain, args.quiet, max(20, args.dork_timeout), args.verbose)
        found |= dork_names
        passive_names |= dork_names

    if args.brute:
        words = load_words(args.wordlist, args.quiet)
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
            probes = probe_all(list(results), min(threads, 30), not args.no_follow)

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
        if args.probe:
            st = r.get("status")
            if st:
                fs = r.get("final_status")
                tag = str(st)
                if r.get("redirect") and fs is not None and fs != st:
                    tag = "{} -> {}".format(st, fs)
                line += "  [{}] {}  {}".format(tag, r.get("server", ""), r.get("title", ""))
                if r.get("redirect"):
                    dest = r["final_url"] if r.get("final_url") and r["final_url"] != r.get("url") \
                        else r["redirect"]
                    line += "  => {}".format(dest)
            elif r.get("resolved") is not False:
                line += "  [no response]"
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
