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

__version__ = "1.1.0"
__author__ = "Sujoy Karmakar"

# ---- update settings -------------------------------------------------------
# Used by `Sublist -update` when the tool was NOT installed with `git clone`.
# Change this to your GitHub "username/repository" before publishing.
REPO = "YOUR_GITHUB_USERNAME/Sublist"
BRANCH = "main"
SCRIPT_NAME = "Sublist.py"
RAW_URL = "https://raw.githubusercontent.com/{repo}/{branch}/{script}"
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

DEFAULT_WORDS = list(dict.fromkeys("""
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
""".split()))


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


def http_get(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": UA})
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


# ------------------------------------------------------------ passive sources
def src_crtsh(domain):
    data = json.loads(http_get("https://crt.sh/?q=%25.{}&output=json".format(domain), 30))
    names = []
    for row in data:
        names.extend(row.get("name_value", "").split("\n"))
    return names


def src_certspotter(domain):
    data = json.loads(http_get(
        "https://api.certspotter.com/v1/issuances?domain={}"
        "&include_subdomains=true&expand=dns_names".format(domain), 25))
    names = []
    for row in data:
        names.extend(row.get("dns_names", []))
    return names


def src_hackertarget(domain):
    text = http_get("https://api.hackertarget.com/hostsearch/?q={}".format(domain), 20)
    if "error" in text.lower()[:50]:
        return []
    return [line.split(",")[0] for line in text.splitlines()]


def src_otx(domain):
    data = json.loads(http_get(
        "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns".format(domain), 25))
    return [r.get("hostname", "") for r in data.get("passive_dns", [])]


def src_anubis(domain):
    return json.loads(http_get("https://jldc.me/anubis/subdomains/{}".format(domain), 20))


def src_wayback(domain):
    url = ("https://web.archive.org/cdx/search/cdx?url={}&matchType=domain&output=text"
           "&fl=original&collapse=urlkey&limit=20000".format(domain))
    names = []
    for line in http_get(url, 30).splitlines():
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
    html = http_get("https://rapiddns.io/subdomain/{}?full=1".format(domain), 25).lower()
    return re.findall(r"([a-z0-9][a-z0-9.\-]*\.{})".format(re.escape(domain)), html)


def src_threatminer(domain):
    data = json.loads(http_get(
        "https://api.threatminer.org/v2/domain.php?q={}&rt=5".format(domain), 25))
    return data.get("results", [])


def src_columbus(domain):
    data = json.loads(http_get(
        "https://columbus.elmasy.com/api/subdomains/{}".format(domain), 25))
    return ["{}.{}".format(x, domain) for x in data if isinstance(x, str)]


SOURCES = {
    "crtsh": src_crtsh,
    "certspotter": src_certspotter,
    "hackertarget": src_hackertarget,
    "otx": src_otx,
    "anubis": src_anubis,
    "wayback": src_wayback,
    "urlscan": src_urlscan,
    "rapiddns": src_rapiddns,
    "threatminer": src_threatminer,
    "columbus": src_columbus,
}


def _run_source(fn, domain):
    """Run one source. Retry once on a quick failure, never on a timeout."""
    for attempt in (1, 2):
        try:
            return fn(domain)
        except Exception as e:
            timed_out = isinstance(e, (socket.timeout, TimeoutError)) or \
                isinstance(getattr(e, "reason", None), socket.timeout)
            if attempt == 2 or timed_out:
                break
            time.sleep(1)
    return []


def passive_enum(domain, quiet=False, deadline=40):
    """Query all passive sources in parallel. Slow sources are cut off at
    `deadline` seconds so one bad source can't block the whole scan."""
    found = set()
    lock = threading.Lock()

    def worker(fn):
        try:
            names = clean(_run_source(fn, domain), domain)
        except Exception:
            names = set()
        with lock:
            found.update(names)

    threads = [threading.Thread(target=worker, args=(fn,), daemon=True)
               for fn in SOURCES.values()]
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
    log("[+] Passive sources: {} candidates".format(len(result)), quiet)
    return result


# ------------------------------------------------------------ active: brute
def load_words(path):
    if not path:
        return DEFAULT_WORDS
    with open(path, encoding="utf-8", errors="ignore") as f:
        words = [w.strip().lower() for w in f if w.strip() and not w.startswith("#")]
    return [w for w in dict.fromkeys(words) if LABEL_RE.match(w)]


def permutations(subs, domain):
    """Simple alterations: dev-api, api-dev, api2 ..."""
    prefixes = ["dev", "test", "stage", "staging", "prod", "uat", "beta", "old", "new", "internal"]
    out = set()
    for s in subs:
        label = s[: -(len(domain) + 1)].split(".")[0]
        for p in prefixes:
            out.add("{}-{}.{}".format(p, label, domain))
            out.add("{}-{}.{}".format(label, p, domain))
        for i in range(1, 4):
            out.add("{}{}.{}".format(label, i, domain))
    return out - set(subs)


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
               "  Sublist -d example.com -b -p --probe -o result.json\n"
               "  Sublist -d example.com -b -w words.txt -t 200 -q\n"
               "  Sublist -update",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-d", "--domain", help="target domain (example.com)")
    ap.add_argument("-b", "--brute", action="store_true", help="enable DNS brute-force (active)")
    ap.add_argument("-w", "--wordlist", help="custom wordlist file for brute-force")
    ap.add_argument("-p", "--permute", action="store_true", help="try permutations of found names")
    ap.add_argument("--no-passive", action="store_true", help="skip passive sources")
    ap.add_argument("--no-resolve", action="store_true", help="do not DNS-validate results")
    ap.add_argument("--probe", action="store_true", help="HTTP probe live hosts (status, title, server)")
    ap.add_argument("-t", "--threads", type=int, default=100, help="threads (default 100)")
    ap.add_argument("--timeout", type=int, default=40,
                    help="max seconds to wait for passive sources (default 40)")
    ap.add_argument("-r", "--resolvers",
                    help="comma-separated DNS resolvers (default 1.1.1.1,8.8.8.8,9.9.9.9)")
    ap.add_argument("-o", "--output", help="save results (.txt / .json / .csv)")
    ap.add_argument("-q", "--quiet", action="store_true", help="print only results")
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

    log(BANNER, args.quiet)
    log("[*] Target: {}".format(domain), args.quiet)
    start = time.time()
    found = set()

    if not args.no_passive:
        found |= passive_enum(domain, args.quiet, max(5, args.timeout))

    if args.brute:
        words = load_words(args.wordlist)
        log("[*] Brute-forcing {} words...".format(len(words)), args.quiet)
        found |= {"{}.{}".format(w, domain) for w in words}

    if not found:
        sys.exit("No candidates found. Try --brute or check your internet connection.")

    if args.no_resolve:
        if args.permute:
            extra = permutations(found, domain)
            log("[*] Permutations: {} extra candidates".format(len(extra)), args.quiet)
            found |= extra
        results = {h: [] for h in found}
    else:
        custom = args.resolvers.split(",") if args.resolvers else None
        init_dns(custom)
        wild = wildcard_ips(domain)
        if wild:
            log("[!] Wildcard DNS detected, filtering fake results", args.quiet)

        with Spinner("Resolving {} candidates".format(len(found)), args.quiet) as sp:
            results = resolve_all(found, threads, wild, sp)

        if args.permute and results:
            extra = permutations(list(results), domain) - found
            if extra:
                log("[*] Permutations: {} extra candidates".format(len(extra)), args.quiet)
                with Spinner("Resolving permutations", args.quiet) as sp:
                    results.update(resolve_all(extra, threads, wild, sp, "Permutations"))

    probes = {}
    if args.probe and results:
        with Spinner("HTTP probing {} hosts".format(len(results)), args.quiet):
            probes = probe_all(list(results), min(threads, 50))

    rows = []
    for host in sorted(results):
        row = {"subdomain": host, "ips": results[host]}
        row.update(probes.get(host, {}))
        rows.append(row)

    log("", args.quiet)
    for r in rows:
        line = r["subdomain"]
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
