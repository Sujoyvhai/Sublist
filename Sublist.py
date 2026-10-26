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
import random
import re
import socket
import ssl
import string
import sys
import threading
import time
import urllib.error
import urllib.request

__version__ = "1.0.0"
__author__ = "Sujoy Karmakar"

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

DEFAULT_WORDS = """www mail ftp smtp pop imap webmail admin api dev test staging stage beta demo
portal blog shop store app apps cdn static assets img images media vpn remote secure login
auth sso dashboard panel cpanel whm ns1 ns2 ns3 mx mx1 mx2 git gitlab jenkins ci jira wiki
docs help support status monitor grafana kibana db mysql sql mongo redis backup old new v1 v2
intranet internal mobile m web server host cloud ssh crm erp hr billing pay payment office
exchange owa autodiscover autoconfig cms forum community news video download uploads files
proxy gateway lb office365 sandbox uat prod production""".split()


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
            sys.stderr.write("\r[*] {} {}".format(self.text, ch))
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
            sys.stderr.write("\r" + " " * (len(self.text) + 12) + "\r")
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
        n = n.strip().lower().rstrip(".")
        n = re.sub(r"^\*\.", "", n)
        if n.endswith("." + domain) and DOMAIN_RE.match(n):
            out.add(n)
    return out


# ------------------------------------------------------------ passive sources
def src_crtsh(domain):
    data = json.loads(http_get("https://crt.sh/?q=%25.{}&output=json".format(domain), 40))
    names = []
    for row in data:
        names.extend(row.get("name_value", "").split("\n"))
    return names


def src_hackertarget(domain):
    text = http_get("https://api.hackertarget.com/hostsearch/?q={}".format(domain))
    if "error" in text.lower()[:50]:
        return []
    return [line.split(",")[0] for line in text.splitlines()]


def src_otx(domain):
    data = json.loads(http_get(
        "https://otx.alienvault.com/api/v1/indicators/domain/{}/passive_dns".format(domain)))
    return [r.get("hostname", "") for r in data.get("passive_dns", [])]


def src_anubis(domain):
    return json.loads(http_get("https://jldc.me/anubis/subdomains/{}".format(domain)))


def src_wayback(domain):
    url = ("https://web.archive.org/cdx/search/cdx?url=*.{}&output=text"
           "&fl=original&collapse=urlkey&limit=50000".format(domain))
    names = []
    for line in http_get(url, 60).splitlines():
        m = re.match(r"^[a-z]+://([^/:?#]+)", line.strip().lower())
        if m:
            names.append(m.group(1))
    return names


SOURCES = {
    "crtsh": src_crtsh,
    "hackertarget": src_hackertarget,
    "otx": src_otx,
    "anubis": src_anubis,
    "wayback": src_wayback,
}


def _run_source(fn, domain, retries=2):
    """Run one source; retry once on failure. Failures are silent."""
    for attempt in range(retries):
        try:
            return fn(domain)
        except Exception:
            time.sleep(1)
    return []


def passive_enum(domain, quiet=False):
    found = set()
    with Spinner("Loading", quiet):
        with cf.ThreadPoolExecutor(max_workers=len(SOURCES)) as ex:
            futs = [ex.submit(_run_source, fn, domain) for fn in SOURCES.values()]
            for fut in cf.as_completed(futs):
                try:
                    found |= clean(fut.result(), domain)
                except Exception:
                    pass
    log("[+] Passive sources: {} candidates".format(len(found)), quiet)
    return found


# ------------------------------------------------------------ active: brute
def load_words(path):
    if not path:
        return DEFAULT_WORDS
    with open(path, encoding="utf-8", errors="ignore") as f:
        words = [w.strip().lower() for w in f if w.strip() and not w.startswith("#")]
    return [w for w in words if LABEL_RE.match(w)]


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


# ------------------------------------------------------------ DNS
def resolve(host, timeout=3):
    socket.setdefaulttimeout(timeout)
    try:
        infos = socket.getaddrinfo(host, None)
        return sorted({i[4][0] for i in infos})
    except (socket.gaierror, socket.timeout, UnicodeError, OSError):
        return []


def wildcard_ips(domain):
    ips = set()
    for _ in range(3):
        rnd = "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
        ips |= set(resolve("{}.{}".format(rnd, domain)))
    return ips


def resolve_all(hosts, threads, wild):
    live = {}
    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(resolve, h): h for h in hosts}
        for fut in cf.as_completed(futs):
            ips = fut.result()
            if ips and not (wild and set(ips) <= wild):
                live[futs[fut]] = ips
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
    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        futs = {ex.submit(probe, h): h for h in hosts}
        for fut in cf.as_completed(futs):
            res[futs[fut]] = fut.result()
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
               "  python Sublist.py -d example.com\n"
               "  python Sublist.py -d example.com -b -p --probe -o result.json\n"
               "  python Sublist.py -d example.com -b -w words.txt -t 100 -q",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("-d", "--domain", help="target domain (example.com)")
    ap.add_argument("-b", "--brute", action="store_true", help="enable DNS brute-force (active)")
    ap.add_argument("-w", "--wordlist", help="custom wordlist file for brute-force")
    ap.add_argument("-p", "--permute", action="store_true", help="try permutations of found names")
    ap.add_argument("--no-passive", action="store_true", help="skip passive sources")
    ap.add_argument("--no-resolve", action="store_true", help="do not DNS-validate results")
    ap.add_argument("--probe", action="store_true", help="HTTP probe live hosts (status, title, server)")
    ap.add_argument("-t", "--threads", type=int, default=50, help="threads (default 50)")
    ap.add_argument("-o", "--output", help="save results (.txt / .json / .csv)")
    ap.add_argument("-q", "--quiet", action="store_true", help="print only results")
    return ap


def main():
    ap = build_parser()

    # Just "python Sublist.py" with nothing else -> show full help
    if len(sys.argv) == 1:
        ap.print_help()
        sys.exit(0)

    args = ap.parse_args()

    if not args.domain:
        ap.print_help()
        sys.exit("\nError: -d/--domain is required")

    domain = args.domain.strip().lower().replace("http://", "").replace("https://", "").split("/")[0]
    if not DOMAIN_RE.match(domain):
        sys.exit("Error: invalid domain '{}'".format(args.domain))

    log(BANNER, args.quiet)
    log("[*] Target: {}".format(domain), args.quiet)
    start = time.time()
    found = set()

    if not args.no_passive:
        found |= passive_enum(domain, args.quiet)

    if args.brute:
        words = load_words(args.wordlist)
        log("[*] Brute-forcing {} words...".format(len(words)), args.quiet)
        found |= {"{}.{}".format(w, domain) for w in words}

    if args.permute and found:
        extra = permutations(found, domain)
        log("[*] Permutations: {} extra candidates".format(len(extra)), args.quiet)
        found |= extra

    if not found:
        sys.exit("No candidates found. Try --brute or check your internet connection.")

    if args.no_resolve:
        results = {h: [] for h in found}
    else:
        wild = wildcard_ips(domain)
        if wild:
            log("[!] Wildcard DNS detected ({}), filtering fake results".format(", ".join(sorted(wild))),
                args.quiet)
        with Spinner("Resolving {} candidates".format(len(found)), args.quiet):
            results = resolve_all(found, args.threads, wild)

    probes = {}
    if args.probe and results:
        with Spinner("HTTP probing {} hosts".format(len(results)), args.quiet):
            probes = probe_all(list(results), min(args.threads, 30))

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
