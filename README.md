# Sublist

```
 ____        _     _ _     _
/ ___| _   _| |__ | (_)___| |_
\___ \| | | | '_ \| | / __| __|
 ___) | |_| | |_) | | \__ \ |_
|____/ \__,_|_.__/|_|_|___/\__|
        v1.6.0  |  by Sujoy Karmakar
```

A fast subdomain enumeration tool written in pure Python. No third-party packages needed.
Type `sublist -d example.com` and it does everything for you: passive sources, DNS brute-force with an auto-downloaded wordlist, permutations, recursive scan and wildcard filtering. Add `--dork` for search-engine dorking and `-s` for trustworthy HTTP status codes.

> **Legal notice:** Use Sublist only on domains you own or have written permission to test. The author is not responsible for misuse.

## What's new in v1.6.0

- **Search-engine dorking (`-D`, `--dork`):** finds subdomains through Bing, DuckDuckGo, Brave, Yahoo, Mojeek and Google using `site:` dorks, 100+ third-party sites (GitHub, Pastebin, Trello ...) and generic dorks (`inurl`, `filetype` ...). No API key needed.
- **Better status codes (`-s`, `--status`):** redirects are no longer hidden. `[301 -> 200]` means the host answered 301 and the page it redirects to finally answered 200. The final URL is shown too.
- **`--no-follow`:** with `-s`, show only the raw first answer (301/302) and do not follow redirects.
- **Retries and honesty:** flaky answers (429, 502, 503, 504, timeouts) are retried. A host that answers nothing is shown as `[no response]`, never as a made-up code.
- **New passive source:** AlienVault OTX URL list.
- **Richer output:** JSON and CSV now include `url`, `status`, `redirect`, `final_url`, `final_status`, `server` and `title`.
- `--probe` still works as an alias of `-s`.

### Earlier (v1.5.0)

- **Auto mode:** `sublist -d example.com` automatically runs `-a -b -p -R -v`.
- **Auto wordlist:** downloaded from [Sujoyvhai/subdomin-wordlist](https://github.com/Sujoyvhai/subdomin-wordlist) and cached in `~/.sublist/wordlist.txt` (refreshed every 7 days). If the download fails, the cached or built-in list is used.
- **Run as a command:** type `sublist`, not `python sublist.py`.
- **Hacker mode:** the banner, status messages and spinner use random green/neon colors. Result lines stay plain, so they are easy to copy and pipe. Turn colors off with `--no-color`.
- **Easy install:** `--install` option and a simple Kali / Termux setup (see below).

## Features

- **Passive enumeration** from many public sources: crt.sh, CertSpotter, Digitorus, HackerTarget, AlienVault OTX (passive DNS and URL list), Anubis, Wayback Machine, URLScan, RapidDNS, ThreatMiner, ThreatCrowd, Sublist3r API, Columbus
- **Optional API sources** (free keys): VirusTotal, SecurityTrails, Chaos, Shodan, FullHunt, BeVigil
- **Search-engine dorking** over 6 search engines and 100+ sites (`--dork`)
- **DNS brute-force** with an auto-downloaded wordlist or your own
- **Permutations** of found names (`dev-api`, `api-dev`, `api2` ...)
- **Recursive scan** (`x.<found-sub>.example.com`)
- **DNS record harvesting** (NS, MX, SRV) and CNAME following
- **Wildcard DNS detection** to filter fake results
- **Fast DNS validation** using raw UDP queries (falls back to the system resolver)
- **HTTP status probing** of live hosts: status code, redirect target, server, page title (`-s`)
- **Export** to `.txt`, `.json` or `.csv`
- **Self-update** with `sublist -update`

## Requirements

- Python 3.6 or newer
- Internet connection
- Works on Kali Linux, other Linux distros, macOS, Windows and Termux (Android)

---

## Install on Kali Linux (step by step)

**Step 1: Install git and Python (usually already installed)**

```bash
sudo apt update
sudo apt install -y git python3
```

**Step 2: Download Sublist**

```bash
cd ~
git clone https://github.com/Sujoyvhai/Sublist.git
cd Sublist
```

**Step 3: Check the file is there**

```bash
ls -l sublist.py
```

**Step 4: Make it a command that works from any folder**

```bash
chmod +x sublist.py
sudo ln -sf "$(pwd)/sublist.py" /usr/local/bin/sublist
hash -r
```

`ln -sf` creates a link named `sublist` in `/usr/local/bin`. Because it is a link to the cloned folder, `sublist -update` (git pull) keeps working.

Alternative: run `sudo python3 sublist.py --install` to copy the script to `/usr/local/bin/sublist` automatically.

**Step 5: Test**

```bash
sublist -V
```

You should see `Sublist v1.6.0`.

**Step 6: Run from any folder**

```bash
cd ~/Desktop
sublist -d example.com
```

**If you get `sublist: command not found`**, add `/usr/local/bin` to PATH:

```bash
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.zshrc && source ~/.zshrc
```

(Use `~/.bashrc` instead of `~/.zshrc` if you use bash.)

---

## Install on Termux (Android, step by step)

**Step 1: Update Termux and install packages**

```bash
pkg update -y && pkg upgrade -y
pkg install -y python git
```

**Step 2: Download Sublist**

```bash
cd ~
git clone https://github.com/Sujoyvhai/Sublist.git
cd Sublist
```

**Step 3: Make it a command**

```bash
chmod +x sublist.py
ln -sf "$(pwd)/sublist.py" $PREFIX/bin/sublist
termux-fix-shebang sublist.py
hash -r
```

**Step 4: Test and run**

```bash
sublist -V
sublist -d example.com
```

Notes for Termux:

- If `sublist` is not found, run it directly: `python sublist.py -d example.com`.
- Use fewer threads on a weak phone: `sublist -d example.com -t 50`.
- If UDP/53 to public DNS is blocked on your network, Sublist automatically uses the system resolver (slower, but works).

---

## Install on Windows

```powershell
git clone https://github.com/Sujoyvhai/Sublist.git
cd Sublist
python sublist.py --install
```

Add the folder printed by the installer to your PATH once, open a **new** terminal, then run `sublist -d example.com`.

## Update

```bash
sublist -update
```

For git-clone installs this runs `git pull`. The wordlist is refreshed automatically every 7 days.

---

## Usage

```
sublist -d example.com [options]
```

### Quick examples

```bash
# Auto mode (recommended): runs -a -b -p -R -v for you
sublist -d example.com

# Auto mode and save the result
sublist -d example.com -o result.txt

# Auto mode + status codes ([200], [301 -> 200], [403] ...)
sublist -d example.com -s

# Auto mode + search-engine dorking
sublist -d example.com --dork

# Passive sources only (fast)
sublist -d example.com --passive

# Passive + dorking only, no brute-force
sublist -d example.com --passive --dork

# Manual mode: brute-force with your own wordlist, 200 threads, results only
sublist -d example.com -b -w words.txt -t 200 -q

# Brute-force + permutations + status codes, saved as JSON
sublist -d example.com -b -p -s -o result.json

# Show the raw first answer only (do not follow redirects)
sublist -d example.com -s --no-follow

# Brute-force only (no passive sources)
sublist -d example.com --no-passive -b
```

### Auto mode vs manual mode

- **Auto mode:** if you give only `-d` (plus things like `-o`, `-t`, `-q`, `-s`, `--dork`), Sublist enables `-a -b -p -R -v` by itself.
- **Manual mode:** if you give any scan option yourself (`-b`, `-p`, `-R`, `-a`, `-w`, `--passive`, `--no-passive`, `--no-resolve`), Sublist runs only what you asked for.

`--dork` and `-s` are extras. They never turn auto mode off and are never enabled by it, so add them when you want them.

### All options

| Option | What it does |
|---|---|
| `-d`, `--domain` | Target domain (`example.com`). Required for a scan. |
| `-b`, `--brute` | DNS brute-force using the wordlist (active). |
| `-w`, `--wordlist` | Use your own wordlist file instead of the auto-downloaded one. |
| `-p`, `--permute` | Try permutations of found names (`dev-api`, `api-dev`, `api2` ...). |
| `-R`, `--recursive` | Also brute-force a small wordlist under every found subdomain (`x.found.example.com`). |
| `-a`, `--all` | Also list passive names that do not resolve in DNS. They are marked `[no DNS]`. |
| `--passive` | Passive sources only. Turns off the automatic `-a -b -p -R -v` mode. |
| `--no-passive` | Skip passive sources (use with `-b`). |
| `--no-resolve` | Do not DNS-validate results. Faster, but may include dead names. |
| `-s`, `--status`, `--probe` | HTTP probe live hosts: status code, redirect target, server, page title. |
| `--no-follow` | With `-s`: do not follow redirects (show the raw 301/302 only). |
| `-D`, `--dork` | Search-engine dorking: search engines + `site:` dorks on 100+ sites. |
| `--dork-timeout` | Max seconds for `--dork` (default `120`). |
| `-t`, `--threads` | Number of threads (default `150`, max `1000`). |
| `--timeout` | Max seconds to wait for passive sources (default `60`). |
| `-r`, `--resolvers` | Comma-separated DNS resolvers (default `1.1.1.1,8.8.8.8,9.9.9.9`). |
| `-o`, `--output` | Save results to `.txt`, `.json` or `.csv`. |
| `-q`, `--quiet` | Print only results (no banner or logs). Good for piping. |
| `-v`, `--verbose` | Show how many names each source returned and which failed. |
| `--no-color` | Turn off hacker colors. |
| `--install` | Install Sublist as the `sublist` command. |
| `-U`, `-update`, `--update` | Update Sublist to the latest version. |
| `-V`, `--version` | Show the version and exit. |
| `-h`, `--help` | Show help. |

## Status codes (`-s`)

`-s` sends a real `GET` request with a browser User-Agent to every live host (HTTPS first, HTTP only if HTTPS gives no answer at all). It talks to the host directly. No API or third-party service is used.

Example output:

```
www.example.com    [200] nginx  Example Domain
old.example.com    [301 -> 200] nginx  Home  => https://www.example.com/
admin.example.com  [403] cloudflare  Attention Required!
dead.example.com   [no response]
```

How to read it:

| Output | Meaning |
|---|---|
| `[200]` | The host answered 200 directly. |
| `[301 -> 200]` | The host itself said 301, and the page it redirects to answered 200. The final URL is printed after `=>`. |
| `[403]`, `[404]` ... | The exact code the host returned. |
| `[no response]` | The host did not answer on HTTPS or HTTP. No code is invented. |

Notes:

- Redirects are followed (up to 6 hops) unless you use `--no-follow`.
- `429`, `502`, `503` and `504` answers and timeouts are retried before the result is shown.
- HTTPS certificates are not verified, so hosts with expired or self-signed certificates still show a code.
- Only the main page (`/`) is requested. A `403` or `503` can be a firewall or Cloudflare blocking scripts while a real browser gets `200`. Open the URL in a browser to double-check any code that looks wrong.

## Dorking (`--dork`)

`--dork` scrapes normal search-engine result pages. No API key is needed, and no traffic goes to the target. Only the search engines see your queries.

What it does:

1. `site:example.com -site:known1 -site:known2 ...` repeated, excluding names already found, until nothing new appears.
2. `site:<third-party site> "example.com"` for 100+ sites (GitHub, Pastebin, Trello, Notion, archive.org, cloud storage and more).
3. Generic dorks such as `inurl:`, `intext:` and `filetype:` (txt, xml, json, log, conf, pdf).

Queries are spread over Bing, DuckDuckGo, Yahoo, Brave, Mojeek and Google. Each engine is paced politely, and an engine that shows a captcha or rate limit is switched off while the others continue. Use `-v` to see how each engine did.

Notes:

- Google blocks scripts very quickly, so it is best effort only. Bing, DuckDuckGo, Brave, Yahoo and Mojeek usually do most of the work.
- Names found by dorking are checked in DNS like every other candidate. With `-a` the ones that do not resolve are kept and marked `[no DNS]`.
- Results change between runs because search engines change. Increase `--dork-timeout` for bigger targets.
- Scraping search engines can be against their terms of service. Use it sensibly and in moderation.

## Wordlist

- Default: downloaded from `Sujoyvhai/subdomin-wordlist` on GitHub and saved to `~/.sublist/wordlist.txt`.
- Built-in words are always merged in, so nothing is lost.
- No internet? The cached copy (or the built-in list) is used.
- Use `-w yourlist.txt` to use only your own list. Lines starting with `#` are ignored.

## Optional API keys

Free keys add more data sources. Set them as environment variables or in `~/.sublist.json`:

```json
{"virustotal": "KEY", "securitytrails": "KEY", "chaos": "KEY",
 "shodan": "KEY", "fullhunt": "KEY", "bevigil": "KEY"}
```

Environment variables: `VIRUSTOTAL_API_KEY`, `SECURITYTRAILS_API_KEY`, `CHAOS_API_KEY`, `SHODAN_API_KEY`, `FULLHUNT_API_KEY`, `BEVIGIL_API_KEY`.
Sublist also reuses keys from subfinder's `~/.config/subfinder/provider-config.yaml` if it exists.

**Google Custom Search (legacy, optional):** `google_cse` / `google_cx` (`GOOGLE_CSE_KEY` / `GOOGLE_CSE_CX`) are still supported for `--dork`, but Google closed the Custom Search JSON API to new customers in January 2026 and plans to shut it down on 1 January 2027. This only works if you already had a key. Everything else works without it.

## Output formats

| Extension | Content |
|---|---|
| `.txt` | One subdomain per line |
| `.json` | Subdomain, IPs, URL, status, redirect, final URL, final status, server, title |
| `.csv` | Same fields as JSON in table form |

Status fields are filled only when you use `-s`. Names kept by `-a` that have no DNS record carry `"resolved": false` in JSON. Any other extension is saved as plain text.

## How it works

1. Collects candidate names from passive sources (in parallel) and from NS/MX/SRV DNS records.
2. Optionally adds names found by search-engine dorking (`--dork`).
3. Adds brute-force words from the wordlist.
4. Detects wildcard DNS by resolving random names.
5. Resolves all candidates and drops wildcard/fake results.
6. Follows CNAME targets, then tries permutations and the recursive scan.
7. Optionally probes live hosts over HTTPS/HTTP for status codes (`-s`).
8. Prints and saves the results.

## Notes

- Passive sources may rate-limit or time out. Sublist skips failed sources, so results can differ between runs. Use `-v` to see which ones failed.
- Brute-force, recursive scan and status probing send traffic to the target's DNS and web servers. Only do this with permission.
- Dorking sends traffic to search engines, not to the target.

## Author

**Sujoy Karmakar**

## License

MIT
