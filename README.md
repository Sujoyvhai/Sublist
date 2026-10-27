# Sublist

```
 ____        _     _ _     _
/ ___| _   _| |__ | (_)___| |_
\___ \| | | | '_ \| | / __| __|
 ___) | |_| | |_) | | \__ \ |_
|____/ \__,_|_.__/|_|_|___/\__|
        v1.5.0  |  by Sujoy Karmakar
```

A fast subdomain enumeration tool written in pure Python. No third-party packages needed.
Type `sublist -d example.com` and it does everything for you: passive sources, DNS brute-force with an auto-downloaded wordlist, permutations, recursive scan and wildcard filtering.

> **Legal notice:** Use Sublist only on domains you own or have written permission to test. The author is not responsible for misuse.

## What's new in v1.5.0

- **Auto mode:** `sublist -d example.com` automatically runs `-a -b -p -R -v`. No need to type every option.
- **Auto wordlist:** the wordlist is downloaded from [Sujoyvhai/subdomin-wordlist](https://github.com/Sujoyvhai/subdomin-wordlist) and cached in `~/.sublist/wordlist.txt` (refreshed every 7 days). If the download fails, the cached or built-in list is used.
- **Run as a command:** type `sublist`, not `python sublist.py`.
- **Hacker mode:** the banner, status messages and spinner use random green/neon colors. Result lines stay plain, so they are easy to copy and pipe. Turn colors off with `--no-color`.
- **Easy install:** `--install` option and a simple Kali / Termux setup (see below).

## Features

- **Passive enumeration** from many public sources: crt.sh, CertSpotter, Digitorus, HackerTarget, AlienVault OTX, Anubis, Wayback Machine, URLScan, RapidDNS, ThreatMiner, ThreatCrowd, Sublist3r API, Columbus
- **Optional API sources** (free keys): VirusTotal, SecurityTrails, Chaos, Shodan, FullHunt, BeVigil
- **DNS brute-force** with an auto-downloaded wordlist or your own
- **Permutations** of found names (`dev-api`, `api-dev`, `api2` ...)
- **Recursive scan** (`x.<found-sub>.example.com`)
- **DNS record harvesting** (NS, MX, SRV) and CNAME following
- **Wildcard DNS detection** to filter fake results
- **Fast DNS validation** using raw UDP queries (falls back to the system resolver)
- **HTTP probing** of live hosts (status code, server, page title)
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

You should see `Sublist v1.5.0`.

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

# Passive sources only (fast)
sublist -d example.com --passive

# Manual mode: brute-force with your own wordlist, 200 threads, results only
sublist -d example.com -b -w words.txt -t 200 -q

# Brute-force + permutations + HTTP probe, saved as JSON
sublist -d example.com -b -p --probe -o result.json

# Brute-force only (no passive sources)
sublist -d example.com --no-passive -b
```

### Auto mode vs manual mode

- **Auto mode:** if you give only `-d` (plus things like `-o`, `-t`, `-q`, `--probe`), Sublist enables `-a -b -p -R -v` by itself.
- **Manual mode:** if you give any scan option yourself (`-b`, `-p`, `-R`, `-a`, `-w`, `--passive`, `--no-passive`, `--no-resolve`), Sublist runs only what you asked for.

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
| `--probe` | HTTP probe live hosts (status code, server, page title). |
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

## Output formats

| Extension | Content |
|---|---|
| `.txt` | One subdomain per line |
| `.json` | Subdomain, IPs, URL, status, server, title |
| `.csv` | Same fields as JSON in table form |

Any other extension is saved as plain text.

## How it works

1. Collects candidate names from passive sources (in parallel) and from NS/MX/SRV DNS records.
2. Adds brute-force words from the wordlist.
3. Detects wildcard DNS by resolving random names.
4. Resolves all candidates and drops wildcard/fake results.
5. Follows CNAME targets, then tries permutations and the recursive scan.
6. Optionally probes live hosts over HTTPS/HTTP.
7. Prints and saves the results.

## Notes

- Passive sources may rate-limit or time out. Sublist skips failed sources, so results can differ between runs. Use `-v` to see which ones failed.
- Brute-force, recursive scan and probing send traffic to the target's DNS and web servers. Only do this with permission.

## Author

**Sujoy Karmakar**

## License

MIT
