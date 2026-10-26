# Sublist

```
 ____        _     _ _     _
/ ___| _   _| |__ | (_)___| |_
\___ \| | | | '_ \| | / __| __|
 ___) | |_| | |_) | | \__ \ |_
|____/ \__,_|_.__/|_|_|___/\__|
        v1.0.0  |  by Sujoy Karmakar
```

A simple, fast subdomain enumeration tool written in pure Python. No third-party packages needed.

> **Legal notice:** Use Sublist only on domains you own or have written permission to test. The author is not responsible for misuse.

## Features

- **Passive enumeration** from public sources: crt.sh, HackerTarget, AlienVault OTX, Anubis, Wayback Machine
- **DNS brute-force** with a built-in wordlist or your own
- **Permutations** of found names (`dev-api`, `api-dev`, `api2` ...)
- **Wildcard DNS detection** to filter fake results
- **DNS validation** of every candidate
- **HTTP probing** of live hosts (status code, server, page title)
- **Export** to `.txt`, `.json` or `.csv`
- Clean output with a loading spinner; failing sources are skipped silently and retried once

## Requirements

- Python 3.6 or newer
- Internet connection (for passive sources)

## Installation

```bash
git clone https://github.com/Sujoyvhai/Sublist.git
cd Sublist
python Sublist.py
```

Running `python Sublist.py` with no arguments prints the full help.

Note
## Run Sublist from Any Folder

Go to the folder that contains `Sublist.py`, then run:

```bash
ls -l Sublist.py
sudo ln -sf "$(pwd)/Sublist.py" /usr/local/bin/Sublist
chmod +x Sublist.py
ls -l /usr/local/bin/Sublist
Sublist
```

- `ls -l Sublist.py` checks that the file exists in the current folder.
- `ln -sf` creates (or overwrites) a link named `Sublist` in `/usr/local/bin`.
- `chmod +x` makes the script executable.
- `ls -l /usr/local/bin/Sublist` verifies where the link points.
- `Sublist` shows the banner and full help. Now you can run it from any folder, for example `Sublist -d example.com`.

## Usage

```
python Sublist.py -d example.com [options]
```

| Option | Description |
|---|---|
| `-d`, `--domain` | Target domain (`example.com`) |
| `-b`, `--brute` | Enable DNS brute-force (active) |
| `-w`, `--wordlist` | Custom wordlist file for brute-force |
| `-p`, `--permute` | Try permutations of found names |
| `--no-passive` | Skip passive sources |
| `--no-resolve` | Do not DNS-validate results |
| `--probe` | HTTP probe live hosts (status, title, server) |
| `-t`, `--threads` | Number of threads (default `50`) |
| `-o`, `--output` | Save results to `.txt`, `.json` or `.csv` |
| `-q`, `--quiet` | Print only results |
| `-h`, `--help` | Show help |

## Examples

Passive scan only:

```bash
python Sublist.py -d example.com
```

Passive + brute-force + permutations + HTTP probe, saved as JSON:

```bash
python Sublist.py -d example.com -b -p --probe -o result.json
```

Custom wordlist with 100 threads, results only (good for piping):

```bash
python Sublist.py -d example.com -b -w words.txt -t 100 -q
```

Brute-force only (no passive sources):

```bash
python Sublist.py -d example.com --no-passive -b
```

## Output formats

| Extension | Content |
|---|---|
| `.txt` | One subdomain per line |
| `.json` | Subdomain, IPs, URL, status, server, title |
| `.csv` | Same fields as JSON in table form |

Any other extension is saved as plain text.

## How it works

1. Collects candidate names from passive sources (in parallel).
2. Optionally adds brute-force words and permutations.
3. Detects wildcard DNS by resolving random names.
4. Resolves all candidates and drops wildcard/fake results.
5. Optionally probes live hosts over HTTPS/HTTP.
6. Prints and saves the results.

## Notes

- Passive sources may rate-limit or time out. Sublist skips failed sources, so results can differ between runs.
- Brute-force and probing send traffic to the target's DNS and web servers. Only do this with permission.

## Author

**Sujoy Karmakar**

## License

MIT
