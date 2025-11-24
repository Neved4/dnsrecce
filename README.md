<h3 align="center"><code>dnsrecce</code> · Threaded DNS recon pipeline</h3>
<h4 align="center">DNS recon for real-world targets</h4>
<p align="center">
<a href="#features">Features</a> •
<a href="#getting-started">Getting Started</a> •
<a href="#usage">Usage</a> •
<a href="#examples">Examples</a> •
<a href="#benchmarks">Benchmarks</a> •
<a href="#credits">Credits</a> •
<a href="#license">License</a>
</p>

---

dnsrecce is a DNS reconnaissance CLI that covers A/NS/MX queries, AXFR,
Google scraping, brute-force with recursion, whois CIDR expansion, and
reverse PTR lookups, with structured output and optional XML.

> [!IMPORTANT]
> Pentesting tools must only be used in lab environments or on systems
> you are explicitly authorized to test. Running this against systems
> you do not own is illegal and unethical.

## Features

- ~10× faster than [dnsenum](https://github.com/fwaeytens/dnsenum) in a
  minimal hyperfine run (~0.3s).
- Multithreaded A/NS/MX, zone transfers, brute force + recursion.
- Google scraping with wildcard/PTR filters.
- Whois netrange expansion and reverse PTR lookups.
- MagicTree-friendly XML output; colorized CLI.

## Getting Started

Install quickly via Homebrew:

```sh
brew install Neved4/tap/dnsrecce
```

Clone and build from source:

```sh
git clone https://github.com/Neved4/dnsrecce
cd dnsrecce
go mod download
go build -o bin/dnsrecce ./cmd/dnsrecce
```

Default brute-force list lives at `data/dns.txt`.

## Usage

Run with the options you need; everything is optional except the domain:

```sh
usage: dnsrecce [-e] [-S <srv>] [-s <n>] [-p <n>] [-f <path>] [-u <mode>]
	[-r] [-w] [-x <regex>] [-o <xml>] [-b <file>] [-T <n>]
	[-t <s>] [-D <domain>] <domain>

Options:
  -e, -enum       Shortcut sweep (threads=5, scrap=15, whois on)
  -S, -server     Pin resolvers
  -s, -scrap      Google scraping budget
  -p, -pages      Google pages to scrape
  -f, -file       Brute-force wordlist
  -u, -update     Write discoveries back to wordlist (a/all,g,r,z)
  -r, -recursive  Recurse on NS-capable subs
  -w, -whois      Whois netrange expansion
  -x, -exclude    Regex to drop PTR matches
  -o, -output     MagicTree-friendly XML
  -b, -subfile    Write discovered subdomains
  -T, -threads    Concurrency
  -t, -timeout    DNS timeout
  -D, -domain     Explicit domain flag (positional also works)
  -R, -noreverse  Skip reverse PTR
  -C, -nocolor    Disable ANSI colors
  -P, -private    Show/save private IPs
  -h, -help       Show help
```

## Examples

Fast sweep without reverse lookups:

```sh
GOCACHE="$(pwd)/.gocache" go run ./cmd/dnsrecce \
	--threads 5 --scrap 0 --noreverse example.com
```

Sample output:

```
-----   example.com   -----

Host's addresses:
example.com.  IN  A   23.215.0.136
example.com.  IN  A   23.220.75.245

Brute forcing with dns.txt:
www.example.com.  IN  CNAME  www.example.com-v4.edgesuite.net.

example.com ip blocks:
23.192.228.80/32
23.220.75.245/32
```

## Benchmarks

On a microbench against google.com (bench.txt, 10 threads, 3s timeout),
`dnspeek` completes ~11× faster than `dnsrecce`.

| Command | Mean [ms] | Min [ms] | Max [ms] | Relative |
|:---|---:|---:|---:|---:|
| `dnsrecce` | 308.4 ± 17.0 | 289.1 | 324.7 | 10.92 ± 0.63 |
| `dnspeek` | 28.2 ± 0.5 | 27.8 | 29.0 | 1.00 |

Hyperfine command:

```sh
hyperfine \
	"dnsrecce --threads 10 --timeout 3 --file bench.txt google.com" \
	"dnspeek --hosts bench.txt google.com"
```

## Credits

Original script idea:
[github.com/fwaeytens/dnsenum](https://github.com/fwaeytens/dnsenum)

## License

This repository is licensed under the terms of the [MIT License](LICENSE).
