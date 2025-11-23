package internal

import (
	"fmt"
	"math/bits"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func normalizeLongFlags(args []string) []string {
	var out []string
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") &&
			!strings.HasPrefix(arg, "--") &&
			len(arg) > 2 &&
			arg[1] != '-' {
			out = append(out, "--"+arg[1:])
			continue
		}
		out = append(out, arg)
	}
	return out
}

func getDNSList(path string) string {
	if _, err := os.Stat(path); err == nil {
		return path
	}
	wd, err := os.Getwd()
	if err != nil {
		return path
	}
	candidates := []string{
		filepath.Join(wd, "dns.txt"),
		filepath.Join(wd, "data", "dns.txt"),
	}
	for _, candidate := range candidates {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return path
}

func netsEqual(a, b net.IPNet) bool {
	return a.IP.Equal(b.IP) && bytesEqual(a.Mask, b.Mask)
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func uniqHosts(hosts []string) []string {
	uniq := make(map[string]bool)

	for _, host := range hosts {
		for _, part := range strings.Split(host, ".") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if !uniq[part] {
				uniq[part] = true
			}
		}
	}

	var out []string
	for part := range uniq {
		out = append(out, part)
	}
	sort.Strings(out)
	return out
}

func addDomain(subs []string, domain string) []string {
	var out []string
	for _, sub := range subs {
		if sub == "" {
			continue
		}
		out = append(out, sub+"."+domain)
	}
	return out
}

func sortIPs(ips []string) []string {
	var nums []uint32
	seen := make(map[uint32]bool)
	for _, ip := range ips {
		val := ipToUint32(net.ParseIP(ip))
		if val == 0 && ip != "0.0.0.0" {
			continue
		}
		if seen[val] {
			continue
		}
		seen[val] = true
		nums = append(nums, val)
	}

	sort.Slice(nums, func(i, j int) bool {
		return nums[i] < nums[j]
	})

	var out []string
	for _, n := range nums {
		out = append(out, uint32ToIP(n).String())
	}
	return out
}

func isPrivate(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	o := ip.To4()
	return o[0] == 10 ||
		o[0] == 127 ||
		(o[0] == 169 && o[1] == 254) ||
		(o[0] == 172 && o[1] > 15 && o[1] < 32) ||
		(o[0] == 192 && o[1] == 168)
}

func prefixSize(n *net.IPNet) int {
	ones, bitsTotal := n.Mask.Size()
	if bitsTotal != 32 {
		return 0
	}
	return 1 << (32 - ones)
}

func enumerate(prefix *net.IPNet) []string {
	ones, bitsTotal := prefix.Mask.Size()
	if bitsTotal != 32 {
		return nil
	}
	size := 1 << (32 - ones)
	start := ipToUint32(prefix.IP.Mask(prefix.Mask))
	var ips []string
	for i := 0; i < size; i++ {
		ips = append(ips, uint32ToIP(start+uint32(i)).String())
	}
	return ips
}

func rangeBounds(text string) []net.IP {
	parts := strings.FieldsFunc(text, func(r rune) bool {
		return r == '-' || r == ' '
	})
	if len(parts) < 2 {
		return nil
	}
	start := net.ParseIP(parts[0])
	end := net.ParseIP(parts[1])
	if start == nil || end == nil {
		return nil
	}
	return []net.IP{start, end}
}

func coverRange(start, end net.IP) *net.IPNet {
	s := ipToUint32(start)
	e := ipToUint32(end)
	mask := 32
	for mask > 0 {
		network := s & ^uint32((1<<(32-uint(mask)))-1)
		broadcast := network + (1 << (32 - uint(mask))) - 1
		if network == s && broadcast >= e {
			return &net.IPNet{
				IP:   uint32ToIP(network),
				Mask: net.CIDRMask(mask, 32),
			}
		}
		mask--
	}
	return nil
}

func rangeToCIDR(start, end uint32) []string {
	var blocks []string
	for start <= end {
		maxSize := start & -start
		maxMask := 32 - bits.TrailingZeros32(maxSize)
		remain := end - start + 1

		for (1 << (32 - maxMask)) > remain {
			maxMask++
		}

		blocks = append(
			blocks,
			fmt.Sprintf("%s/%d", uint32ToIP(start), maxMask),
		)
		start += 1 << (32 - maxMask)
	}
	return blocks
}

func ipToUint32(ip net.IP) uint32 {
	o := ip.To4()
	if o == nil {
		return 0
	}
	return uint32(o[0])<<24 |
		uint32(o[1])<<16 |
		uint32(o[2])<<8 |
		uint32(o[3])
}

func uint32ToIP(n uint32) net.IP {
	return net.IPv4(
		byte(n>>24),
		byte(n>>16),
		byte(n>>8),
		byte(n),
	)
}

func printUsage() {
	fmt.Print(`Usage: dnsrecce [Options] <domain>
GENERAL:
  --dnsserver <server>   Use this DNS server for A/NS/MX queries.
  --enum                 Shortcut for --threads 5 -s 15 -w.
  -h, --help             Print this help.
  --noreverse            Skip reverse lookups.
  --nocolor              Disable color output.
  --private              Show and save private IPs.
  --subfile <file>       Write valid subdomains to this file.
  -t, --timeout <secs>   DNS timeout (default: 10).
  --threads <count>      Number of concurrent workers.
  -v, --verbose          Verbose progress and errors.
SCRAPING:
  -p, --pages <count>    Google pages to scrape (default: 5).
  -s, --scrap <count>    Max subdomains to scrape (default: 0).
BRUTE FORCE:
  -f, --file <file>      Subdomain list (default: /usr/share/dnsenum/dns.txt).
  -u, --update <mode>    Update list with results (a,g,r,z).
  -r, --recursive        Recurse on subdomains with NS records.
WHOIS/REVERSE:
  -d, --delay <secs>     Max delay between whois queries.
  -w, --whois            Perform whois netrange lookups.
  -e, --exclude <regex>  Exclude PTR matches in reverse lookup.
OUTPUT:
  -o, --output <file>    XML output (MagicTree style).
`)
}
