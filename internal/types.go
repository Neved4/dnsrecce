package internal

import (
	"encoding/xml"
	"math/rand"
	"net"
	"os"
	"regexp"
	"sync"

	"github.com/miekg/dns"
)

const (
	program     = "dnsrecce"
	version     = "1.3.2"
	defaultList = "/usr/share/dnsenum/dns.txt"
	red         = "\033[1;31m"
	blue        = "\033[1;34m"
	reset       = "\033[0m"
)

type options struct {
	dnsServer string
	enumMode  bool
	delay     int
	exclude   string
	dnsFile   string
	help      bool
	noReverse bool
	noColor   bool
	pages     int
	private   bool
	recursion bool
	scrap     int
	subFile   string
	threads   int
	timeout   int
	update    string
	verbose   bool
	whois     bool
	output    string
}

type store struct {
	mu             sync.Mutex
	nameservers    map[string]bool
	allSubs        map[string]string
	googleSubs     map[string]bool
	fileSubs       map[string]bool
	recurSubs      map[string]bool
	netRanges      map[string]bool
	results        []string
	mxServers      []string
	privateIPs     []string
	ipBlocks       []string
	wildcardAddrs  []string
	wildcardCNames []string
	ipCount        int
	ipValid        int
}

type netRangeSet struct {
	mu       sync.Mutex
	prefixes []net.IPNet
}

type xmlWriter struct {
	active bool
	enc    *xml.Encoder
	file   *os.File
}

type app struct {
	opts     *options
	store    *store
	rng      *rand.Rand
	colorOn  bool
	domain   string
	fileIPs  string
	exclude  *regexp.Regexp
	xml      *xmlWriter
	client   *dns.Client
	resolver *dns.ClientConfig
	dnsTmp   *os.File
	subTmp   *os.File
	extendB  bool
	extendR  bool
	recur    bool
}
