package internal

import (
	"bufio"
	"context"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/likexian/whois"
	"github.com/miekg/dns"
	"golang.org/x/net/html"
)

func Execute(ctx context.Context, args []string) error {
	opts, domain, err := parseArgs(args)
	if err != nil {
		printUsage()
		return err
	}

	if opts.help {
		printUsage()
		return nil
	}

	app, err := newApp(opts, domain)
	if err != nil {
		return err
	}
	return app.run(ctx)
}

func parseArgs(args []string) (*options, string, error) {
	args = normalizeLongFlags(args)

	opts := &options{
		delay:   3,
		pages:   5,
		timeout: 10,
	}

	dnsList := getDNSList(defaultList)
	fs := flag.NewFlagSet(program, flag.ExitOnError)

	fs.StringVar(&opts.dnsServer, "dnsserver", "", "DNS server")
	fs.StringVar(&opts.dnsServer, "server", "", "DNS server")
	fs.StringVar(&opts.dnsServer, "S", "", "DNS server")
	fs.BoolVar(&opts.enumMode, "enum", false, "enum shortcut")
	fs.BoolVar(&opts.enumMode, "e", false, "enum shortcut")
	fs.IntVar(&opts.delay, "d", opts.delay, "whois delay")
	fs.IntVar(&opts.delay, "delay", opts.delay, "whois delay")
	fs.StringVar(&opts.exclude, "x", "", "exclude regex")
	fs.StringVar(&opts.exclude, "exclude", "", "exclude regex")
	fs.StringVar(&opts.dnsFile, "f", dnsList, "dns file")
	fs.StringVar(&opts.dnsFile, "file", dnsList, "dns file")
	fs.BoolVar(&opts.help, "h", false, "help")
	fs.BoolVar(&opts.help, "help", false, "help")
	fs.BoolVar(&opts.noReverse, "noreverse", false, "no reverse")
	fs.BoolVar(&opts.noReverse, "R", false, "no reverse")
	fs.BoolVar(&opts.noColor, "nocolor", false, "no color")
	fs.BoolVar(&opts.noColor, "C", false, "no color")
	fs.IntVar(&opts.pages, "p", opts.pages, "google pages")
	fs.IntVar(&opts.pages, "pages", opts.pages, "google pages")
	fs.BoolVar(&opts.private, "private", false, "keep private")
	fs.BoolVar(&opts.private, "P", false, "keep private")
	fs.BoolVar(&opts.recursion, "r", false, "recursion")
	fs.BoolVar(&opts.recursion, "recursion", false, "recursion")
	fs.BoolVar(&opts.recursion, "recursive", false, "recursion")
	fs.IntVar(&opts.scrap, "s", 0, "scrap")
	fs.IntVar(&opts.scrap, "scrap", 0, "scrap")
	fs.StringVar(&opts.subFile, "subfile", "", "save subdomains")
	fs.StringVar(&opts.subFile, "b", "", "save subdomains")
	fs.IntVar(&opts.threads, "threads", 0, "thread count")
	fs.IntVar(&opts.threads, "T", 0, "thread count")
	fs.IntVar(&opts.timeout, "t", opts.timeout, "timeout secs")
	fs.IntVar(&opts.timeout, "timeout", opts.timeout, "timeout secs")
	fs.StringVar(&opts.update, "u", "", "update mode")
	fs.StringVar(&opts.update, "update", "", "update mode")
	fs.BoolVar(&opts.verbose, "v", false, "verbose")
	fs.BoolVar(&opts.verbose, "verbose", false, "verbose")
	fs.BoolVar(&opts.whois, "w", false, "whois")
	fs.BoolVar(&opts.whois, "whois", false, "whois")
	fs.StringVar(&opts.output, "o", "", "xml output")
	fs.StringVar(&opts.output, "output", "", "xml output")
	fs.StringVar(&opts.output, "O", "", "xml output")
	var domainFlag string
	fs.StringVar(&domainFlag, "domain", "", "target domain")
	fs.StringVar(&domainFlag, "D", "", "target domain")

	_ = fs.Parse(args)

	argv := fs.Args()
	if domainFlag == "" && len(argv) == 0 && !opts.help {
		return nil, "", errors.New("domain is required")
	}

	if opts.enumMode {
		opts.threads = 5
		opts.scrap = 15
		opts.whois = true
	}

	if opts.timeout < 0 || opts.timeout > 128 {
		opts.timeout = 10
	}
	if opts.delay < 0 {
		opts.delay = 3
	}
	if opts.scrap <= 0 || opts.pages <= 0 {
		opts.scrap = 0
	}
	if opts.update != "" && opts.dnsFile == "" {
		opts.update = ""
	}

	domain := ""
	if domainFlag != "" {
		domain = strings.ToLower(domainFlag)
	} else if len(argv) > 0 {
		domain = strings.ToLower(argv[0])
	}

	return opts, domain, nil
}

func newApp(opts *options, domain string) (*app, error) {
	if domain == "" {
		return nil, errors.New("domain is required")
	}

	st := &store{
		nameservers: make(map[string]bool),
		allSubs:     make(map[string]string),
		googleSubs:  make(map[string]bool),
		fileSubs:    make(map[string]bool),
		recurSubs:   make(map[string]bool),
		netRanges:   make(map[string]bool),
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	cfg, err := loadResolver(opts.dnsServer)
	if err != nil {
		return nil, err
	}

	var re *regexp.Regexp
	if opts.exclude != "" {
		re, err = regexp.Compile(opts.exclude)
		if err != nil {
			return nil, fmt.Errorf("bad exclude regex: %w", err)
		}
	}

	xmlw, err := newXMLWriter(opts.output)
	if err != nil {
		return nil, err
	}

	client := &dns.Client{
		Timeout: time.Duration(opts.timeout) * time.Second,
	}

	app := &app{
		opts:     opts,
		store:    st,
		rng:      rng,
		colorOn:  !opts.noColor,
		domain:   domain,
		fileIPs:  domain + "_ips.txt",
		exclude:  re,
		xml:      xmlw,
		client:   client,
		resolver: cfg,
	}

	if opts.subFile != "" {
		app.extendB = true
	}

	if opts.recursion {
		app.extendB = true
	}

	if opts.update == "a" || opts.update == "all" {
		app.extendB = true
	}

	return app, nil
}

func newXMLWriter(path string) (*xmlWriter, error) {
	if path == "" {
		return &xmlWriter{}, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}

	enc := xml.NewEncoder(file)
	enc.Indent("", "\t")

	startMagic := xml.StartElement{
		Name: xml.Name{Local: "magictree"},
		Attr: []xml.Attr{{
			Name:  xml.Name{Local: "class"},
			Value: "MtBranchObject",
		}},
	}
	startTest := xml.StartElement{
		Name: xml.Name{Local: "testdata"},
		Attr: []xml.Attr{{
			Name:  xml.Name{Local: "class"},
			Value: "MtBranchObject",
		}},
	}

	if err := enc.EncodeToken(startMagic); err != nil {
		return nil, err
	}
	if err := enc.EncodeToken(startTest); err != nil {
		return nil, err
	}

	return &xmlWriter{
		active: true,
		enc:    enc,
		file:   file,
	}, nil
}

func (x *xmlWriter) writeRR(rr dns.RR) {
	if !x.active {
		return
	}

	name := strings.TrimSuffix(rr.Header().Name, ".")
	ip := ""

	switch v := rr.(type) {
	case *dns.A:
		ip = v.A.String()
	}

	if ip == "" {
		ip = lookupIP(name)
	}

	if ip != "" {
		host := xml.StartElement{
			Name: xml.Name{Local: "host"},
		}
		hostname := xml.StartElement{
			Name: xml.Name{Local: "hostname"},
		}

		_ = x.enc.EncodeToken(host)
		_ = x.enc.EncodeToken(xml.CharData(ip))
		_ = x.enc.EncodeToken(hostname)
		_ = x.enc.EncodeToken(xml.CharData(name))
		_ = x.enc.EncodeToken(xml.EndElement{Name: hostname.Name})
		_ = x.enc.EncodeToken(xml.EndElement{Name: host.Name})
	}

	fqdn := xml.StartElement{
		Name: xml.Name{Local: "fqdn"},
	}
	_ = x.enc.EncodeToken(fqdn)
	_ = x.enc.EncodeToken(xml.CharData(name + "."))
	_ = x.enc.EncodeToken(xml.EndElement{Name: fqdn.Name})
}

func (x *xmlWriter) close() error {
	if !x.active {
		return nil
	}

	if err := x.enc.EncodeToken(
		xml.EndElement{Name: xml.Name{Local: "testdata"}},
	); err != nil {
		return err
	}
	if err := x.enc.EncodeToken(
		xml.EndElement{Name: xml.Name{Local: "magictree"}},
	); err != nil {
		return err
	}
	if err := x.enc.Flush(); err != nil {
		return err
	}

	return x.file.Close()
}

func (s *store) addNameServer(ns string) {
	s.mu.Lock()
	s.nameservers[ns] = true
	s.mu.Unlock()
}

func (s *store) addMX(mx string) {
	s.mu.Lock()
	s.mxServers = append(s.mxServers, mx)
	s.mu.Unlock()
}

func (s *store) addResult(ip string) {
	s.mu.Lock()
	s.results = append(s.results, ip)
	s.mu.Unlock()
}

func (s *store) addPrivate(ip string) {
	s.mu.Lock()
	s.privateIPs = append(s.privateIPs, ip)
	s.mu.Unlock()
}

func (s *store) addSub(name, source string) {
	s.mu.Lock()
	if _, ok := s.allSubs[name]; !ok {
		s.allSubs[name] = source
	}
	s.mu.Unlock()
}

func (s *store) addGoogleSub(name string) {
	s.mu.Lock()
	s.googleSubs[name] = true
	if _, ok := s.allSubs[name]; !ok {
		s.allSubs[name] = "g"
	}
	s.mu.Unlock()
}

func (s *store) addFileSub(name string) {
	s.mu.Lock()
	s.fileSubs[name] = true
	s.mu.Unlock()
}

func (s *store) addRecurSub(name string) {
	s.mu.Lock()
	s.recurSubs[name] = true
	s.mu.Unlock()
}

func (s *store) addNetRange(block string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.netRanges[block] {
		return false
	}
	s.netRanges[block] = true
	return true
}

func (s *store) addWildcardAddr(addr string) {
	s.mu.Lock()
	s.wildcardAddrs = append(s.wildcardAddrs, addr)
	s.mu.Unlock()
}

func (s *store) addWildcardCName(name string) {
	s.mu.Lock()
	s.wildcardCNames = append(s.wildcardCNames, name)
	s.mu.Unlock()
}

func (s *store) addIPBlock(block string) {
	s.mu.Lock()
	s.ipBlocks = append(s.ipBlocks, block)
	s.mu.Unlock()
}

func (s *store) bumpIPCount(n int) {
	s.mu.Lock()
	s.ipCount += n
	s.mu.Unlock()
}

func (s *store) bumpIPValid() {
	s.mu.Lock()
	s.ipValid++
	s.mu.Unlock()
}

func (s *netRangeSet) contains(ip net.IP) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, p := range s.prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *netRangeSet) add(p net.IPNet) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, n := range s.prefixes {
		if netsEqual(n, p) {
			return false
		}
	}
	s.prefixes = append(s.prefixes, p)
	return true
}

func (a *app) banner() {
	fmt.Printf("%s VERSION:%s\n", program, version)
	if a.colorOn {
		fmt.Print(blue)
	}
	fmt.Printf("\n-----   %s   -----\n", a.domain)
	if a.colorOn {
		fmt.Print(reset)
	}
}

func (a *app) header(text string) {
	if a.colorOn {
		fmt.Print(red)
	}
	line := strings.Repeat("_", len(text))
	fmt.Printf("\n\n%s%s\n\n", text, line)
	if a.colorOn {
		fmt.Print(reset)
	}
}

func (a *app) friendly(text string) {
	fmt.Printf(" %s\n", text)
}

func (a *app) printRR(rr dns.RR) {
	parts := strings.Fields(rr.String())
	fields := make([]string, 5)
	copy(fields, parts)
	fmt.Printf(
		"%-40s %-8s %-5s %-8s %10s\n",
		fields[0], fields[1], fields[2], fields[3], fields[4],
	)
}

func (a *app) trimDot(text string) string {
	return strings.TrimSuffix(text, ".")
}

func (a *app) matchDomain(name string) (string, bool) {
	clean := strings.ToLower(a.trimDot(name))
	domain := strings.ToLower(a.domain)

	if clean == domain {
		return "", true
	}

	suffix := "." + domain
	if strings.HasSuffix(clean, suffix) {
		return strings.TrimSuffix(clean, suffix), true
	}

	return "", false
}

func (a *app) serverList(override string) []string {
	var servers []string
	if override != "" {
		host, port, err := splitHostPort(override)
		if err != nil {
			return servers
		}
		return []string{net.JoinHostPort(host, port)}
	}

	for _, srv := range a.resolver.Servers {
		servers = append(servers, net.JoinHostPort(srv, a.resolver.Port))
	}
	return servers
}

func (a *app) query(
	ctx context.Context,
	host string,
	qtype uint16,
	servers []string,
) (*dns.Msg, error) {
	if len(servers) == 0 {
		servers = a.serverList(a.opts.dnsServer)
	}
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(host), qtype)
	msg.RecursionDesired = true

	var lastErr error
	for _, srv := range servers {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		resp, _, err := a.client.Exchange(msg, srv)
		if err == nil && resp != nil {
			if resp.Rcode == dns.RcodeSuccess {
				return resp, nil
			}
			lastErr = fmt.Errorf("rcode %s", dns.RcodeToString[resp.Rcode])
			continue
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no response")
	}
	return nil, lastErr
}

func (a *app) run(ctx context.Context) error {
	defer func() {
		if err := a.xml.close(); err != nil && a.opts.verbose {
			fmt.Fprintln(os.Stderr, "xml:", err)
		}
	}()

	a.banner()

	if err := a.hostAddresses(ctx); err != nil && a.opts.verbose {
		fmt.Fprintf(
			os.Stderr,
			" %s A query failed: %v\n",
			a.domain,
			err,
		)
	}

	if err := a.wildcardTest(ctx); err != nil && a.opts.verbose {
		fmt.Fprintln(os.Stderr, err)
	}

	if err := a.fetchNameServers(ctx); err != nil {
		return err
	}

	a.fetchMailServers(ctx)
	a.zoneTransfers(ctx)

	if a.opts.scrap > 0 {
		a.googleScrape(ctx)
	}

	if a.opts.dnsFile == "" {
		fmt.Println("\nbrute force file not specified, bay.")
		return nil
	}

	if err := a.bruteForceFile(ctx); err != nil {
		return err
	}

	updateEntries := a.collectUpdateBeforeReverse()
	var subEntries []string
	if a.opts.subFile != "" {
		subEntries = append(subEntries, a.collectSubfileEntries()...)
	}

	if a.opts.recursion {
		a.recursionFlow(ctx)
	}

	updateEntries = append(
		updateEntries,
		a.collectUpdateAll()...,
	)

	a.store.mxServers = nil
	a.store.allSubs = make(map[string]string)

	ranges := a.networkRanges()
	if a.opts.noReverse {
		blocks := finalValidIPs(ranges)
		for _, b := range blocks {
			a.store.addIPBlock(b)
		}
	} else {
		if a.opts.update == "r" ||
			a.opts.update == "a" ||
			a.opts.update == "all" ||
			a.opts.subFile != "" {
			a.extendR = true
		}

		if err := a.reverseLookups(ctx, ranges); err != nil &&
			a.opts.verbose {
			fmt.Fprintln(os.Stderr, err)
		}
	}

	if a.opts.subFile != "" && a.extendR {
		subEntries = append(subEntries, a.allSubKeys()...)
	}

	if a.opts.update != "" {
		if a.extendR {
			updateEntries = append(
				updateEntries,
				a.collectUpdateReverse()...,
			)
		}
		if err := a.applyUpdate(updateEntries); err != nil {
			return err
		}
	}

	if a.opts.subFile != "" {
		if err := a.writeSubFile(subEntries); err != nil {
			return err
		}
	}

	if err := a.writeIPBlocks(); err != nil {
		return err
	}

	a.printPrivateIPs()
	a.printIPBlocks()

	fmt.Println("\ndone.")
	return nil
}

func (a *app) hostAddresses(ctx context.Context) error {
	a.header("Host's addresses:\n")

	msg, err := a.query(ctx, a.domain, dns.TypeA, nil)
	if err != nil {
		return err
	}

	for _, rr := range msg.Answer {
		if aRec, ok := rr.(*dns.A); ok {
			a.printRR(rr)
			a.xml.writeRR(rr)
			if _, ok := a.matchDomain(rr.Header().Name); ok {
				a.store.addResult(aRec.A.String())
			}
		}
	}

	return nil
}

func (a *app) wildcardTest(ctx context.Context) error {
	if a.opts.verbose {
		fmt.Printf("\n----------------\nWildcards test:\n----------------\n")
	}

	label := a.randomLabel(12)
	host := label + "." + a.domain

	msg, err := a.query(ctx, host, dns.TypeA, nil)
	if err != nil || msg == nil || len(msg.Answer) == 0 {
		if a.opts.verbose {
			fmt.Println(" good")
		}
		return nil
	}

	a.header("Wildcard detection using: " + label + "\n")
	for _, rr := range msg.Answer {
		switch rec := rr.(type) {
		case *dns.A:
			a.printRR(rr)
			a.store.addWildcardAddr(rec.A.String())
		case *dns.CNAME:
			a.printRR(rr)
			a.store.addWildcardCName(a.trimDot(rec.Target))
		default:
			a.printRR(rr)
		}
	}

	if a.colorOn {
		fmt.Print(red)
	}
	fmt.Print("\n\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n")
	fmt.Println(
		" Wildcards detected, all subdomains will point to the same IP",
	)
	fmt.Printf(
		" Omitting results containing %s.\n",
		strings.Join(a.store.wildcardAddrs, ", "),
	)
	fmt.Println(" Maybe you are using OpenDNS servers.")
	fmt.Print("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
	if a.colorOn {
		fmt.Print(reset)
	}

	return nil
}

func (a *app) fetchNameServers(ctx context.Context) error {
	a.header("Name Servers:\n")

	msg, err := a.query(ctx, a.domain, dns.TypeNS, nil)
	if err != nil {
		return fmt.Errorf(
			" %s NS record query failed: %w",
			a.domain,
			err,
		)
	}

	var servers []string
	for _, rr := range msg.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			host := a.trimDot(ns.Ns)
			a.store.addNameServer(host)
			servers = append(servers, host)
		}
	}

	if len(servers) == 0 {
		return fmt.Errorf(
			" Error: can't continue no NS record for %s",
			a.domain,
		)
	}

	remain := a.additionalRecords(msg, servers)
	if len(remain) > 0 {
		a.lookupHosts(ctx, remain, "n")
	}

	return nil
}

func (a *app) fetchMailServers(ctx context.Context) {
	a.header("Mail (MX) Servers:\n")

	msg, err := a.query(ctx, a.domain, dns.TypeMX, nil)
	if err != nil {
		if a.opts.verbose {
			fmt.Fprintf(
				os.Stderr,
				" %s MX record query failed: %v\n",
				a.domain,
				err,
			)
		}
		return
	}

	var servers []string
	for _, rr := range msg.Answer {
		if mx, ok := rr.(*dns.MX); ok {
			host := a.trimDot(mx.Mx)
			a.store.addMX(host)
			servers = append(servers, host)
		}
	}

	if len(servers) == 0 {
		return
	}

	remain := a.additionalRecords(msg, servers)
	if len(remain) > 0 {
		a.lookupHosts(ctx, remain, "m")
	} else {
		a.lookupHosts(ctx, servers, "m")
	}
}

func (a *app) additionalRecords(
	msg *dns.Msg,
	servers []string,
) []string {
	remain := make(map[string]bool)
	for _, srv := range servers {
		remain[strings.ToLower(a.trimDot(srv))] = true
	}

	for _, rr := range msg.Extra {
		aRec, ok := rr.(*dns.A)
		if !ok {
			continue
		}
		name := strings.ToLower(a.trimDot(aRec.Hdr.Name))
		if !remain[name] {
			continue
		}

		a.printRR(rr)
		a.xml.writeRR(rr)

		if _, ok := a.matchDomain(name); ok {
			a.store.addResult(aRec.A.String())
		}

		delete(remain, name)
	}

	var left []string
	for srv := range remain {
		left = append(left, srv)
	}
	return left
}

func (a *app) lookupHosts(
	ctx context.Context,
	hosts []string,
	source string,
) {
	if len(hosts) == 0 {
		return
	}

	if a.opts.threads < 1 || len(hosts) == 1 {
		for _, host := range hosts {
			a.lookupHost(ctx, host, source)
		}
		return
	}

	runTasks(hosts, a.opts.threads, func(h string) {
		a.lookupHost(ctx, h, source)
	})
}

func (a *app) lookupHost(
	ctx context.Context,
	host string,
	source string,
) {
	msg, err := a.query(ctx, host, dns.TypeA, nil)
	if err != nil {
		if a.opts.verbose {
			fmt.Fprintf(
				os.Stderr,
				"  %s A record query failed: %v\n",
				host,
				err,
			)
		}
		return
	}

	for _, rr := range msg.Answer {
		if a.skipWildcard(rr) {
			continue
		}

		a.printRR(rr)
		a.xml.writeRR(rr)

		sub, ok := a.matchDomain(rr.Header().Name)
		if ok {
			if a.extendB && sub != "" {
				tag := source
				if tag == "" {
					tag = "f"
				}
				a.store.addSub(sub, tag)
				if a.recur {
					a.store.addRecurSub(sub)
				}
			}

			if aRec, ok := rr.(*dns.A); ok {
				a.store.addResult(aRec.A.String())
			}
		}
	}
}

func (a *app) skipWildcard(rr dns.RR) bool {
	switch rec := rr.(type) {
	case *dns.A:
		for _, addr := range a.store.wildcardAddrs {
			if rec.A.String() == addr {
				return true
			}
		}
	case *dns.CNAME:
		for _, name := range a.store.wildcardCNames {
			if a.trimDot(rec.Target) == name {
				return true
			}
		}
	}
	return false
}

func (a *app) nameserverList() []string {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()

	var servers []string
	for ns := range a.store.nameservers {
		servers = append(servers, ns)
	}
	sort.Strings(servers)
	return servers
}

func (a *app) mxList() []string {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()

	mx := make([]string, len(a.store.mxServers))
	copy(mx, a.store.mxServers)
	sort.Strings(mx)
	return mx
}

func (a *app) allSubKeys() []string {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()

	var subs []string
	for sub := range a.store.allSubs {
		subs = append(subs, sub)
	}
	sort.Strings(subs)
	return subs
}

func (a *app) googleKeys() []string {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()

	var subs []string
	for sub := range a.store.googleSubs {
		subs = append(subs, sub)
	}
	sort.Strings(subs)
	return subs
}

func (a *app) resultsList() []string {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()

	ips := make([]string, len(a.store.results))
	copy(ips, a.store.results)
	return ips
}

func (a *app) zoneTransfers(ctx context.Context) {
	a.header("Trying Zone Transfers and getting Bind Versions:\n")
	servers := a.nameserverList()
	if len(servers) == 0 {
		return
	}

	runTasks(servers, a.opts.threads, func(ns string) {
		addr := a.nsAddress(ns)
		m := new(dns.Msg)
		m.SetAxfr(dns.Fqdn(a.domain))

		tr := &dns.Transfer{
			DialTimeout: time.Duration(a.opts.timeout) * time.Second,
			ReadTimeout: time.Duration(a.opts.timeout) * time.Second,
		}

		fmt.Printf(
			"\nTrying Zone Transfer for %s on %s ... \n",
			a.domain,
			ns,
		)

		envs, err := tr.In(m, addr)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				"AXFR record query failed: %v\n",
				err,
			)
			return
		}

		for env := range envs {
			if env.Error != nil {
				fmt.Fprintln(os.Stderr, env.Error)
				continue
			}

			for _, rr := range env.RR {
				a.printRR(rr)
				a.xml.writeRR(rr)

				sub, ok := a.matchDomain(rr.Header().Name)
				if ok && sub != "" {
					a.store.addSub(sub, "z")
				}

				switch rec := rr.(type) {
				case *dns.A:
					a.store.addResult(rec.A.String())
				case *dns.MX:
					a.store.addMX(a.trimDot(rec.Mx))
				}
			}
		}
	})
}

func (a *app) googleScrape(ctx context.Context) {
	a.header("Scraping " + a.domain + " subdomains from Google:\n")

	subs := a.scrapeGoogle(ctx)
	if len(subs) == 0 {
		fmt.Fprintln(
			os.Stderr,
			"  perhaps Google is blocking our queries.\n Check manually.",
		)
		return
	}

	var hosts []string
	for _, sub := range subs {
		hosts = append(hosts, sub+"."+a.domain)
	}

	a.lookupHosts(ctx, hosts, "g")
}

func (a *app) scrapeGoogle(ctx context.Context) []string {
	client := &http.Client{
		Timeout: time.Duration(a.opts.timeout) * time.Second,
	}

	var results []string
	seen := make(map[string]bool)
	page := 0

	for page < a.opts.pages && len(results) < a.opts.scrap {
		url := fmt.Sprintf(
			"https://www.google.com/search?q=-www+site:%s&start=%d",
			a.domain,
			page*10,
		)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return results
		}
		req.Header.Set("User-Agent", a.randomAgent())

		resp, err := client.Do(req)
		if err != nil {
			return results
		}

		doc, err := html.Parse(resp.Body)
		resp.Body.Close()
		if err != nil {
			return results
		}

		fmt.Printf(
			"\n ----   Google search page: %d   ---- \n\n",
			page+1,
		)

		for _, href := range a.collectLinks(doc) {
			if len(results) >= a.opts.scrap {
				break
			}
			sub := a.extractSubdomain(href)
			if sub == "" || seen[sub] {
				continue
			}
			seen[sub] = true
			a.store.addGoogleSub(sub)
			results = append(results, sub)
			fmt.Printf("  %s\n", sub)
		}

		page++
	}

	a.header("Google Results:\n")
	return results
}

func (a *app) collectLinks(node *html.Node) []string {
	var links []string
	if node.Type == html.ElementNode && node.Data == "a" {
		for _, attr := range node.Attr {
			if attr.Key == "href" {
				links = append(links, attr.Val)
			}
		}
	}
	for child := node.FirstChild; child != nil; child = child.NextSibling {
		links = append(links, a.collectLinks(child)...)
	}
	return links
}

func (a *app) extractSubdomain(href string) string {
	if strings.HasPrefix(href, "/url?") {
		href = "https://www.google.com" + href
	}

	u, err := url.Parse(href)
	if err != nil {
		return ""
	}

	target := u.Query().Get("q")
	if target != "" {
		u, err = url.Parse(target)
		if err != nil {
			return ""
		}
	}

	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}

	if !strings.HasSuffix(host, a.domain) {
		return ""
	}

	sub := strings.TrimSuffix(host, "."+a.domain)
	if sub == "" || sub == host {
		return ""
	}

	return sub
}

func (a *app) randomAgent() string {
	agents := []string{
		"Mozilla/5.0 (X11; Linux x86_64)",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
	}
	return agents[a.rng.Intn(len(agents))]
}

func (a *app) bruteForceFile(ctx context.Context) error {
	a.header("Brute forcing with " + a.opts.dnsFile + ":\n")

	file, err := os.Open(a.opts.dnsFile)
	if err != nil {
		return err
	}
	defer file.Close()

	var words []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		sub := strings.TrimSpace(scanner.Text())
		if sub == "" {
			continue
		}

		if a.opts.recursion {
			a.store.addFileSub(sub)
		}

		a.store.mu.Lock()
		_, exists := a.store.allSubs[sub]
		a.store.mu.Unlock()

		if !exists {
			words = append(words, sub+"."+a.domain)
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	if len(words) == 0 {
		fmt.Println(" Can't find new subdomains.")
		return nil
	}

	a.lookupHosts(ctx, words, "f")
	return nil
}

func (a *app) recursionFlow(ctx context.Context) {
	subs := a.allSubKeys()
	if len(subs) == 0 {
		fmt.Print("\n Can't perform recursion no subdomains.\n")
		return
	}

	a.header("Performing recursion:\n")
	fmt.Print("\n ---- Checking subdomains NS records ----\n")

	a.store.recurSubs = make(map[string]bool)
	a.selectSubdomains(ctx, addDomain(subs, a.domain))
	queue := a.recurKeys()
	if len(queue) == 0 {
		fmt.Print("\n  Can't perform recursion no NS records.\n")
		return
	}

	level := 1
	for len(queue) > 0 {
		fmt.Printf("\n ----   Recursion level %d   ---- \n", level)
		for _, sub := range queue {
			host := sub + "." + a.domain
			fmt.Printf("\n Recursion on %s ...\n", host)

			if a.hasWildcardHost(ctx, host) {
				fmt.Printf("  %s: Wildcards detected.\n", host)
				continue
			}

			words := a.recursionWords(host)
			a.recur = true
			a.lookupHosts(ctx, words, "r")
			a.recur = false
		}

		next := a.recurKeys()
		if len(next) == 0 {
			break
		}

		fmt.Println()
		a.header("Checking subdomains NS records:\n")
		a.selectSubdomains(ctx, addDomain(next, a.domain))
		queue = a.recurKeys()
		level++
	}

	a.store.fileSubs = make(map[string]bool)
}

func (a *app) selectSubdomains(
	ctx context.Context,
	hosts []string,
) {
	if len(hosts) == 0 {
		return
	}

	runTasks(hosts, a.opts.threads, func(host string) {
		msg, err := a.query(ctx, host, dns.TypeNS, nil)
		if err != nil {
			if a.opts.verbose {
				fmt.Fprintf(
					os.Stderr,
					"  %s NS record query failed: %v\n",
					host,
					err,
				)
			}
			return
		}

		for _, rr := range msg.Answer {
			ns, ok := rr.(*dns.NS)
			if !ok {
				continue
			}

			a.printRR(rr)
			a.xml.writeRR(rr)

			sub, ok := a.matchDomain(rr.Header().Name)
			if !ok || sub == "" {
				continue
			}

			a.store.addSub(sub, "r")
			a.store.addRecurSub(sub)
			_ = ns
		}
	})
}

func (a *app) recurKeys() []string {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()

	var subs []string
	for sub := range a.store.recurSubs {
		subs = append(subs, sub)
	}
	sort.Strings(subs)
	a.store.recurSubs = make(map[string]bool)
	return subs
}

func (a *app) hasWildcardHost(
	ctx context.Context,
	host string,
) bool {
	label := a.randomLabel(8)
	name := label + "." + host
	msg, err := a.query(ctx, name, dns.TypeA, nil)
	return err == nil && msg != nil && len(msg.Answer) > 0
}

func (a *app) recursionWords(host string) []string {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()

	var base []string
	for sub := range a.store.allSubs {
		base = append(base, sub)
	}
	for sub := range a.store.fileSubs {
		if _, ok := a.store.allSubs[sub]; !ok {
			base = append(base, sub)
		}
	}
	sort.Strings(base)

	uniq := make(map[string]bool)
	var words []string

	for _, name := range base {
		words = append(words, name+"."+host)

		for _, part := range strings.Split(name, ".") {
			if part == "" {
				continue
			}
			if _, ok := a.store.allSubs[part]; ok {
				continue
			}
			if a.store.fileSubs[part] || uniq[part] {
				continue
			}
			uniq[part] = true
			words = append(words, part+"."+host)
		}
	}

	return words
}

func (a *app) networkRanges() []string {
	var ips []string
	seen := make(map[string]bool)

	for _, ip := range a.resultsList() {
		if seen[ip] {
			continue
		}
		seen[ip] = true
		ips = append(ips, ip)
	}

	var cnets []string
	netSeen := make(map[string]bool)
	var filtered []string

	for _, ip := range sortIPs(ips) {
		octets := strings.Split(ip, ".")
		if len(octets) != 4 {
			continue
		}

		if isPrivate(ip) {
			if a.opts.private {
				a.store.addPrivate(ip)
			}
			continue
		}

		filtered = append(filtered, ip)

		netBase := strings.Join(octets[:3], ".") + ".0"
		if !netSeen[netBase] {
			netSeen[netBase] = true
			cnets = append(cnets, netBase)
		}
	}

	if a.opts.whois {
		a.header("Launching Whois Queries:\n")
		ranges := a.runWhois(cnets)
		a.header(a.domain + " whois netranges:\n")
		for _, block := range ranges {
			fmt.Printf(" %s\n", block)
		}
		if a.opts.noReverse {
			return filtered
		}
		return ranges
	}

	a.header(a.domain + " class C netranges:\n")
	for i := range cnets {
		cnets[i] += "/24"
		fmt.Printf(" %s\n", cnets[i])
	}
	a.store.bumpIPCount(len(cnets) * 256)

	if a.opts.noReverse {
		return filtered
	}
	return cnets
}

func (a *app) runWhois(ips []string) []string {
	set := &netRangeSet{}

	runTasks(ips, a.opts.threads, func(ip string) {
		a.whoisLookup(ip, set)
	})

	a.store.mu.Lock()
	var ranges []string
	for block := range a.store.netRanges {
		ranges = append(ranges, block)
	}
	a.store.mu.Unlock()

	sort.Strings(ranges)
	return ranges
}

func (a *app) whoisLookup(ip string, set *netRangeSet) {
	addr := net.ParseIP(ip)
	if addr == nil {
		return
	}

	if set.contains(addr) {
		return
	}

	if a.opts.delay > 0 {
		time.Sleep(
			time.Duration(a.rng.Intn(a.opts.delay+1)) * time.Second,
		)
	}

	var block *net.IPNet
	resp, err := whois.Whois(ip)
	if err == nil {
		block = parseWhoisRange(resp)
	}

	if block == nil {
		mask := net.CIDRMask(24, 32)
		block = &net.IPNet{
			IP:   addr.Mask(mask),
			Mask: mask,
		}
		fmt.Printf(
			" c class default:   %-15s    ->      %s"+
				"      (whois netrange operation failed)\n",
			ip,
			block.String(),
		)
	}

	if !set.add(*block) {
		return
	}
	if a.store.addNetRange(block.String()) {
		a.store.bumpIPCount(prefixSize(block))
		fmt.Printf(
			" whois ip result:   %-15s    ->      %s\n",
			ip,
			block.String(),
		)
	}
}

func parseWhoisRange(body string) *net.IPNet {
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		if key != "inetnum" && key != "netrange" {
			continue
		}
		val := strings.TrimSpace(parts[1])

		if strings.Contains(val, "/") {
			_, block, err := net.ParseCIDR(val)
			if err == nil {
				return block
			}
		}

		if strings.Contains(val, "-") {
			ips := rangeBounds(val)
			if len(ips) == 2 {
				return coverRange(ips[0], ips[1])
			}
		}
	}
	return nil
}

func finalValidIPs(ips []string) []string {
	sorted := sortIPs(ips)
	if len(sorted) == 0 {
		return nil
	}

	var ranges []string
	start := ipToUint32(net.ParseIP(sorted[0]))
	prev := start

	for i := 1; i < len(sorted); i++ {
		cur := ipToUint32(net.ParseIP(sorted[i]))
		if cur == prev+1 {
			prev = cur
			continue
		}
		ranges = append(ranges, rangeToCIDR(start, prev)...)
		start, prev = cur, cur
	}

	ranges = append(ranges, rangeToCIDR(start, prev)...)
	return ranges
}

func (a *app) nsAddresses() []string {
	var addrs []string
	for _, ns := range a.nameserverList() {
		addrs = append(addrs, a.nsAddress(ns))
	}
	if len(addrs) == 0 {
		addrs = a.serverList(a.opts.dnsServer)
	}
	return addrs
}

func (a *app) reverseLookups(
	ctx context.Context,
	ranges []string,
) error {
	if len(ranges) == 0 {
		return nil
	}

	servers := a.nsAddresses()
	a.header(
		fmt.Sprintf(
			"Performing reverse lookup on %d ip addresses:\n",
			a.store.ipCount,
		),
	)

	for _, block := range ranges {
		_, prefix, err := net.ParseCIDR(block)
		if err != nil {
			fmt.Fprintf(
				os.Stderr,
				" Can't perform reverse lookup: %v\n",
				err,
			)
			continue
		}

		ips := enumerate(prefix)
		valid := make(map[string]bool)
		runTasks(ips, a.opts.threads, func(ip string) {
			msg, err := a.query(ctx, ip, dns.TypePTR, servers)
			if err != nil {
				if a.opts.verbose {
					fmt.Printf("  %s    ...\n", ip)
				}
				return
			}

			for _, rr := range msg.Answer {
				ptr, ok := rr.(*dns.PTR)
				if !ok {
					continue
				}

				if a.exclude != nil &&
					a.exclude.MatchString(ptr.Ptr) {
					continue
				}

				sub, ok := a.matchDomain(ptr.Ptr)
				if ok {
					if a.extendR && sub != "" {
						a.store.addSub(sub, "r")
					}
					if !valid[ip] {
						valid[ip] = true
						a.store.bumpIPValid()
					}
					a.printRR(rr)
					a.xml.writeRR(rr)
				} else if a.opts.verbose {
					a.printRR(rr)
					a.xml.writeRR(rr)
				}
			}
		})

		var valids []string
		for ip := range valid {
			valids = append(valids, ip)
		}

		blocks := finalValidIPs(valids)
		for _, b := range blocks {
			a.store.addIPBlock(b)
		}
	}

	fmt.Printf(
		"\n%d results out of %d IP addresses.\n",
		a.store.ipValid,
		a.store.ipCount,
	)
	return nil
}

func (a *app) collectSubfileEntries() []string {
	var entries []string

	for _, host := range a.nameserverList() {
		h := a.trimDot(host)
		suffix := "." + a.domain
		if strings.HasSuffix(h, suffix) {
			entries = append(
				entries,
				strings.TrimSuffix(h, suffix),
			)
		}
	}

	for _, host := range a.mxList() {
		h := a.trimDot(host)
		suffix := "." + a.domain
		if strings.HasSuffix(h, suffix) {
			entries = append(
				entries,
				strings.TrimSuffix(h, suffix),
			)
		}
	}

	entries = append(entries, a.allSubKeys()...)
	return entries
}

func (a *app) writeSubFile(entries []string) error {
	if a.opts.subFile == "" {
		return nil
	}
	return writeMerged(a.opts.subFile, entries)
}

func (a *app) applyUpdate(entries []string) error {
	if a.opts.update == "" {
		return nil
	}
	return writeMerged(a.opts.dnsFile, entries)
}

func writeMerged(path string, entries []string) error {
	uniq := make(map[string]bool)

	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e != "" {
			uniq[e] = true
		}
	}

	data, err := os.ReadFile(path)
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				uniq[line] = true
			}
		}
	}

	var out []string
	for line := range uniq {
		out = append(out, line)
	}

	sort.Slice(out, func(i, j int) bool {
		return strings.ToUpper(out[i]) < strings.ToUpper(out[j])
	})

	return os.WriteFile(
		path,
		[]byte(strings.Join(out, "\n")+"\n"),
		0o644,
	)
}

func (a *app) writeIPBlocks() error {
	uniq := make(map[string]bool)
	for _, block := range a.store.ipBlocks {
		if strings.TrimSpace(block) != "" {
			uniq[block] = true
		}
	}

	var blocks []string
	for block := range uniq {
		blocks = append(blocks, block)
	}
	sort.Strings(blocks)
	return writeLines(a.fileIPs, blocks, false)
}

func writeLines(
	path string,
	lines []string,
	appendMode bool,
) error {
	flag := os.O_CREATE | os.O_WRONLY
	if appendMode {
		flag |= os.O_APPEND
	} else {
		flag |= os.O_TRUNC
	}

	file, err := os.OpenFile(path, flag, 0o644)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if _, err := file.WriteString(line + "\n"); err != nil {
			return err
		}
	}

	return nil
}

func (a *app) printPrivateIPs() {
	if !a.opts.private || len(a.store.privateIPs) == 0 {
		return
	}

	fmt.Printf(
		"\n--------------------------\n%s private ips:\n"+
			"--------------------------\n",
		a.domain,
	)
	for _, ip := range a.store.privateIPs {
		fmt.Printf(" %s\n", ip)
	}

	_ = writeLines(a.fileIPs, a.store.privateIPs, true)
}

func (a *app) printIPBlocks() {
	a.header(a.domain + " ip blocks:\n")
	uniq := make(map[string]bool)
	for _, block := range a.store.ipBlocks {
		if strings.TrimSpace(block) != "" {
			uniq[block] = true
		}
	}

	var blocks []string
	for block := range uniq {
		blocks = append(blocks, block)
	}
	sort.Strings(blocks)

	for _, block := range blocks {
		fmt.Printf(" %s\n", block)
	}
}

func (a *app) nsAddress(ns string) string {
	host := a.trimDot(ns)
	ip := lookupIP(host)
	target := host
	if ip != "" {
		target = ip
	}
	return net.JoinHostPort(target, a.resolver.Port)
}

func (a *app) randomLabel(size int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyz")
	var b strings.Builder
	for i := 0; i < size; i++ {
		b.WriteRune(letters[a.rng.Intn(len(letters))])
	}
	return b.String()
}

func (a *app) subsBySource(source string) []string {
	a.store.mu.Lock()
	defer a.store.mu.Unlock()

	var subs []string
	for sub, src := range a.store.allSubs {
		if src == source {
			subs = append(subs, sub)
		}
	}
	sort.Strings(subs)
	return subs
}

func (a *app) collectUpdateBeforeReverse() []string {
	if a.opts.update == "" {
		return nil
	}

	switch a.opts.update {
	case "z":
		return uniqHosts(a.subsBySource("z"))
	case "g":
		subs := uniqHosts(a.googleKeys())
		if len(a.store.googleSubs) > 0 {
			a.store.googleSubs = make(map[string]bool)
		}
		return subs
	}

	return nil
}

func (a *app) collectUpdateAll() []string {
	if a.opts.update != "a" && a.opts.update != "all" {
		return nil
	}

	var entries []string
	var base []string

	for _, host := range a.nameserverList() {
		h := a.trimDot(host)
		suffix := "." + a.domain
		if strings.HasSuffix(h, suffix) {
			base = append(base, strings.TrimSuffix(h, suffix))
		}
	}

	for _, host := range a.mxList() {
		h := a.trimDot(host)
		suffix := "." + a.domain
		if strings.HasSuffix(h, suffix) {
			base = append(base, strings.TrimSuffix(h, suffix))
		}
	}

	entries = append(entries, uniqHosts(base)...)
	entries = append(entries, uniqHosts(a.allSubKeys())...)
	return entries
}

func (a *app) collectUpdateReverse() []string {
	if a.opts.update == "" {
		return nil
	}

	subs := uniqHosts(a.allSubKeys())
	a.store.allSubs = make(map[string]string)
	return subs
}
