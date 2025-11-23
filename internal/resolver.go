package internal

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

func loadResolver(server string) (*dns.ClientConfig, error) {
	if server != "" {
		host, port, err := splitHostPort(server)
		if err != nil {
			return nil, err
		}
		return &dns.ClientConfig{
			Servers: []string{host},
			Port:    port,
		}, nil
	}

	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("resolver: %w", err)
	}
	return cfg, nil
}

func splitHostPort(host string) (string, string, error) {
	if strings.Contains(host, ":") {
		h, p, err := net.SplitHostPort(host)
		if err != nil {
			return "", "", err
		}
		return h, p, nil
	}
	return host, "53", nil
}

func runTasks(items []string, threads int, fn func(string)) {
	if len(items) == 0 {
		return
	}
	if threads < 1 || len(items) == 1 {
		for _, item := range items {
			fn(item)
		}
		return
	}

	if threads > len(items) {
		threads = len(items)
	}

	ch := make(chan string)
	var wg sync.WaitGroup

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for item := range ch {
				fn(item)
			}
		}()
	}

	for _, item := range items {
		ch <- item
	}
	close(ch)
	wg.Wait()
}

func lookupIP(host string) string {
	ctx, cancel := context.WithTimeout(
		context.Background(),
		3*time.Second,
	)
	defer cancel()

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0].String()
}
