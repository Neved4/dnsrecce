package internal

import (
	"net"
	"reflect"
	"testing"
)

func TestUniqHosts(t *testing.T) {
	got := uniqHosts([]string{"a.b", "b.c", "a"})
	want := []string{"a", "b", "c"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("uniqHosts() = %v, want %v", got, want)
	}
}

func TestRangeToCIDR(t *testing.T) {
	got := rangeToCIDR(
		ipToUint32(parseIP(t, "10.0.0.0")),
		ipToUint32(parseIP(t, "10.0.0.3")),
	)
	want := []string{"10.0.0.0/30"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("rangeToCIDR() = %v, want %v", got, want)
	}
}

func parseIP(t *testing.T, ip string) net.IP {
	t.Helper()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("parseIP(%q) returned nil", ip)
	}
	return parsed
}

func TestNormalizeLongFlags(t *testing.T) {
	in := []string{"-domain", "example.com", "-scrap=5", "-v", "--help"}
	got := normalizeLongFlags(in)
	want := []string{"--domain", "example.com", "--scrap=5", "-v", "--help"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeLongFlags() = %v, want %v", got, want)
	}
}
