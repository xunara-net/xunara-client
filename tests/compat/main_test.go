package main

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestUDPCapacityProbeUsesBoundedDistinctFlows(test *testing.T) {
	server, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		test.Fatal(err)
	}
	defer server.Close()
	if err := udpCapacityProbe(context.Background(), server.LocalAddr().String()); err != nil {
		test.Fatal(err)
	}
	server.SetReadDeadline(time.Now().Add(time.Second))
	remotes := map[string]bool{}
	buffer := make([]byte, 512)
	for attempt := 0; attempt < 33; attempt++ {
		length, remote, err := server.ReadFrom(buffer)
		if err != nil {
			test.Fatal(err)
		}
		var query dnsmessage.Message
		if err := query.Unpack(buffer[:length]); err != nil || len(query.Questions) != 1 {
			test.Fatal("probe did not send a valid single-question DNS packet")
		}
		remotes[remote.String()] = true
	}
	if len(remotes) != 33 {
		test.Fatalf("expected 33 distinct UDP flows, got %d", len(remotes))
	}
	for _, invalid := range []string{"resolver.test:53", "127.0.0.1:0", "224.0.0.1:53", "[::1]:53"} {
		if err := udpCapacityProbe(context.Background(), invalid); err == nil {
			test.Fatalf("invalid endpoint accepted: %s", invalid)
		}
	}
}

func TestDNSBurstQueriesItsExplicitResolverWithoutAnApplicationCache(test *testing.T) {
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		test.Fatal(err)
	}
	var queries atomic.Int32
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		buffer := make([]byte, 4096)
		for {
			length, remote, err := server.ReadFrom(buffer)
			if err != nil {
				return
			}
			queries.Add(1)
			answer, err := dnsAnswer(buffer[:length])
			if err == nil {
				server.WriteTo(answer, remote)
			}
		}
	}()
	test.Cleanup(func() { server.Close(); <-finished })
	if err := dnsBurst(context.Background(), server.LocalAddr().String(), "external.public.test", 4); err != nil {
		test.Fatal(err)
	}
	if queries.Load() < 8 {
		test.Fatalf("expected fresh A/AAAA queries for every lookup, got %d", queries.Load())
	}
}

func TestDNSBurstRejectsUnboundedOrNonNumericInputsBeforeDialing(test *testing.T) {
	for _, candidate := range []struct {
		endpoint, name string
		count          int
	}{
		{"resolver.test:53", "external.public.test", 1},
		{"127.0.0.1:53", "external.public.test", 0},
		{"127.0.0.1:53", "external.public.test", 129},
		{"127.0.0.1:53", "", 1},
	} {
		if err := dnsBurst(context.Background(), candidate.endpoint, candidate.name, candidate.count); err == nil {
			test.Fatal("invalid DNS burst input accepted")
		}
	}
}

func TestUnreachableDNSIsLimitedToTheIsolatedAndroidPair(test *testing.T) {
	for _, enabled := range []string{"", "false", "true"} {
		test.Run(enabled, func(test *testing.T) {
			test.Setenv("XUNARA_TEST_UNREACHABLE_DNS", enabled)
			if got := strings.Join(fixtureNameservers(false), ","); got != "192.168.90.2:5353" {
				test.Fatalf("ordinary fixture DNS changed: %s", got)
			}
			want := "114.114.114.114,1.1.1.1"
			if enabled == "true" {
				want = "192.0.2.53"
			}
			if got := strings.Join(fixtureNameservers(true), ","); got != want {
				test.Fatalf("pair fixture DNS = %s, want %s", got, want)
			}
		})
	}
}

func TestWebProbeRejectsInvalidPreResolvedTarget(test *testing.T) {
	for _, address := range []string{"127.0.0.1", "10.0.0.1", "0.0.0.0", "224.0.0.1", "::1", "2606:4700::1111", "::ffff:1.1.1.1", "example.com"} {
		test.Run(address, func(test *testing.T) {
			err := webProbe(context.Background(), "100.100.100.100:53", address)
			if err == nil || !strings.Contains(err.Error(), "requires a public IPv4") {
				test.Fatalf("expected target validation before dialing, got %v", err)
			}
		})
	}
}

func TestWebProbeRequiresNumericDNSEndpoint(test *testing.T) {
	for _, endpoint := range []string{"", "localhost:53", "1.1.1.1", "1.1.1.1:invalid"} {
		test.Run(endpoint, func(test *testing.T) {
			err := webProbe(context.Background(), endpoint, "1.1.1.1")
			if err == nil || !strings.Contains(err.Error(), "requires a numeric VPN DNS endpoint") {
				test.Fatalf("expected DNS endpoint validation before dialing, got %v", err)
			}
		})
	}
}

func TestUDPErrorProbeRejectsNonPrivateOrInvalidTargets(test *testing.T) {
	for _, target := range []string{"", "example.com:53", "1.1.1.1:53", "127.0.0.1:53", "10.0.0.1:0"} {
		if err := udpErrorProbe(context.Background(), target); err == nil || !strings.Contains(err.Error(), "private numeric") {
			test.Fatalf("invalid UDP error probe target was not rejected")
		}
	}
}

func TestFixtureICMPPolicyIncludesSharedAliasesButNotLAN(test *testing.T) {
	for _, denyPhone := range []bool{false, true} {
		var document struct {
			ACLs []struct {
				Proto string   `json:"proto"`
				Src   []string `json:"src"`
			} `json:"acls"`
		}
		if err := json.Unmarshal(fixturePolicy(denyPhone), &document); err != nil {
			test.Fatal(err)
		}
		for _, candidate := range []struct {
			protocol string
			address  string
			allowed  bool
		}{
			{"icmp", "100.80.0.2", true},
			{"icmp", "100.127.0.1", true},
			{"icmp", "192.168.90.2", false},
			{"icmp", "203.0.113.77", false},
			{"icmpv6", "fd7a:115c:a1e0::1", true},
			{"icmpv6", "fd7a:115c:a1e0:ffff::1", true},
			{"icmpv6", "2001:db8::77", false},
		} {
			allowed := false
			for _, rule := range document.ACLs {
				if rule.Proto != candidate.protocol {
					continue
				}
				for _, source := range rule.Src {
					prefix, err := netip.ParsePrefix(source)
					if err != nil {
						test.Fatalf("ICMP fixture source must be an explicit prefix: %v", err)
					}
					allowed = allowed || prefix.Contains(netip.MustParseAddr(candidate.address))
				}
			}
			if allowed != candidate.allowed {
				test.Errorf("denyPhone=%v %s source %s allowed=%v, want %v", denyPhone, candidate.protocol, candidate.address, allowed, candidate.allowed)
			}
		}
	}
}
