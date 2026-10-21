package main

import (
	"context"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

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
