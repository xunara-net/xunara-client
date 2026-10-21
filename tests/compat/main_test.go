package main

import (
	"context"
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
