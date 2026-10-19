package main

import (
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDualStackFixtureUsesRefusedPhoneAddressAndReachableHost(t *testing.T) {
	for _, recordType := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		query := dnsmessage.Message{
			Header: dnsmessage.Header{ID: 42, RecursionDesired: true},
			Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("fec0--abcd.dual-stack.public.test."),
				Type: recordType, Class: dnsmessage.ClassINET}},
		}
		wire, err := query.Pack()
		if err != nil {
			t.Fatal(err)
		}
		response, err := dnsAnswer(wire)
		if err != nil {
			t.Fatal(err)
		}
		var answer dnsmessage.Message
		if err := answer.Unpack(response); err != nil || answer.ID != 42 || len(answer.Answers) != 1 {
			t.Fatalf("invalid fixture answer: %v, %+v", err, answer)
		}
		if recordType == dnsmessage.TypeA && answer.Answers[0].Body.(*dnsmessage.AResource).A != [4]byte{10, 0, 2, 2} {
			t.Fatal("IPv4 did not resolve to the real host HTTP proxy")
		}
		if recordType == dnsmessage.TypeAAAA && answer.Answers[0].Body.(*dnsmessage.AAAAResource).AAAA != netip.MustParseAddr("fec0::abcd").As16() {
			t.Fatal("IPv6 did not resolve to the phone's own address")
		}
	}
}
