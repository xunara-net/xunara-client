package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
)

func udpErrorProbe(ctx context.Context, target string) error {
	address, err := netip.ParseAddrPort(target)
	if err != nil || !address.Addr().IsPrivate() || address.Port() == 0 {
		return errors.New("UDP error probe requires a private numeric test endpoint")
	}
	connection, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "udp", address.String())
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(4 * time.Second)); err != nil {
		return err
	}
	if _, err := connection.Write([]byte("icmp-related-probe")); err != nil {
		return err
	}
	buffer := make([]byte, 128)
	_, err = connection.Read(buffer)
	if !errors.Is(err, syscall.ECONNREFUSED) {
		return errors.New("expected authenticated ICMP port-unreachable instead of a silent timeout")
	}
	fmt.Println("PASS authenticated related ICMP reaches the originating UDP socket")
	return nil
}
