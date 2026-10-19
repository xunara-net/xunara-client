package main

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/ipn"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

func officialExit(ctx context.Context, directory string) error {
	secret, err := os.ReadFile(filepath.Join(directory, "auth-key"))
	if err != nil {
		return err
	}
	server := &tsnet.Server{Dir: filepath.Join(directory, "official-exit"), Hostname: "official-exit", ControlURL: "http://127.0.0.1:18080", AuthKey: strings.TrimSpace(string(secret)), Logf: logger.Discard, UserLogf: logger.Discard}
	defer server.Close()
	// tsnet 默认拒绝未注册监听；仅允许隔离 namespace 中两个测试目的地址的真实转发。
	unregister := server.RegisterFallbackTCPHandler(func(_ netip.AddrPort, destination netip.AddrPort) (func(net.Conn), bool) {
		if destination.Port() != 8088 || destination.Addr() != netip.MustParseAddr("203.0.113.77") && destination.Addr() != netip.MustParseAddr("2001:db8::77") {
			return nil, false
		}
		return func(incoming net.Conn) {
			defer incoming.Close()
			outgoing, err := (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, "tcp", destination.String())
			if err != nil {
				return
			}
			defer outgoing.Close()
			incoming.SetDeadline(time.Now().Add(10 * time.Second))
			outgoing.SetDeadline(time.Now().Add(10 * time.Second))
			done := make(chan struct{})
			go func() {
				io.Copy(outgoing, incoming)
				if socket, ok := outgoing.(*net.TCPConn); ok {
					socket.CloseWrite()
				}
				close(done)
			}()
			io.Copy(incoming, outgoing)
			incoming.Close()
			<-done
		}, true
	})
	defer unregister()
	up, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if _, err := server.Up(up); err != nil {
		return err
	}
	local, err := server.LocalClient()
	if err != nil {
		return err
	}
	_, err = local.EditPrefs(up, &ipn.MaskedPrefs{Prefs: ipn.Prefs{AdvertiseRoutes: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}}, AdvertiseRoutesSet: true})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(directory, "exit-ready"), []byte("ready\n"), 0o600); err != nil {
		return err
	}
	<-ctx.Done()
	return nil
}

func dnsAnswer(bytes []byte) ([]byte, error) {
	var query dnsmessage.Message
	if err := query.Unpack(bytes); err != nil {
		return nil, err
	}
	if query.Response || len(query.Questions) != 1 {
		return nil, errors.New("invalid fixture DNS query")
	}
	question := query.Questions[0]
	response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionDesired: query.RecursionDesired, RecursionAvailable: true}, Questions: query.Questions}
	if !strings.HasSuffix(question.Name.String(), "public.test.") && !strings.HasSuffix(question.Name.String(), "split.test.") {
		response.RCode = dnsmessage.RCodeNameError
	} else {
		header := dnsmessage.ResourceHeader{Name: question.Name, Type: question.Type, Class: dnsmessage.ClassINET, TTL: 5}
		ipv4 := [4]byte{203, 0, 113, 77}
		ipv6 := netip.MustParseAddr("2001:db8::77")
		if strings.HasSuffix(question.Name.String(), ".dual-stack.public.test.") {
			address, err := netip.ParseAddr(strings.ReplaceAll(strings.TrimSuffix(question.Name.String(), ".dual-stack.public.test."), "-", ":"))
			if err != nil || !address.Is6() || address.Is4In6() {
				return nil, errors.New("invalid dual-stack fixture address")
			}
			ipv4 = [4]byte{10, 0, 2, 2}
			ipv6 = address
		}
		switch question.Type {
		case dnsmessage.TypeA:
			response.Answers = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.AResource{A: ipv4}}}
		case dnsmessage.TypeAAAA:
			response.Answers = []dnsmessage.Resource{{Header: header, Body: &dnsmessage.AAAAResource{AAAA: ipv6.As16()}}}
		}
	}
	return response.Pack()
}

func dnsFixture(ctx context.Context, listen string) error {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	packet, err := net.ListenPacket("udp", listen)
	if err != nil {
		return err
	}
	defer packet.Close()
	go func() { <-ctx.Done(); listener.Close(); packet.Close() }()
	go func() {
		buffer := make([]byte, 4096)
		for {
			length, source, err := packet.ReadFrom(buffer)
			if err != nil {
				return
			}
			if response, err := dnsAnswer(buffer[:length]); err == nil {
				packet.WriteTo(response, source)
			}
		}
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer connection.Close()
			connection.SetDeadline(time.Now().Add(5 * time.Second))
			var length [2]byte
			if _, err := io.ReadFull(connection, length[:]); err != nil {
				return
			}
			size := int(binary.BigEndian.Uint16(length[:]))
			if size < 12 || size > 4096 {
				return
			}
			bytes := make([]byte, size)
			if _, err := io.ReadFull(connection, bytes); err != nil {
				return
			}
			response, err := dnsAnswer(bytes)
			if err != nil {
				return
			}
			binary.BigEndian.PutUint16(length[:], uint16(len(response)))
			connection.Write(append(length[:], response...))
		}()
	}
}
