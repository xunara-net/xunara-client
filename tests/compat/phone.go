package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

func fixturePolicy(denyPhone bool) []byte {
	ports := []string{"*:8088", "*:5353", "*:53"}
	if !denyPhone {
		ports = append(ports, "*:18088")
	}
	rules := []map[string]any{
		{"action": "accept", "src": []string{"*"}, "proto": "tcp", "dst": ports},
		{"action": "accept", "src": []string{"*"}, "proto": "udp", "dst": []string{"*:5353", "*:18088"}},
		{"action": "accept", "src": []string{"*"}, "proto": "icmp", "dst": []string{"*:*"}},
		{"action": "accept", "src": []string{"*"}, "proto": "icmpv6", "dst": []string{"*:*"}},
	}
	encoded, _ := json.Marshal(map[string]any{"acls": rules})
	return encoded
}

// 此探针只在 rootless 隔离 fixture 中运行，流量由官方 tsnet 发起，不是手机自身绕过 VPN 的请求。
func officialPhoneProbe(ctx context.Context, directory string) error {
	secret, err := os.ReadFile(filepath.Join(directory, "auth-key"))
	if err != nil {
		return err
	}
	server := &tsnet.Server{Dir: filepath.Join(directory, "phone-probe"), Hostname: "official-phone-probe", ControlURL: "http://127.0.0.1:18080", AuthKey: strings.TrimSpace(string(secret)), Logf: logger.Discard, UserLogf: logger.Discard}
	defer server.Close()
	up, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if _, err := server.Up(up); err != nil {
		return err
	}
	client, err := server.LocalClient()
	if err != nil {
		return err
	}
	if _, err := client.EditPrefs(up, &ipn.MaskedPrefs{Prefs: ipn.Prefs{RouteAll: true}, RouteAllSet: true}); err != nil {
		return err
	}
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: 1234, RecursionDesired: true}, Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("external.public.test."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	wire, err := query.Pack()
	if err != nil {
		return err
	}
	var lock sync.Mutex
	var held net.Conn
	var reader *bufio.Reader
	details := make(map[string]string)
	defer func() {
		lock.Lock()
		defer lock.Unlock()
		if held != nil {
			held.Close()
		}
	}()
	tcpProbe := func(ctx context.Context, target string, port string) bool {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		connection, err := server.Dial(ctx, "tcp", net.JoinHostPort(target, port))
		if err != nil {
			details["tcp:"+target+":"+port] = err.Error()
			return false
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := io.WriteString(connection, "GET / HTTP/1.0\r\n\r\n"); err != nil {
			return false
		}
		response, err := io.ReadAll(io.LimitReader(connection, 4096))
		if err != nil {
			details["tcp:"+target+":"+port] = err.Error()
		}
		return err == nil && bytes.Contains(response, []byte("xunara-core-ok"))
	}
	udpProbe := func(ctx context.Context, target string) bool {
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		connection, err := server.Dial(ctx, "udp", net.JoinHostPort(target, "18088"))
		if err != nil {
			details["udp:"+target] = err.Error()
			return false
		}
		defer connection.Close()
		connection.SetDeadline(time.Now().Add(3 * time.Second))
		if _, err := connection.Write(wire); err != nil {
			return false
		}
		var response [4096]byte
		length, err := connection.Read(response[:])
		if err != nil {
			details["udp:"+target] = err.Error()
		}
		var answer dnsmessage.Message
		return err == nil && answer.Unpack(response[:length]) == nil && answer.Response && answer.ID == 1234 && len(answer.Answers) > 0
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		lock.Lock()
		defer lock.Unlock()
		probe, cancel := context.WithTimeout(request.Context(), 25*time.Second)
		defer cancel()
		details = make(map[string]string)
		result := map[string]any{}
		switch request.URL.Query().Get("step") {
		case "status":
			status, statusErr := client.Status(probe)
			prefs, prefsErr := client.GetPrefs(probe)
			if statusErr != nil || prefsErr != nil {
				writer.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			peers := make([]map[string]any, 0, len(status.Peer))
			for _, peer := range status.Peer {
				peers = append(peers, map[string]any{"host": peer.HostName, "id": peer.ID, "allowed": peer.AllowedIPs, "primary": peer.PrimaryRoutes, "peerapi": peer.PeerAPIURL})
			}
			filter, _ := client.DebugPacketFilterRules(probe)
			json.NewEncoder(writer).Encode(map[string]any{"route_all": prefs.RouteAll, "exit": prefs.ExitNodeID, "peers": peers, "addresses": status.TailscaleIPs, "filter": filter})
			return
		case "select-exit":
			status, err := client.Status(probe)
			if err == nil {
				for _, peer := range status.Peer {
					if peer.HostName == "android-integration" {
						_, err = client.EditPrefs(probe, &ipn.MaskedPrefs{Prefs: ipn.Prefs{RouteAll: true, ExitNodeID: peer.ID}, RouteAllSet: true, ExitNodeIDSet: true})
						result["selected"] = err == nil
					}
				}
			}
		case "dns":
			status, err := client.Status(probe)
			if err == nil {
				for _, peer := range status.Peer {
					if peer.HostName == "android-integration" && len(peer.PeerAPIURL) > 0 {
						address := peer.PeerAPIURL[0] + "/dns-query"
						dnsRequest, _ := http.NewRequestWithContext(probe, http.MethodPost, address, bytes.NewReader(wire))
						dnsRequest.Header.Set("Content-Type", "application/dns-message")
						httpClient := server.HTTPClient()
						httpClient.Timeout = 5 * time.Second
						response, err := httpClient.Do(dnsRequest)
						if err == nil {
							content, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
							response.Body.Close()
							var answer dnsmessage.Message
							result["dns"] = readErr == nil && response.StatusCode == http.StatusOK && answer.Unpack(content) == nil && answer.ID == 1234 && len(answer.Answers) > 0
						}
					}
				}
			}
		case "hold":
			if held != nil {
				held.Close()
			}
			held, err = server.Dial(probe, "tcp", "10.0.2.2:18088")
			if err == nil {
				held.SetDeadline(time.Now().Add(3 * time.Second))
				reader = bufio.NewReader(held)
				io.WriteString(held, "GET / HTTP/1.1\r\nHost: fixture\r\n\r\n")
				response, readErr := http.ReadResponse(reader, nil)
				if readErr == nil {
					io.Copy(io.Discard, response.Body)
					response.Body.Close()
					result["held"] = true
				}
			}
		case "hold-blocked":
			if held != nil {
				held.SetDeadline(time.Now().Add(2 * time.Second))
				_, writeErr := io.WriteString(held, "GET / HTTP/1.1\r\nHost: fixture\r\n\r\n")
				_, readErr := http.ReadResponse(reader, nil)
				result["blocked"] = writeErr != nil || readErr != nil
				held.Close()
				held = nil
			}
		case "denied-port":
			result["blocked"] = !tcpProbe(probe, "10.0.2.2", "18089")
		case "blocked":
			result["blocked"] = !tcpProbe(probe, "10.0.2.2", "18088")
		default:
			ipv6, parseErr := netip.ParseAddr(request.URL.Query().Get("ipv6"))
			if parseErr != nil || !netip.MustParsePrefix("fec0::/64").Contains(ipv6) {
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			for _, family := range []struct{ name, address string }{{"4", "10.0.2.2"}, {"6", ipv6.String()}} {
				result["tcp"+family.name] = tcpProbe(probe, family.address, "18088")
				result["udp"+family.name] = udpProbe(probe, family.address)
				pingContext, cancelPing := context.WithTimeout(probe, 3*time.Second)
				ping, err := client.Ping(pingContext, netip.MustParseAddr(family.address), tailcfg.PingICMP)
				cancelPing()
				result["icmp"+family.name] = err == nil && ping.Err == ""
				if err != nil {
					details["icmp"+family.name] = err.Error()
				} else if ping.Err != "" {
					details["icmp"+family.name] = ping.Err
				}
			}
		}
		writer.Header().Set("Content-Type", "application/json")
		if len(details) > 0 {
			result["errors"] = details
		}
		json.NewEncoder(writer).Encode(result)
	})
	httpServer := &http.Server{Addr: "127.0.0.1:8099", Handler: mux, ReadHeaderTimeout: 3 * time.Second}
	go func() { <-ctx.Done(); httpServer.Close() }()
	if err := os.WriteFile(filepath.Join(directory, "phone-probe-ready"), []byte("ready\n"), 0o600); err != nil {
		return err
	}
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
