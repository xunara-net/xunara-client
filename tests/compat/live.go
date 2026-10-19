package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	_ "tailscale.com/feature/capture"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

// 现网专项必须单独提供短期机器凭据；不能复用手机私钥、管理员令牌或人类会话。
func liveProbe(ctx context.Context, directory string) error {
	var configuration struct {
		Server  string               `json:"server"`
		Host    string               `json:"hostname"`
		ExitID  tailcfg.StableNodeID `json:"exit_id"`
		Prefix  netip.Prefix         `json:"expected_ipv4_prefix"`
		Capture bool                 `json:"capture"`
	}
	if directory == "" {
		return errors.New("live diagnostics require a private directory")
	}
	information, err := os.Stat(directory)
	if err != nil || !information.IsDir() || information.Mode().Perm()&0o077 != 0 {
		return errors.New("live diagnostic directory must be private")
	}
	content, err := os.ReadFile(filepath.Join(directory, "live.json"))
	if err != nil || json.Unmarshal(content, &configuration) != nil ||
		!strings.HasPrefix(configuration.Server, "https://") || configuration.Host == "" ||
		configuration.ExitID.IsZero() || !configuration.Prefix.IsValid() || !configuration.Prefix.Addr().Is4() {
		return errors.New("invalid live diagnostic configuration")
	}
	secretPath := filepath.Join(directory, "auth-key")
	information, err = os.Lstat(secretPath)
	if err != nil || !information.Mode().IsRegular() || information.Mode().Perm()&0o077 != 0 {
		return errors.New("live credential must be a private regular file")
	}
	secret, err := os.ReadFile(secretPath)
	if err != nil {
		return err
	}
	server := &tsnet.Server{Dir: filepath.Join(directory, "tsnet"), Hostname: configuration.Host,
		ControlURL: configuration.Server, AuthKey: strings.TrimSpace(string(secret)), Ephemeral: true,
		Logf: logger.Discard, UserLogf: logger.Discard}
	defer server.Close()
	startup, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	status, err := server.Up(startup)
	if err != nil {
		return errors.New("live diagnostic control connection failed")
	}
	var exit *ipnstate.PeerStatus
	for _, peer := range status.Peer {
		if peer.ID == configuration.ExitID {
			exit = peer
		}
	}
	matched := false
	for _, address := range status.TailscaleIPs {
		matched = matched || configuration.Prefix.Contains(address)
	}
	if !matched || exit == nil || !exit.ExitNodeOption {
		return errors.New("live diagnostics refused unexpected tenant or unapproved exit")
	}
	emit := func(stage string, details any) {
		json.NewEncoder(os.Stdout).Encode(map[string]any{"stage": stage, "details": details})
	}
	emit("connected", map[string]any{"addresses": status.TailscaleIPs, "self_id": status.Self.ID})
	client, err := server.LocalClient()
	if err != nil {
		return err
	}
	if configuration.Capture {
		captureFile, err := os.OpenFile(filepath.Join(directory, "traffic.pcap"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		capture, err := client.StreamDebugCapture(ctx)
		if err != nil {
			captureFile.Close()
			return err
		}
		finished := make(chan struct{})
		go func() {
			defer close(finished)
			_, _ = io.Copy(captureFile, io.LimitReader(capture, 8<<20))
		}()
		defer func() {
			capture.Close()
			<-finished
			captureFile.Close()
		}()
	}
	for _, peer := range status.Peer {
		emit("peer", map[string]any{"id": peer.ID, "host": peer.HostName, "online": peer.Online,
			"exit": peer.ExitNodeOption, "peerapi": peer.PeerAPIURL, "allowed": peer.AllowedIPs})
		for _, address := range peer.TailscaleIPs {
			probe, stop := context.WithTimeout(ctx, 6*time.Second)
			result, probeErr := client.Ping(probe, address, tailcfg.PingICMP)
			stop()
			emit("peer_ping", map[string]any{"address": address, "result": result, "ok": probeErr == nil})
		}
	}
	if _, err := client.EditPrefs(ctx, &ipn.MaskedPrefs{
		Prefs:       ipn.Prefs{RouteAll: true, CorpDNS: true, ExitNodeID: configuration.ExitID},
		RouteAllSet: true, CorpDNSSet: true, ExitNodeIDSet: true,
	}); err != nil {
		return err
	}
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: 1234, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: dnsmessage.MustNewName("cloudflare.com."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}}}
	wire, err := query.Pack()
	if err != nil {
		return err
	}
	httpClient := server.HTTPClient()
	httpClient.Timeout = 15 * time.Second
	for _, endpoint := range exit.PeerAPIURL {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/dns-query", bytes.NewReader(wire))
		if err != nil {
			return err
		}
		request.Header.Set("Content-Type", "application/dns-message")
		response, requestErr := httpClient.Do(request)
		result := map[string]any{"endpoint": endpoint, "ok": false}
		if requestErr == nil {
			payload, readErr := io.ReadAll(io.LimitReader(response.Body, 4096))
			response.Body.Close()
			var answer dnsmessage.Message
			result["status"] = response.StatusCode
			result["ok"] = readErr == nil && answer.Unpack(payload) == nil && answer.ID == 1234 && len(answer.Answers) > 0
			result["rcode"] = answer.RCode
		} else {
			result["error"] = requestErr.Error()
		}
		emit("exit_dns", result)
	}
	for _, target := range []string{"http://1.1.1.1/cdn-cgi/trace", "https://example.com/"} {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return err
		}
		targetClient := httpClient
		if strings.HasPrefix(target, "http://") {
			direct := *httpClient
			direct.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
			targetClient = &direct
		}
		response, requestErr := targetClient.Do(request)
		result := map[string]any{"target": target, "ok": false}
		if requestErr == nil {
			payload, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			response.Body.Close()
			result["status"], result["bytes"] = response.StatusCode, len(payload)
			result["ok"] = readErr == nil && response.StatusCode == http.StatusOK && len(payload) > 0
			result["verified_tls"] = response.TLS != nil && len(response.TLS.VerifiedChains) > 0
		} else {
			result["error"] = requestErr.Error()
		}
		emit("exit_http", result)
	}
	for _, family := range []string{"tcp4", "tcp6"} {
		transport := &http.Transport{DialContext: func(ctx context.Context, _ string, address string) (net.Conn, error) {
			return server.Dial(ctx, family, address)
		}, TLSHandshakeTimeout: 8 * time.Second}
		familyClient := &http.Client{Transport: transport, Timeout: 15 * time.Second}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
		if err != nil {
			return err
		}
		response, requestErr := familyClient.Do(request)
		result := map[string]any{"family": family, "ok": false}
		if requestErr == nil {
			payload, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
			response.Body.Close()
			result["status"], result["bytes"] = response.StatusCode, len(payload)
			result["ok"] = readErr == nil && response.StatusCode == http.StatusOK && response.TLS != nil && len(response.TLS.VerifiedChains) > 0
		} else {
			result["error"] = requestErr.Error()
		}
		transport.CloseIdleConnections()
		emit("exit_https_family", result)
	}
	if final, err := client.Status(ctx); err == nil {
		for _, peer := range final.Peer {
			emit("peer_final", map[string]any{"id": peer.ID, "online": peer.Online, "relay": peer.Relay,
				"direct": peer.CurAddr != "", "received": peer.RxBytes, "sent": peer.TxBytes, "handshake": peer.LastHandshake})
		}
	}
	fmt.Println("Live diagnostics finished; results do not change client preferences on other devices.")
	return nil
}
