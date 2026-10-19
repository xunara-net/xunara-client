package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/xunara-net/xunara-server/control"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
	"tailscale.com/derp/derpserver"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
)

func main() {
	mode := flag.String("mode", "fixture", "fixture | proxy | http | official | exit | phone | dns | web-probe | stun-vector | masq-vector")
	directory := flag.String("dir", "", "private test directory")
	listen := flag.String("listen", "127.0.0.1:18080", "test listen address")
	target := flag.String("target", "", "test proxy/HTTP target")
	flag.Parse()
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	var err error
	switch *mode {
	case "proxy":
		err = proxy(ctx, *listen, *target)
	case "http":
		server := &http.Server{Addr: *listen, Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			fmt.Fprintln(writer, "xunara-core-ok")
		}), ReadHeaderTimeout: 3 * time.Second}
		go func() { <-ctx.Done(); server.Close() }()
		err = server.ListenAndServe()
	case "official":
		err = official(ctx, *directory, *target)
	case "exit":
		err = officialExit(ctx, *directory)
	case "phone":
		err = officialPhoneProbe(ctx, *directory)
	case "dns":
		err = dnsFixture(ctx, *listen)
	case "web-probe":
		err = webProbe(ctx, *listen)
	case "stun-vector":
		packet, readErr := hex.DecodeString(*target)
		if readErr != nil {
			err = readErr
			break
		}
		_, err = stun.ParseBindingRequest(packet)
	case "masq-vector":
		err = masqueradeVector(*target)
	case "fixture":
		err = fixture(ctx, *directory)
	default:
		err = errors.New("unknown test mode")
	}
	if err != nil && ctx.Err() == nil {
		log.Fatal(err)
	}
}

func webProbe(ctx context.Context, dnsAddress string) error {
	if _, err := netip.ParseAddrPort(dnsAddress); err != nil {
		return errors.New("web probe requires a numeric VPN DNS endpoint")
	}
	// 探针从 Android shell UID 发包，刻意不 protect、不使用代理，也不能跳过证书校验。
	dialer := &net.Dialer{Timeout: 8 * time.Second, Resolver: &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, dnsAddress)
		},
	}}
	transport := &http.Transport{DialContext: dialer.DialContext, TLSHandshakeTimeout: 8 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(request *http.Request, previous []*http.Request) error {
		if request.URL.Scheme != "https" || len(previous) >= 3 {
			return errors.New("web probe rejected redirect")
		}
		return nil
	}}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/", nil)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK || response.TLS == nil || len(response.TLS.VerifiedChains) == 0 || len(body) == 0 {
		return errors.New("web probe did not receive an authenticated HTTPS page")
	}
	fmt.Printf("PASS verified HTTPS status=%d bytes=%d\n", response.StatusCode, len(body))
	return nil
}

func proxy(ctx context.Context, listen, target string) error {
	listener, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	defer listener.Close()
	go func() { <-ctx.Done(); listener.Close() }()
	for {
		incoming, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer incoming.Close()
			outgoing, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", target)
			if err != nil {
				return
			}
			defer outgoing.Close()
			done := make(chan struct{})
			go func() { io.Copy(outgoing, incoming); outgoing.Close(); close(done) }()
			io.Copy(incoming, outgoing)
			incoming.Close()
			<-done
		}()
	}
}

func fixture(ctx context.Context, directory string) error {
	if directory == "" {
		return errors.New("private test directory required")
	}
	androidPair := os.Getenv("XUNARA_TEST_ANDROID_PAIR") == "true"
	if androidPair {
		mapping, err := os.ReadFile("/proc/self/uid_map")
		fields := strings.Fields(string(mapping))
		interfaces, networkErr := net.Interfaces()
		// 无认证的专项审批入口只能在新建的 rootless 网络中监听，不能暴露在宿主 LAN。
		if err != nil || os.Geteuid() != 0 || len(fields) != 3 || fields[0] != "0" || fields[1] == "0" || fields[2] != "1" ||
			networkErr != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" {
			return errors.New("Android pair fixture requires an isolated user/network namespace")
		}
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	derp := derpserver.New(key.NewNode(), logger.Discard)
	defer derp.Close()
	derpHTTP := httptest.NewUnstartedServer(derpserver.Handler(derp))
	derpHTTP.Listener.Close()
	listener, err := net.Listen("tcp", "0.0.0.0:8081")
	if err != nil {
		return err
	}
	derpHTTP.Listener = listener
	derpHTTP.StartTLS()
	defer derpHTTP.Close()
	digest := sha256.Sum256(derpHTTP.Certificate().Raw)
	derpMap := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{900: {
		RegionID: 900, RegionCode: "test", RegionName: "isolated core test", Nodes: []*tailcfg.DERPNode{{
			Name: "900a", RegionID: 900, HostName: "127.0.0.1", IPv4: "127.0.0.1", IPv6: "none",
			DERPPort: 18081, STUNPort: -1, CertName: "sha256-raw:" + hex.EncodeToString(digest[:]),
		}},
	}}}
	policy := filepath.Join(directory, "policy.hujson")
	nameservers := []string{"192.168.90.2:5353"}
	if androidPair {
		// 保持与待诊断租户相同的默认放行和公网 DNS，不能用假域名响应代替公网验收。
		policy = ""
		nameservers = []string{"114.114.114.114", "1.1.1.1"}
	} else if err := os.WriteFile(policy, fixturePolicy(false), 0o600); err != nil {
		return err
	}
	server, err := control.New(control.Config{ServerURL: "http://127.0.0.1:18080", StateDir: filepath.Join(directory, "server"), Domain: "core.test", Nameservers: nameservers, DERPMap: derpMap, PolicyPath: policy, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		return err
	}
	defer server.Close()
	if err := server.SetAddressPrefix(netip.MustParsePrefix("100.80.0.0/24")); err != nil {
		return err
	}
	secret, err := state.NewPreAuthKeySecret()
	if err != nil {
		return err
	}
	credential := state.PreAuthKey{Key: secret, UserID: state.DefaultUserID, Reusable: true, Expiry: time.Now().Add(time.Hour)}
	if err := server.Store().CreatePreAuthKey(&credential); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(directory, "auth-key"), []byte(secret), 0o600); err != nil {
		return err
	}
	second := identity.User{LoginName: "second-account", Role: identity.RoleMember}
	if err := server.Identity().CreateUser(&second); err != nil {
		return err
	}
	secondSecret, err := state.NewPreAuthKeySecret()
	if err != nil {
		return err
	}
	secondKey := state.PreAuthKey{Key: secondSecret, UserID: second.ID, Reusable: true, Expiry: time.Now().Add(time.Hour)}
	if err := server.Store().CreatePreAuthKey(&secondKey); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(directory, "second-auth-key"), []byte(secondSecret), 0o600); err != nil {
		return err
	}
	_, token, err := server.Identity().CreateAPIKey(identity.NewAPIKeyOptions{Name: "isolated fixture", UserID: state.DefaultUserID, Scopes: []string{identity.ScopeRead, identity.ScopeWrite}, TTL: time.Hour})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/_test/node", func(writer http.ResponseWriter, request *http.Request) {
		for _, node := range server.Store().ListNodes() {
			if node.Hostname == request.URL.Query().Get("host") {
				json.NewEncoder(writer).Encode(map[string]string{"ipv4": node.IPv4.String(), "ipv6": node.IPv6.String(), "id": node.StableID, "user": fmt.Sprint(node.UserID)})
				return
			}
		}
		http.NotFound(writer, request)
	})
	mux.HandleFunc("/_test/approve", func(writer http.ResponseWriter, request *http.Request) {
		host := request.URL.Query().Get("host")
		if host == "" {
			host = "rust-router"
		}
		for _, node := range server.Store().ListNodes() {
			if node.Hostname != host {
				continue
			}
			body, _ := json.Marshal(map[string][]string{"approve": {"192.168.90.0/24"}})
			if host == "android-integration" {
				operation := "approve"
				if request.URL.Query().Get("revoke") == "1" {
					operation = "unapprove"
				}
				body, _ = json.Marshal(map[string][]string{operation: {"10.0.2.0/24", "fec0::/64"}})
			}
			action := httptest.NewRequest(http.MethodPost, "/api/v1/machines/"+node.StableID+"/routes", strings.NewReader(string(body)))
			action.Header.Set("Authorization", "Bearer "+token)
			action.Header.Set("Content-Type", "application/json")
			server.Handler().ServeHTTP(writer, action)
			return
		}
		http.NotFound(writer, request)
	})
	mux.Handle("/", server.Handler())
	mux.HandleFunc("/_test/exit", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		host := request.URL.Query().Get("host")
		if host == "" {
			host = "official-exit"
		}
		for _, node := range server.Store().ListNodes() {
			if node.Hostname != host {
				continue
			}
			body, _ := json.Marshal(map[string][]string{"approve": {"0.0.0.0/0", "::/0"}})
			if request.URL.Query().Get("revoke") == "1" {
				body, _ = json.Marshal(map[string][]string{"unapprove": {"0.0.0.0/0", "::/0"}})
			}
			action := httptest.NewRequest(http.MethodPost, "/api/v1/machines/"+node.StableID+"/routes", strings.NewReader(string(body)))
			action.Header.Set("Authorization", "Bearer "+token)
			action.Header.Set("Content-Type", "application/json")
			server.Handler().ServeHTTP(writer, action)
			return
		}
		http.NotFound(writer, request)
	})
	mux.HandleFunc("/_test/phone-policy", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := os.WriteFile(policy, fixturePolicy(request.URL.Query().Get("deny") == "1"), 0o600); err != nil {
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		writer.WriteHeader(http.StatusNoContent)
	})
	if os.Getenv("XUNARA_TEST_SHARING") == "true" {
		cleanup, err := startSharingFixture(ctx, directory, server, derpMap, mux)
		if err != nil {
			return err
		}
		defer cleanup()
	}
	server.Start(ctx)
	httpServer := &http.Server{Addr: "0.0.0.0:8080", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); httpServer.Close() }()
	return httpServer.ListenAndServe()
}

func official(ctx context.Context, directory, target string) error {
	secret, err := os.ReadFile(filepath.Join(directory, "auth-key"))
	if err != nil {
		return err
	}
	server := &tsnet.Server{Dir: filepath.Join(directory, "official"), Hostname: "official-peer", ControlURL: "http://127.0.0.1:18080", AuthKey: strings.TrimSpace(string(secret)), Logf: logger.Discard, UserLogf: logger.Discard}
	defer server.Close()
	up, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	if _, err := server.Up(up); err != nil {
		return err
	}
	listener, err := server.Listen("tcp", ":8088")
	if err != nil {
		return err
	}
	defer listener.Close()
	go http.Serve(listener, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { fmt.Fprintln(writer, "official-core-ok") }))
	if target != "" {
		client := server.HTTPClient()
		client.Timeout = 5 * time.Second
		var success bool
		for attempt := 0; attempt < 30; attempt++ {
			request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+target+":8088", nil)
			response, err := client.Do(request)
			if err == nil {
				content, _ := io.ReadAll(io.LimitReader(response.Body, 100))
				response.Body.Close()
				if string(content) == "xunara-core-ok\n" {
					success = true
					break
				}
			}
			time.Sleep(time.Second)
		}
		if !success {
			return errors.New("official client could not reach Rust node")
		}
		if err := os.WriteFile(filepath.Join(directory, "official-ok"), []byte("pass\n"), 0o600); err != nil {
			return err
		}
	}
	<-ctx.Done()
	return nil
}
