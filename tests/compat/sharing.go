package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/xunara-net/xunara-server/control"
	"github.com/xunara-net/xunara-server/identity"
	"github.com/xunara-net/xunara-server/state"
	"tailscale.com/tailcfg"
)

// 三个真实控制面故意使用相同地址池；共享必须经过别名转换，不能靠地址恰好不重叠蒙混通过。
// 测试管理凭据仅驻留内存，手机只获得属于自己的临时设备接入密钥。
func startSharingFixture(parent context.Context, directory string, owner *control.Server, derpMap *tailcfg.DERPMap, mux *http.ServeMux) (func(), error) {
	ctx, cancel := context.WithCancel(parent)
	var resources []io.Closer
	cleanup := func() {
		cancel()
		for index := len(resources) - 1; index >= 0; index-- {
			resources[index].Close()
		}
	}
	ready := false
	defer func() {
		if !ready {
			cleanup()
		}
	}()
	servers := make(map[string]*control.Server)
	for index, name := range []string{"guest", "third"} {
		server, err := control.New(control.Config{ServerURL: fmt.Sprintf("http://127.0.0.1:%d", 18082+index), StateDir: filepath.Join(directory, "share-"+name), Domain: name + ".test", DERPMap: derpMap, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
		if err != nil {
			return nil, err
		}
		resources = append(resources, server)
		if err := server.SetAddressPrefix(netip.MustParsePrefix("100.80.0.0/24")); err != nil {
			return nil, err
		}
		servers[name] = server
	}
	registry, err := control.OpenShareRegistry(ctx, control.ShareRegistryConfig{Path: filepath.Join(directory, "shares.db")})
	if err != nil {
		return nil, err
	}
	resources = append(resources, registry)
	_, err = control.NewRouter(control.RouterConfig{Orgs: []control.OrgSite{
		{ID: "owner", Name: "Owner fixture", Domains: []string{"owner.fixture.invalid"}, Server: owner},
		{ID: "guest", Name: "Guest fixture", Domains: []string{"guest.fixture.invalid"}, Server: servers["guest"]},
		{ID: "third", Name: "Third fixture", Domains: []string{"third.fixture.invalid"}, Server: servers["third"]},
	}, Shares: registry, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		return nil, err
	}
	const provider, subject = "oidc:sharing-fixture", "recipient-subject"
	credentials := make(map[string]string)
	for _, account := range []struct{ tenant, name, subject string }{{"guest", "recipient", subject}, {"guest", "outsider", "different-subject"}, {"third", "same-subject", subject}} {
		server := servers[account.tenant]
		user := identity.User{LoginName: account.name, Role: identity.RoleMember}
		if err := server.Identity().CreateUser(&user); err != nil {
			return nil, err
		}
		if err := server.Identity().LinkExternalIdentity(&identity.ExternalIdentity{ProviderID: provider, Subject: account.subject, UserID: user.ID}); err != nil {
			return nil, err
		}
		_, token, err := server.Identity().CreateAPIKey(identity.NewAPIKeyOptions{Name: "isolated share fixture", UserID: user.ID, Scopes: []string{identity.ScopeRead}, TTL: time.Hour})
		if err != nil {
			return nil, err
		}
		credentials[account.name] = token
		secret, err := state.NewPreAuthKeySecret()
		if err != nil {
			return nil, err
		}
		credential := state.PreAuthKey{Key: secret, UserID: user.ID, Reusable: true, Expiry: time.Now().Add(time.Hour)}
		if err := server.Store().CreatePreAuthKey(&credential); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(directory, "share-"+account.name+"-auth-key"), []byte(secret), 0o600); err != nil {
			return nil, err
		}
	}
	_, ownerToken, err := owner.Identity().CreateAPIKey(identity.NewAPIKeyOptions{Name: "isolated share owner", UserID: state.DefaultUserID, Scopes: []string{identity.ScopeRead, identity.ScopeWrite}, TTL: time.Hour})
	if err != nil {
		return nil, err
	}
	call := func(ctx context.Context, server *control.Server, token, method, path string, body any) *httptest.ResponseRecorder {
		encoded, _ := json.Marshal(body)
		request := httptest.NewRequest(method, path, bytes.NewReader(encoded)).WithContext(ctx)
		request.Header.Set("Authorization", "Bearer "+token)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		return response
	}
	var lock sync.Mutex
	var shareID string
	mux.HandleFunc("/_test/share", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost {
			writer.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		lock.Lock()
		defer lock.Unlock()
		var response *httptest.ResponseRecorder
		switch request.URL.Query().Get("step") {
		case "create":
			if shareID != "" {
				writer.WriteHeader(http.StatusConflict)
				return
			}
			for _, node := range owner.Store().ListNodes() {
				if node.Hostname == "rust-router" {
					response = call(request.Context(), owner, ownerToken, http.MethodPost, "/api/v2/shares", map[string]string{"node": node.StableID, "targetOrganization": "guest", "provider": provider, "subject": subject})
					var created struct{ ID string }
					if response.Code == http.StatusCreated && json.Unmarshal(response.Body.Bytes(), &created) == nil {
						shareID = created.ID
					}
					break
				}
			}
		case "accept":
			if shareID == "" {
				break
			}
			path := "/api/v2/shares/" + shareID + "/accept"
			wrongUser := call(request.Context(), servers["guest"], credentials["outsider"], http.MethodPost, path, nil)
			wrongTenant := call(request.Context(), servers["third"], credentials["same-subject"], http.MethodPost, path, nil)
			if wrongUser.Code != http.StatusNotFound || wrongTenant.Code != http.StatusNotFound {
				http.Error(writer, "sharing identity boundary failed", http.StatusInternalServerError)
				return
			}
			response = call(request.Context(), servers["guest"], credentials["recipient"], http.MethodPost, path, nil)
		case "revoke":
			if shareID != "" {
				response = call(request.Context(), owner, ownerToken, http.MethodDelete, "/api/v2/shares/"+shareID, nil)
			}
		}
		if response == nil {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(response.Code)
		writer.Write(response.Body.Bytes())
	})
	// 只在隔离命名空间暴露每个租户独立端口；普通生产站点仍走 Router 的 Host 边界。
	for index, name := range []string{"guest", "third"} {
		server := servers[name]
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", 8082+index))
		if err != nil {
			return nil, err
		}
		httpServer := &http.Server{Handler: server.Handler(), ReadHeaderTimeout: 5 * time.Second}
		resources = append(resources, httpServer)
		server.Start(ctx)
		go httpServer.Serve(listener)
	}
	ready = true
	return cleanup, nil
}
