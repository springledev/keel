package proxmox

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// fwServer serves canned bodies by "METHOD path" and records requests.
func fwServer(t *testing.T, routes map[string]string, got *[]string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		key := r.Method + " " + r.URL.Path
		*got = append(*got, key+"?"+r.URL.RawQuery+"|"+string(b))
		body, ok := routes[key]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return &Client{Host: srv.URL, TokenID: "x@pve!y", TokenSecret: "z", HTTPClient: srv.Client()}
}

func TestScopePaths(t *testing.T) {
	tests := []struct {
		name    string
		s       Scope
		parts   []string
		want    string
		wantErr bool
	}{
		{"cluster", ClusterScope(), []string{"rules"}, "/api2/json/cluster/firewall/rules", false},
		{"node", NodeScope("pve1"), []string{"options"}, "/api2/json/nodes/pve1/firewall/options", false},
		{"vm", Scope{Kind: ScopeQEMU, Node: "pve1", VMID: 101}, []string{"rules", "3"}, "/api2/json/nodes/pve1/qemu/101/firewall/rules/3", false},
		{"lxc via guest", GuestScope(Guest{Node: "n", VMID: 100, Type: "lxc"}), nil, "/api2/json/nodes/n/lxc/100/firewall", false},
		{"node traversal", NodeScope("../x"), nil, "", true},
		{"empty node", NodeScope(""), nil, "", true},
		{"low vmid", Scope{Kind: ScopeQEMU, Node: "n", VMID: 5}, nil, "", true},
		{"bad kind", Scope{Kind: "x", Node: "n"}, nil, "", true},
		{"bad part", ClusterScope(), []string{"a/b"}, "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.path(tt.parts...)
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Errorf("path() = %q, %v; want %q (err %v)", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestListNodeGuests(t *testing.T) {
	var reqs []string
	cl := fwServer(t, map[string]string{
		"GET /api2/json/nodes/pve1/qemu": `{"data":[{"vmid":105,"name":"b","status":"running","tags":"app=db"},{"vmid":101,"name":"a","status":"stopped"}]}`,
	}, &reqs)
	g, err := cl.ListNodeGuests(context.Background(), "pve1", ScopeQEMU)
	if err != nil || len(g) != 2 || g[0].VMID != 101 || g[1].Tags != "app=db" {
		t.Fatalf("got %+v, %v", g, err)
	}
	if _, err := cl.ListNodeGuests(context.Background(), "pve1", ScopeNode); err == nil {
		t.Error("bad kind should fail")
	}
	if _, err := cl.ListNodeGuests(context.Background(), "a/b", ScopeLXC); err == nil {
		t.Error("bad node should fail")
	}
}

func TestFirewallOptions(t *testing.T) {
	var reqs []string
	cl := fwServer(t, map[string]string{
		"GET /api2/json/cluster/firewall/options":    `{"data":{"enable":1,"policy_in":"DROP","digest":"abc"}}`,
		"PUT /api2/json/nodes/pve1/firewall/options": `{"data":null}`,
	}, &reqs)
	o, err := cl.FirewallOptions(context.Background(), ClusterScope())
	if err != nil || !o.Enabled() || o.PolicyIn != "DROP" {
		t.Fatalf("got %+v, %v", o, err)
	}
	if (FirewallOptions{}).Enabled() {
		t.Error("zero options should not be enabled")
	}
	if err := cl.SetFirewallOptions(context.Background(), NodeScope("pve1"), url.Values{"enable": {"1"}}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(reqs[len(reqs)-1], "|enable=1") {
		t.Errorf("body = %q", reqs[len(reqs)-1])
	}
	if _, err := cl.FirewallOptions(context.Background(), NodeScope("pve2")); err == nil || !strings.Contains(err.Error(), "node pve2") {
		t.Errorf("err = %v, want scope context", err)
	}
}

func TestFirewallRules(t *testing.T) {
	var reqs []string
	vm := Scope{Kind: ScopeQEMU, Node: "pve1", VMID: 101}
	base := "/api2/json/nodes/pve1/qemu/101/firewall/rules"
	cl := fwServer(t, map[string]string{
		"GET " + base:           `{"data":[{"pos":1,"type":"in","action":"DROP","enable":1},{"pos":0,"type":"in","action":"ACCEPT","enable":1,"proto":"tcp","dport":"22","source":"+trusted","comment":"ssh"}]}`,
		"POST " + base:          `{"data":null}`,
		"DELETE " + base + "/0": `{"data":null}`,
	}, &reqs)
	ctx := context.Background()
	rules, err := cl.FirewallRules(ctx, vm)
	if err != nil || len(rules) != 2 || rules[0].DPort != "22" || rules[1].Action != "DROP" {
		t.Fatalf("got %+v, %v", rules, err)
	}
	if err := cl.AddFirewallRule(ctx, vm, FirewallRule{Type: "in", Action: "ACCEPT", Enable: 1, Proto: "tcp", DPort: "5432"}); err != nil {
		t.Fatal(err)
	}
	form, _ := url.ParseQuery(strings.SplitN(reqs[len(reqs)-1], "|", 2)[1])
	if form.Get("dport") != "5432" || form.Get("enable") != "1" || form.Has("source") {
		t.Errorf("form = %v", form)
	}
	if err := cl.DeleteFirewallRule(ctx, vm, 0, "dg1"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reqs[len(reqs)-1], "?digest=dg1|") {
		t.Errorf("delete request = %q", reqs[len(reqs)-1])
	}
	if err := cl.DeleteFirewallRule(ctx, vm, 9, ""); err == nil || !strings.Contains(err.Error(), "deleting firewall rule 9") {
		t.Errorf("err = %v", err)
	}
}

func TestGroupsIPSetsAliases(t *testing.T) {
	var reqs []string
	cl := fwServer(t, map[string]string{
		"GET /api2/json/cluster/firewall/groups":        `{"data":[{"group":"web"}]}`,
		"GET /api2/json/cluster/firewall/groups/web":    `{"data":[{"pos":0,"type":"in","action":"ACCEPT","enable":1}]}`,
		"GET /api2/json/cluster/firewall/ipset":         `{"data":[{"name":"trusted"}]}`,
		"GET /api2/json/cluster/firewall/ipset/trusted": `{"data":[{"cidr":"10.0.0.0/24"}]}`,
		"GET /api2/json/cluster/firewall/aliases":       `{"data":[{"name":"lan","cidr":"192.168.1.0/24"}]}`,
	}, &reqs)
	ctx := context.Background()
	if g, err := cl.SecurityGroups(ctx); err != nil || len(g) != 1 || g[0].Group != "web" {
		t.Errorf("groups = %+v, %v", g, err)
	}
	if r, err := cl.SecurityGroupRules(ctx, "web"); err != nil || len(r) != 1 {
		t.Errorf("group rules = %+v, %v", r, err)
	}
	if _, err := cl.SecurityGroupRules(ctx, "../x"); err == nil {
		t.Error("bad group name should fail")
	}
	if s, err := cl.IPSets(ctx, ClusterScope()); err != nil || s[0].Name != "trusted" {
		t.Errorf("ipsets = %+v, %v", s, err)
	}
	if e, err := cl.IPSetEntries(ctx, ClusterScope(), "trusted"); err != nil || e[0].CIDR != "10.0.0.0/24" {
		t.Errorf("entries = %+v, %v", e, err)
	}
	if a, err := cl.Aliases(ctx, ClusterScope()); err != nil || a[0].CIDR != "192.168.1.0/24" {
		t.Errorf("aliases = %+v, %v", a, err)
	}
	if _, err := cl.Aliases(ctx, NodeScope("pve1")); err == nil {
		t.Error("missing route should surface an error")
	}
}
