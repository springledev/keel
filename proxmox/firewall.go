package proxmox

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
)

// ScopeKind says which level of the Proxmox firewall hierarchy a
// Scope addresses.
type ScopeKind string

// The levels of the Proxmox firewall hierarchy.
const (
	// ScopeCluster is the datacenter-wide firewall (/cluster/firewall).
	ScopeCluster ScopeKind = "cluster"
	// ScopeNode is one node's host firewall.
	ScopeNode ScopeKind = "node"
	// ScopeQEMU is one virtual machine's firewall.
	ScopeQEMU ScopeKind = "qemu"
	// ScopeLXC is one container's firewall.
	ScopeLXC ScopeKind = "lxc"
)

// Scope addresses one firewall: the datacenter, a node, a VM or a
// container.
type Scope struct {
	Kind ScopeKind `json:"kind"`
	// Node is required for every kind except ScopeCluster.
	Node string `json:"node,omitempty"`
	// VMID is required for ScopeQEMU and ScopeLXC.
	VMID int `json:"vmid,omitempty"`
}

// ClusterScope returns the datacenter-wide firewall scope.
func ClusterScope() Scope { return Scope{Kind: ScopeCluster} }

// NodeScope returns the firewall scope of one node's host.
func NodeScope(node string) Scope { return Scope{Kind: ScopeNode, Node: node} }

// GuestScope returns the firewall scope of g.
func GuestScope(g Guest) Scope {
	k := ScopeQEMU
	if g.IsLXC() {
		k = ScopeLXC
	}
	return Scope{Kind: k, Node: g.Node, VMID: g.VMID}
}

// pathSegment limits names that are interpolated into API paths, so a
// hostile or mistyped name can never change which endpoint is called.
var pathSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// base returns the scope's firewall API path prefix.
func (s Scope) base() (string, error) {
	if s.Kind == ScopeCluster {
		return "/api2/json/cluster/firewall", nil
	}
	if !pathSegment.MatchString(s.Node) {
		return "", fmt.Errorf("invalid Proxmox node name %q", s.Node)
	}
	switch s.Kind {
	case ScopeNode:
		return "/api2/json/nodes/" + s.Node + "/firewall", nil
	case ScopeQEMU, ScopeLXC:
		if s.VMID < 100 {
			return "", fmt.Errorf("invalid VMID %d for %s on node %s", s.VMID, s.Kind, s.Node)
		}
		return "/api2/json/nodes/" + s.Node + "/" + string(s.Kind) + "/" + strconv.Itoa(s.VMID) + "/firewall", nil
	}
	return "", fmt.Errorf("unknown firewall scope kind %q", s.Kind)
}

// path joins the scope's base with a sub-path made of validated names.
func (s Scope) path(parts ...string) (string, error) {
	b, err := s.base()
	if err != nil {
		return "", err
	}
	for _, p := range parts {
		if !pathSegment.MatchString(p) {
			return "", fmt.Errorf("invalid Proxmox name %q", p)
		}
		b += "/" + p
	}
	return b, nil
}

// NodeGuest is one VM or container as listed by a node's
// /qemu or /lxc endpoint.
type NodeGuest struct {
	VMID     int    `json:"vmid"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Tags     string `json:"tags"`
	Template int    `json:"template"`
}

// ListNodeGuests lists the VMs (kind ScopeQEMU) or containers (kind
// ScopeLXC) on one node, sorted by VMID.
func (cl *Client) ListNodeGuests(ctx context.Context, node string, kind ScopeKind) ([]NodeGuest, error) {
	if kind != ScopeQEMU && kind != ScopeLXC {
		return nil, fmt.Errorf("listing guests on %s: kind must be qemu or lxc, got %q", node, kind)
	}
	if !pathSegment.MatchString(node) {
		return nil, fmt.Errorf("invalid Proxmox node name %q", node)
	}
	var out []NodeGuest
	if err := cl.do(ctx, http.MethodGet, "/api2/json/nodes/"+node+"/"+string(kind), nil, &out); err != nil {
		return nil, fmt.Errorf("listing %s guests on node %s: %w", kind, node, err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].VMID < out[j].VMID })
	return out, nil
}

// FirewallOptions is a firewall's options. Fields are pointers so an
// update only sends what was set; Proxmox returns 0/1 for booleans.
type FirewallOptions struct {
	Enable    *int   `json:"enable,omitempty"`
	PolicyIn  string `json:"policy_in,omitempty"`
	PolicyOut string `json:"policy_out,omitempty"`
	// Digest is the options' version token for optimistic concurrency.
	Digest string `json:"digest,omitempty"`
}

// Enabled reports whether the firewall is switched on.
func (o FirewallOptions) Enabled() bool { return o.Enable != nil && *o.Enable == 1 }

// FirewallOptions reads the firewall options at scope s.
func (cl *Client) FirewallOptions(ctx context.Context, s Scope) (FirewallOptions, error) {
	p, err := s.path("options")
	if err != nil {
		return FirewallOptions{}, err
	}
	var o FirewallOptions
	if err := cl.do(ctx, http.MethodGet, p, nil, &o); err != nil {
		return FirewallOptions{}, fmt.Errorf("reading firewall options (%s): %w", s.label(), err)
	}
	return o, nil
}

// SetFirewallOptions updates the options at scope s from form (for
// example "enable" = "1"). Enabling a firewall is a lockout hazard:
// callers must gate it behind their safety guard.
func (cl *Client) SetFirewallOptions(ctx context.Context, s Scope, form url.Values) error {
	p, err := s.path("options")
	if err != nil {
		return err
	}
	if err := cl.do(ctx, http.MethodPut, p, form, nil); err != nil {
		return fmt.Errorf("updating firewall options (%s): %w", s.label(), err)
	}
	return nil
}

// FirewallRule is one Proxmox firewall rule.
type FirewallRule struct {
	// Pos is the rule's zero-based position in its list.
	Pos int `json:"pos"`
	// Type is "in", "out" or "group" (a security-group reference).
	Type string `json:"type"`
	// Action is ACCEPT, DROP, REJECT, or a security group's name for
	// Type "group".
	Action  string `json:"action"`
	Enable  int    `json:"enable"`
	Source  string `json:"source,omitempty"`
	Dest    string `json:"dest,omitempty"`
	Proto   string `json:"proto,omitempty"`
	DPort   string `json:"dport,omitempty"`
	SPort   string `json:"sport,omitempty"`
	Iface   string `json:"iface,omitempty"`
	Macro   string `json:"macro,omitempty"`
	Log     string `json:"log,omitempty"`
	Comment string `json:"comment,omitempty"`
	Digest  string `json:"digest,omitempty"`
}

// Form encodes r as the request body for creating or updating a rule.
// Pos and Digest are not included.
func (r FirewallRule) Form() url.Values {
	f := url.Values{}
	f.Set("type", r.Type)
	f.Set("action", r.Action)
	f.Set("enable", strconv.Itoa(r.Enable))
	for k, v := range map[string]string{
		"source": r.Source, "dest": r.Dest, "proto": r.Proto, "dport": r.DPort,
		"sport": r.SPort, "iface": r.Iface, "macro": r.Macro, "log": r.Log, "comment": r.Comment,
	} {
		if v != "" {
			f.Set(k, v)
		}
	}
	return f
}

// FirewallRules lists the rules at scope s in evaluation order.
func (cl *Client) FirewallRules(ctx context.Context, s Scope) ([]FirewallRule, error) {
	p, err := s.path("rules")
	if err != nil {
		return nil, err
	}
	var out []FirewallRule
	if err := cl.do(ctx, http.MethodGet, p, nil, &out); err != nil {
		return nil, fmt.Errorf("listing firewall rules (%s): %w", s.label(), err)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Pos < out[j].Pos })
	return out, nil
}

// AddFirewallRule appends rule at scope s. It is a building block for
// a ChangeSet, never a public one-rule-at-a-time path.
func (cl *Client) AddFirewallRule(ctx context.Context, s Scope, rule FirewallRule) error {
	p, err := s.path("rules")
	if err != nil {
		return err
	}
	if err := cl.do(ctx, http.MethodPost, p, rule.Form(), nil); err != nil {
		return fmt.Errorf("adding firewall rule (%s): %w", s.label(), err)
	}
	return nil
}

// DeleteFirewallRule removes the rule at pos. digest, when non-empty,
// makes Proxmox refuse the delete if the list changed since it was read.
func (cl *Client) DeleteFirewallRule(ctx context.Context, s Scope, pos int, digest string) error {
	p, err := s.path("rules", strconv.Itoa(pos))
	if err != nil {
		return err
	}
	if digest != "" {
		p += "?digest=" + url.QueryEscape(digest)
	}
	if err := cl.do(ctx, http.MethodDelete, p, nil, nil); err != nil {
		return fmt.Errorf("deleting firewall rule %d (%s): %w", pos, s.label(), err)
	}
	return nil
}

// SecurityGroup is a named, reusable rule list defined at the cluster.
type SecurityGroup struct {
	Group   string `json:"group"`
	Comment string `json:"comment,omitempty"`
	Digest  string `json:"digest,omitempty"`
}

// SecurityGroups lists the cluster's security groups.
func (cl *Client) SecurityGroups(ctx context.Context) ([]SecurityGroup, error) {
	var out []SecurityGroup
	if err := cl.do(ctx, http.MethodGet, "/api2/json/cluster/firewall/groups", nil, &out); err != nil {
		return nil, fmt.Errorf("listing security groups: %w", err)
	}
	return out, nil
}

// SecurityGroupRules lists the rules inside one security group.
func (cl *Client) SecurityGroupRules(ctx context.Context, group string) ([]FirewallRule, error) {
	if !pathSegment.MatchString(group) {
		return nil, fmt.Errorf("invalid security group name %q", group)
	}
	var out []FirewallRule
	if err := cl.do(ctx, http.MethodGet, "/api2/json/cluster/firewall/groups/"+group, nil, &out); err != nil {
		return nil, fmt.Errorf("listing rules of security group %s: %w", group, err)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Pos < out[j].Pos })
	return out, nil
}

// IPSet is a named set of addresses usable in rules.
type IPSet struct {
	Name    string `json:"name"`
	Comment string `json:"comment,omitempty"`
}

// IPSets lists the IP sets defined at scope s (cluster or guest).
func (cl *Client) IPSets(ctx context.Context, s Scope) ([]IPSet, error) {
	p, err := s.path("ipset")
	if err != nil {
		return nil, err
	}
	var out []IPSet
	if err := cl.do(ctx, http.MethodGet, p, nil, &out); err != nil {
		return nil, fmt.Errorf("listing IP sets (%s): %w", s.label(), err)
	}
	return out, nil
}

// IPSetEntry is one address or network inside an IP set.
type IPSetEntry struct {
	CIDR    string `json:"cidr"`
	NoMatch int    `json:"nomatch,omitempty"`
	Comment string `json:"comment,omitempty"`
}

// IPSetEntries lists the entries of one IP set.
func (cl *Client) IPSetEntries(ctx context.Context, s Scope, name string) ([]IPSetEntry, error) {
	p, err := s.path("ipset", name)
	if err != nil {
		return nil, err
	}
	var out []IPSetEntry
	if err := cl.do(ctx, http.MethodGet, p, nil, &out); err != nil {
		return nil, fmt.Errorf("listing IP set %s (%s): %w", name, s.label(), err)
	}
	return out, nil
}

// Alias is a named address or network usable in rules.
type Alias struct {
	Name    string `json:"name"`
	CIDR    string `json:"cidr"`
	Comment string `json:"comment,omitempty"`
}

// Aliases lists the aliases defined at scope s (cluster or guest).
func (cl *Client) Aliases(ctx context.Context, s Scope) ([]Alias, error) {
	p, err := s.path("aliases")
	if err != nil {
		return nil, err
	}
	var out []Alias
	if err := cl.do(ctx, http.MethodGet, p, nil, &out); err != nil {
		return nil, fmt.Errorf("listing aliases (%s): %w", s.label(), err)
	}
	return out, nil
}

// label names the scope for error messages.
func (s Scope) label() string {
	switch s.Kind {
	case ScopeCluster:
		return "datacenter"
	case ScopeNode:
		return "node " + s.Node
	}
	return fmt.Sprintf("%s %d on %s", s.Kind, s.VMID, s.Node)
}
