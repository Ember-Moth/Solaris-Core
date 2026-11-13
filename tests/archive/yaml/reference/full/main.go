// Fixed full loader oracle. Read-only reflection projects constructor results.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	I "github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	_ "github.com/metacubex/mihomo/hub/executor"
	L "github.com/metacubex/mihomo/listener"
	LI "github.com/metacubex/mihomo/listener/inbound"
	U "github.com/metacubex/mihomo/transport/anytls/util"
	"github.com/metacubex/mihomo/transport/socks5"
	T "github.com/metacubex/mihomo/tunnel"
	"github.com/sirupsen/logrus"
	"go.yaml.in/yaml/v3"
)

type object = map[string]any

var rawProjection = object{"listeners": []object{}, "rules": []object{}, "vless": []object{}}

func deref(v reflect.Value) reflect.Value {
	for v.IsValid() && (v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface) {
		v = v.Elem()
	}
	return v
}
func field(v reflect.Value, names ...string) reflect.Value {
	for _, name := range names {
		v = deref(v)
		if !v.IsValid() || v.Kind() != reflect.Struct {
			panic("projection field: " + name)
		}
		v = v.FieldByName(name)
		if !v.IsValid() {
			panic("projection missing: " + name)
		}
	}
	return v
}
func text(v reflect.Value, n string) string   { return field(v, n).String() }
func integer(v reflect.Value, n string) int64 { return field(v, n).Int() }
func boolean(v reflect.Value, n string) bool  { return field(v, n).Bool() }
func emit(v any) {
	if err := json.NewEncoder(os.Stdout).Encode(v); err != nil {
		panic(err)
	}
}
func allowed(k, list string) bool { return strings.Contains(" "+list+" ", " "+k+" ") }

// This is a resource guard, not a replacement parser. RawConfig is never
// modified. Providers, geo/rule resources, plugins, certificates, DNS, NTP and
// TUN are excluded before calling the original ParseRawConfig.
func guard(data []byte, raw *config.RawConfig) error {
	var root map[string]any
	if err := yaml.Unmarshal(data, &root); err != nil {
		return err
	}
	for k := range root {
		if !allowed(k, "mode proxies proxy-groups rules port socks-port mixed-port allow-lan bind-address authentication listeners unknown-option unified-delay") && !strings.HasPrefix(k, "x-") {
			return fmt.Errorf("unsafe top field %s", k)
		}
	}
	if len(raw.ProxyProvider) != 0 || len(raw.RuleProvider) != 0 || len(raw.SubRules) != 0 || raw.DNS.Enable || raw.Tun.Enable || raw.NTP.Enable {
		return fmt.Errorf("unsafe external resource")
	}
	for _, p := range raw.Proxy {
		kind, _ := p["type"].(string)
		if !allowed(kind, "direct reject socks5 ss vless anytls") {
			return fmt.Errorf("unsafe proxy type %s", kind)
		}
		for k := range p {
			if !allowed(k, "name type udp server port network username password cipher udp-over-tcp udp-over-tcp-version uuid flow encryption tls servername packet-encoding sni idle-session-timeout idle-session-check-interval min-idle-session extra-field") {
				return fmt.Errorf("unsafe proxy field %s", k)
			}
		}
	}
	for _, g := range raw.ProxyGroup {
		if kind, _ := g["type"].(string); kind != "select" {
			return fmt.Errorf("unsafe active group")
		}
		for k := range g {
			if !allowed(k, "name type proxies extra-field") {
				return fmt.Errorf("unsafe group field %s", k)
			}
		}
	}
	for _, l := range raw.Listeners {
		if kind, _ := l["type"].(string); !allowed(kind, "http socks socks5 mixed") {
			return fmt.Errorf("unsafe listener type")
		}
		for k := range l {
			if !allowed(k, "name type listen port udp users extra-field") {
				return fmt.Errorf("unsafe listener field %s", k)
			}
		}
	}
	for _, r := range raw.Rule {
		kind := strings.TrimSpace(strings.Split(r, ",")[0])
		if !allowed(kind, "DOMAIN DOMAIN-SUFFIX DOMAIN-KEYWORD IP-CIDR IP-CIDR6 SRC-IP-CIDR SRC-PORT DST-PORT NETWORK MATCH BAD-RULE") {
			return fmt.Errorf("unsafe resource rule %s", kind)
		}
	}
	return nil
}
func node(p C.Proxy) object {
	a := p.Adapter()
	v := reflect.ValueOf(a)
	if embedded := deref(v).FieldByName("ProxyAdapter"); embedded.IsValid() {
		v = deref(embedded)
	}
	kind := strings.ToLower(a.Type().String())
	if kind == "shadowsocks" {
		kind = "ss"
	}
	f := object{}
	out := object{"name": p.Name(), "type": kind, "udp": p.SupportUDP(), "fields": f}
	if kind == "direct" || kind == "reject" {
		return out
	}
	o := field(v, "option")
	f["server"] = text(o, "Server")
	f["port"] = integer(o, "Port")
	switch kind {
	case "socks5":
		f["username"] = text(v, "user")
		f["password"] = text(v, "pass")
	case "ss":
		f["cipher"] = text(o, "Cipher")
		f["password"] = text(o, "Password")
		f["udp-over-tcp"] = boolean(o, "UDPOverTCP")
		if boolean(o, "UDPOverTCP") {
			f["udp-over-tcp-version"] = integer(o, "UDPOverTCPVersion")
		}
	case "vless":
		rawProjection["vless"] = append(rawProjection["vless"].([]object), object{"name": p.Name(), "uuid": text(o, "UUID"), "flow": text(o, "Flow")})
		var uuid strings.Builder
		bytes := field(v, "client", "uuid")
		for i := 0; i < bytes.Len(); i++ {
			fmt.Fprintf(&uuid, "%02x", bytes.Index(i).Uint())
		}
		f["uuid"] = uuid.String()
		f["flow"] = text(o, "Flow")
		f["tls"] = boolean(o, "TLS")
		f["servername"] = text(o, "ServerName")
		encryption := text(o, "Encryption")
		if encryption == "none" {
			encryption = ""
		}
		f["encryption"] = encryption
		if boolean(o, "XUDP") {
			f["packet-encoding"] = "xudp"
		} else if boolean(o, "PacketAddr") {
			f["packet-encoding"] = "packetaddr"
		} else {
			f["packet-encoding"] = "native"
		}
	case "anytls":
		f["password"] = text(o, "Password")
		f["servername"] = text(o, "SNI")
		f["tls"] = true
		c := field(v, "client", "sessionClient")
		f["idle-session-timeout-ms"] = integer(c, "idleSessionTimeout") / int64(time.Millisecond)
		f["min-idle-session"] = integer(c, "minIdleSession")
		interval, ok := U.SolarisReferenceInterval(field(c, "die").Elem().Pointer())
		if !ok {
			panic("missing effective AnyTLS timer observation")
		}
		f["idle-session-check-interval-ms"] = interval.Milliseconds()
	default:
		panic("unexpected node projection " + kind)
	}
	return out
}
func group(p C.Proxy) object {
	var raw object
	b, err := p.Adapter().MarshalJSON()
	if err != nil {
		panic(err)
	}
	if err = json.Unmarshal(b, &raw); err != nil {
		panic(err)
	}
	return object{"name": p.Name(), "members": raw["all"], "selected": raw["now"]}
}
func users(value LI.AuthUsers, fallback []object) []object {
	if value == nil {
		return fallback
	}
	out := []object{}
	for _, v := range value {
		out = append(out, object{"username": v.Username, "password": v.Password})
	}
	return out
}
func listener(name, kind, address string, udp bool, auth []object) object {
	rawProjection["listeners"] = append(rawProjection["listeners"].([]object), object{"name": name, "address": address, "disabled": false})
	// Canonical numeric spelling for the same unspecified-address endpoint.
	// This projection does not modify genAddr/portIsZero or activate a socket.
	if host, port, err := net.SplitHostPort(address); err == nil && host == "" {
		address = net.JoinHostPort("::", port)
	}
	return object{"name": name, "type": kind, "address": address, "udp": udp, "auth": auth}
}
func rule(r C.Rule) object {
	if w, ok := r.(C.RuleWrapper); ok {
		r = w.Unwrap()
	}
	payload := r.Payload()
	if p, e := netip.ParsePrefix(payload); e == nil {
		payload = p.Masked().String()
	}
	noResolve := false
	if f := deref(reflect.ValueOf(r)).FieldByName("noResolveIP"); f.IsValid() {
		noResolve = f.Bool()
	}
	rawProjection["rules"] = append(rawProjection["rules"].([]object), object{"payload": r.Payload(), "no-resolve": noResolve})
	return object{"type": r.RuleType().String(), "value": payload, "target": r.Adapter(), "no-resolve": noResolve}
}
func route(parsed *config.Config, args []string) object {
	if len(args) != 6 {
		panic("route needs six arguments")
	}
	sp, _ := strconv.ParseUint(args[4], 10, 16)
	address := socks5.ParseAddr(net.JoinHostPort(args[1], args[2]))
	if address == nil {
		panic("invalid SOCKS address fixture")
	}
	md := I.SolarisReferenceMetadata(address)
	md.SrcIP = netip.MustParseAddr(args[3])
	md.SrcPort = uint16(sp)
	md.NetWork = C.TCP
	if args[0] == "udp" {
		md.NetWork = C.UDP
	}
	rawProjection["route_metadata"] = object{"input_host": args[1], "effective_host": md.Host, "effective_ip": md.DstIP.String()}
	calls := 0
	attempted := md.DstIP.IsValid()
	helper := C.RuleMatchHelper{ResolveIP: func() {
		if attempted {
			return
		}
		attempted = true
		calls++
		if ip, e := netip.ParseAddr(args[5]); e == nil {
			md.DstIP = ip.Unmap()
		}
	}, CheckPassRule: func(string) bool { return false }}
	T.UpdateRules(parsed.Rules, parsed.SubRules, parsed.RuleProviders)
	T.UpdateProxies(parsed.Proxies, parsed.Providers)
	var p C.Proxy
	var matched C.Rule
	var err error
	if parsed.General.Mode == T.Direct {
		p = parsed.Proxies["DIRECT"]
	} else if parsed.General.Mode == T.Global {
		p = parsed.Proxies["GLOBAL"]
	} else {
		p, matched, err = T.SolarisReferenceMatch(md, helper)
	}
	if err != nil {
		panic(err)
	}
	index := -1
	for i, r := range parsed.Rules {
		if r == matched {
			index = i
		}
	}
	for next := p.Unwrap(md, false); next != nil; next = p.Unwrap(md, false) {
		p = next
	}
	return object{"node": p.Name(), "rule": index, "dns_calls": calls, "udp": p.SupportUDP()}
}
func main() {
	logrus.SetOutput(io.Discard)
	data, err := io.ReadAll(io.LimitReader(os.Stdin, 1048577))
	if err != nil || len(data) > 1048576 {
		panic("input limit")
	}
	temp, err := os.MkdirTemp("", "solaris-mihomo-reference-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(temp)
	C.SetHomeDir(temp)
	raw, err := config.UnmarshalRawConfig(data)
	if err != nil {
		emit(object{"ok": false, "stage": "yaml"})
		return
	}
	if err = guard(data, raw); err != nil {
		emit(object{"ok": false, "stage": "harness-guard", "error": err.Error()})
		return
	}
	parsed, err := config.ParseRawConfig(raw)
	if err != nil {
		emit(object{"ok": false, "stage": "loader"})
		return
	}
	defer func() {
		for _, p := range parsed.Proxies {
			_ = p.Close()
		}
	}()
	nodes := []object{node(parsed.Proxies["DIRECT"]), node(parsed.Proxies["REJECT"])}
	for _, p := range raw.Proxy {
		nodes = append(nodes, node(parsed.Proxies[fmt.Sprint(p["name"])]))
	}
	groups := []object{}
	hasGlobal := false
	for _, g := range raw.ProxyGroup {
		groups = append(groups, group(parsed.Proxies[fmt.Sprint(g["name"])]))
		hasGlobal = hasGlobal || g["name"] == "GLOBAL"
	}
	if !hasGlobal {
		groups = append(groups, group(parsed.Proxies["GLOBAL"]))
	}
	auth := []object{}
	for _, u := range parsed.Users {
		auth = append(auth, object{"username": u.User, "password": u.Pass})
	}
	listeners := []object{}
	g := parsed.General
	for i, p := range []int{g.Port, g.SocksPort, g.MixedPort} {
		address, zero := L.SolarisReferenceAddress(g.BindAddress, p, g.AllowLan)
		if !zero {
			listeners = append(listeners, listener([]string{"http", "socks", "mixed"}[i], []string{"http", "socks", "mixed"}[i], address, i != 0, auth))
		} else {
			rawProjection["listeners"] = append(rawProjection["listeners"].([]object), object{"name": []string{"http", "socks", "mixed"}[i], "address": address, "disabled": true})
		}
	}
	for _, rawListener := range raw.Listeners {
		l := parsed.Listeners[fmt.Sprint(rawListener["name"])]
		base := l.(interface{ RawAddress() string })
		kind := ""
		udp := false
		listAuth := auth
		switch o := l.Config().(type) {
		case *LI.HTTPOption:
			kind = "http"
			listAuth = users(o.Users, auth)
		case *LI.SocksOption:
			kind = "socks"
			udp = o.UDP
			listAuth = users(o.Users, auth)
		case *LI.MixedOption:
			kind = "mixed"
			udp = o.UDP
			listAuth = users(o.Users, auth)
		default:
			panic("listener projection")
		}
		listeners = append(listeners, listener(l.Name(), kind, base.RawAddress(), udp, listAuth))
	}
	rules := []object{}
	for _, r := range parsed.Rules {
		rules = append(rules, rule(r))
	}
	out := object{"ok": true, "mode": g.Mode.String(), "nodes": nodes, "groups": groups, "listeners": listeners, "rules": rules, "representation": rawProjection}
	if len(os.Args) > 1 {
		out["route"] = route(parsed, os.Args[1:])
	}
	emit(out)
	entries, err := os.ReadDir(temp)
	if err != nil || len(entries) != 0 {
		panic("reference created external resource files")
	}
}
