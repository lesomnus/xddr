package xddr_test

// This file collects runnable examples for the most common Sanitize use.
// Each Example is verified by `go test`: its printed output must match the
// trailing `// Output:` comment. They also render on pkg.go.dev.
//
// The recurring idea: a value is just a string, so you call Sanitize once at a
// trust boundary (config load, user input, request parsing) to both validate it
// and put it in the canonical form the rest of the package assumes.

import (
	"errors"
	"fmt"

	"github.com/lesomnus/xddr"
)

// Sanitize normalizes as well as validates: it lowercases the scheme and host,
// decodes percent-encoded unreserved characters (%7E -> ~), and uppercases the
// hex digits of the triplets it keeps (%2f -> %2F).
func ExampleURL_Sanitize() {
	u, err := xddr.URL("HTTP://Example.COM/%7Euser?tag=%2fweb#Frag").Sanitize()
	if err != nil {
		panic(err)
	}
	fmt.Println(u)
	// Output: http://example.com/~user?tag=%2Fweb#Frag
}

// HTTP knows scheme default ports and elides them from the canonical form,
// while Port resolves them back.
func ExampleHTTP_Sanitize() {
	for _, raw := range []xddr.HTTP{
		"HTTP://Example.COM:80/foo?bar=42",
		"https://example.com:443",
		"https://example.com:8443",
	} {
		u, err := raw.Sanitize()
		if err != nil {
			fmt.Printf("%-32s -> error: %v\n", raw, err)
			continue
		}
		fmt.Printf("%-32s -> %s (port %d)\n", raw, u, u.Port())
	}
	// Output:
	// HTTP://Example.COM:80/foo?bar=42 -> http://example.com/foo?bar=42 (port 80)
	// https://example.com:443          -> https://example.com (port 443)
	// https://example.com:8443         -> https://example.com:8443 (port 8443)
}

// Host is the union of IPv4, IPv6, and Domain. IPv6 is returned bracketed, and
// IPv6/domain forms are canonicalized (RFC 5952 shortening, lowercasing).
func ExampleHost_Sanitize() {
	for _, h := range []xddr.Host{
		"127.0.0.1",
		"0:0:0:0:0:0:0:1",
		"Example.COM",
	} {
		w, err := h.Sanitize()
		if err != nil {
			panic(err)
		}
		fmt.Println(w)
	}
	// Output:
	// 127.0.0.1
	// [::1]
	// example.com
}

// IPv6 addresses are shortened per RFC 5952: leading zeros are dropped and the
// longest run of zero groups collapses to "::".
func ExampleIPv6_Sanitize() {
	w, err := xddr.IPv6("2001:0db8:0000:0000:0000:0000:0000:0001").Sanitize()
	if err != nil {
		panic(err)
	}
	fmt.Println(w)
	// Output: 2001:db8::1
}

// Authority normalizes host and port and drops empty userinfo. Ports keep at
// most no leading zeros ("0080" -> "80"), but ":0" is preserved.
func ExampleAuthority_Sanitize() {
	for _, a := range []xddr.Authority{
		"User@Example.COM:0080",
		"@host", // empty userinfo is removed
		":8080", // empty host means "all interfaces" for local use
	} {
		w, err := a.Sanitize()
		if err != nil {
			panic(err)
		}
		fmt.Println(w)
	}
	// Output:
	// User@example.com:80
	// host
	// :8080
}

// Filepath is a URL-style file path whose authority is optional.
// An empty value canonicalizes to the current directory.
func ExampleFilepath_Sanitize() {
	for _, p := range []xddr.Filepath{
		"",
		"file:/absolute/path.txt",
		"file:./relative/path.txt",
		"file:../up.txt",
	} {
		w, err := p.Sanitize()
		if err != nil {
			panic(err)
		}
		fmt.Printf("%-27q -> %s\n", string(p), w)
	}
	// Output:
	// ""                          -> file://.
	// "file:/absolute/path.txt"   -> file:/absolute/path.txt
	// "file:./relative/path.txt"  -> file:./relative/path.txt
	// "file:../up.txt"            -> file:../up.txt
}

// A listen address (the LocalLike family) infers the network and fills in the
// blanks. This is the typical shape of a config field sanitized at load time.
func ExampleHTTPLocal_Sanitize() {
	for _, l := range []xddr.HTTPLocal{
		":8080",            // all interfaces, both stacks
		"0.0.0.0:8080",     // IPv4 wildcard
		"unix:/run/a.sock", // Unix domain socket
	} {
		w, err := l.Sanitize()
		if err != nil {
			panic(err)
		}
		fmt.Printf("%-20s -> %-22s dial: %s\n", l, w, w.AsURL())
	}
	// Output:
	// :8080                -> tcp::8080              dial: http://127.0.0.1:8080
	// 0.0.0.0:8080         -> tcp4:0.0.0.0:8080      dial: http://127.0.0.1:8080
	// unix:/run/a.sock     -> unix:/run/a.sock       dial: unix:///run/a.sock
}

// TCPLocal infers the address family (tcp4/tcp6) from the host it is given and
// brackets IPv6 to disambiguate it from the port separator.
func ExampleTCPLocal_Sanitize() {
	for _, l := range []xddr.TCPLocal{
		":80",
		"0.0.0.0:80",
		"tcp6::80",
	} {
		w, err := l.Sanitize()
		if err != nil {
			panic(err)
		}
		fmt.Println(w)
	}
	// Output:
	// tcp::80
	// tcp4:0.0.0.0:80
	// tcp6:[::]:80
}

// GRPC follows the gRPC name-resolution syntax scheme://[authority]/endpoint;
// a bare host:port gets the default "dns" resolver.
func ExampleGRPC_Sanitize() {
	for _, g := range []xddr.GRPC{
		"grpc.io:50051",
		"[::1]:50051",
		"unix:///run/grpc.sock",
	} {
		w, err := g.Sanitize()
		if err != nil {
			panic(err)
		}
		fmt.Printf("%-22s -> %-26s local: %s\n", g, w, w.Local())
	}
	// Output:
	// grpc.io:50051          -> dns:///grpc.io:50051       local: tcp:grpc.io:50051
	// [::1]:50051            -> dns:///[::1]:50051         local: tcp6:[::1]:50051
	// unix:///run/grpc.sock  -> unix:///run/grpc.sock      local: unix:/run/grpc.sock
}

// ICE covers STUN/TURN URIs (RFC 7064/7065) with default-port elision and
// transport validation.
func ExampleICE_Sanitize() {
	for _, u := range []xddr.ICE{
		"stun://example.com:3478",
		"turns:example.com:443?transport=tcp",
	} {
		w, err := u.Sanitize()
		if err != nil {
			panic(err)
		}
		fmt.Println(w)
	}
	// Output:
	// stun:example.com
	// turns:example.com:443?transport=tcp
}

// Sanitize is where you validate untrusted input. Errors carry the byte
// position of the offending character via *xddr.ErrorWithPos.
func ExampleURL_Sanitize_errorPosition() {
	_, err := xddr.URL("http://exa mple.com").Sanitize()
	fmt.Println(err)

	var e *xddr.ErrorWithPos
	if errors.As(err, &e) {
		fmt.Println("pos:", e.Pos())
	}
	// Output:
	// [10]: invalid host: [3]: invalid character ' '
	// pos: 10
}

// Example_configBoundary shows the intended pattern: keep addresses as plain
// strings in a config struct, then Sanitize once at the trust boundary before
// the rest of the program relies on their canonical form.
func Example_configBoundary() {
	type Config struct {
		Listen xddr.HTTPLocal
	}

	load := func(conf Config) error {
		addr, err := conf.Listen.Sanitize()
		if err != nil {
			return fmt.Errorf("invalid listen address: %w", err)
		}
		fmt.Printf("listen %s, clients dial %s\n", addr, addr.AsURL())
		return nil
	}

	if err := load(Config{Listen: "0.0.0.0:8080"}); err != nil {
		fmt.Println(err)
	}
	if err := load(Config{Listen: "0.0.0.0:70000"}); err != nil {
		fmt.Println(err)
	}
	// Output:
	// listen tcp4:0.0.0.0:8080, clients dial http://127.0.0.1:8080
	// invalid listen address: [8]: port number out of range
}
