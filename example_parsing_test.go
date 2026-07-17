package xddr_test

// Examples for a common source of confusion: pulling host/port out of a value
// while moving between the URL, HTTP, and GRPC forms.
//
// The single rule that resolves the confusion:
//
//   - Generic helpers (SchemeOf, AuthorityOf, HostOf, PortOf) read the PLAIN
//     URL grammar. They do not resolve scheme default ports and do not know
//     that a gRPC target keeps its endpoint in the path.
//   - Each concrete type's own methods (HTTP.Port, GRPC.Host, ...) apply the
//     protocol semantics and shadow the generic behavior.
//
// When both exist, prefer the concrete method.

import (
	"fmt"

	"github.com/lesomnus/xddr"
)

// HTTP.Port resolves the scheme default, but the generic PortOf does not.
// Because Sanitize ELIDES the default port, it is not even written in the
// value, so PortOf reports "absent" (-1) while Port reports 80/443.
func ExampleHTTP_Port() {
	u, _ := xddr.HTTP("http://foo:80/x?q=1").Sanitize()

	fmt.Printf("sanitized:    %s\n", u)              // default port dropped
	fmt.Printf("PortOf:       %d\n", xddr.PortOf(u)) // as written: absent
	fmt.Printf("HTTP.Port():  %d\n", u.Port())       // scheme default

	s, _ := xddr.HTTP("https://foo").Sanitize()
	fmt.Printf("https Port(): %d\n", s.Port())
	// Output:
	// sanitized:    http://foo/x?q=1
	// PortOf:       -1
	// HTTP.Port():  80
	// https Port(): 443
}

// A gRPC target is scheme://[authority]/endpoint: the endpoint you actually
// dial lives in the URL PATH, and the authority names the RESOLVER. So the
// generic helpers, which read the plain URL grammar, look at the wrong place —
// here HostOf returns the DNS resolver, not the server.
func ExampleGRPC_Endpoint() {
	g, _ := xddr.GRPC("dns://8.8.8.8:53/grpc.io:50051").Sanitize()
	fmt.Printf("target:              %s\n", g)

	// Generic helpers see the resolver authority.
	fmt.Printf("AuthorityOf:         %s\n", xddr.AuthorityOf(g))
	fmt.Printf("HostOf (WRONG here): %s\n", xddr.HostOf(g))

	// Concrete methods read the endpoint from the path.
	fmt.Printf("Endpoint:            %s\n", g.Endpoint())
	fmt.Printf("Host:                %s\n", g.Host())
	fmt.Printf("Port:                %d\n", g.Port())
	// Output:
	// target:              dns://8.8.8.8:53/grpc.io:50051
	// AuthorityOf:         8.8.8.8:53
	// HostOf (WRONG here): 8.8.8.8
	// Endpoint:            grpc.io:50051
	// Host:                grpc.io
	// Port:                50051
}

// Authority returns the name-resolver part of the target (the counterpart to
// Host/Endpoint), which is what you want when the endpoint is not enough.
// An empty result means the default resolver.
//
// The last row is the authority-style gotcha: with no path, gRPC's grammar is
// ambiguous and the authority doubles as the endpoint, so Authority and
// Endpoint coincide. Prefer the path-style forms to keep them distinct.
func ExampleGRPC_Authority() {
	for _, in := range []xddr.GRPC{
		"dns://8.8.8.8:53/grpc.io:50051", // resolver + endpoint (distinct)
		"dns:///grpc.io:50051",           // default resolver (empty)
		"dns://grpc.io:50051",            // authority-style (ambiguous)
	} {
		g, _ := in.Sanitize()
		fmt.Printf("%-30s resolver=%-15q endpoint=%q\n", g, g.Authority(), g.Endpoint())
	}
	// Output:
	// dns://8.8.8.8:53/grpc.io:50051 resolver="8.8.8.8:53"    endpoint="grpc.io:50051"
	// dns:///grpc.io:50051           resolver=""              endpoint="grpc.io:50051"
	// dns://grpc.io:50051            resolver="grpc.io:50051" endpoint="grpc.io:50051"
}

// The same three values side by side show how the generic view diverges from
// the concrete one as the form gets smarter: URL agrees, HTTP hides the default
// port, and GRPC hides the whole endpoint in the path (generic host is empty).
func Example_hostPortAcrossForms() {
	url, _ := xddr.URL("http://foo:80").Sanitize()
	web, _ := xddr.HTTP("http://foo:80").Sanitize()
	rpc, _ := xddr.GRPC("dns:///foo:50051").Sanitize()

	fmt.Printf("%-4s %-18s | %-7s %-6s | %-7s %s\n", "", "value", "HostOf", "PortOf", "Host()", "Port()")
	fmt.Printf("%-4s %-18s | %-7q %-6d | %-7q %d\n", "URL", url, xddr.HostOf(url), xddr.PortOf(url), url.Host(), url.Port())
	fmt.Printf("%-4s %-18s | %-7q %-6d | %-7q %d\n", "HTTP", web, xddr.HostOf(web), xddr.PortOf(web), web.Host(), web.Port())
	fmt.Printf("%-4s %-18s | %-7q %-6d | %-7q %d\n", "GRPC", rpc, xddr.HostOf(rpc), xddr.PortOf(rpc), rpc.Host(), rpc.Port())
	// Output:
	//      value              | HostOf  PortOf | Host()  Port()
	// URL  http://foo:80      | "foo"   80     | "foo"   80
	// HTTP http://foo         | "foo"   -1     | "foo"   80
	// GRPC dns:///foo:50051   | ""      -1     | "foo"   50051
}

// Moving back and forth between the URL form and the listen (Local) form.
// AsURL turns a listen address into something a client can dial, mapping
// wildcard hosts to loopback; Local goes the other way.
func Example_convertForms() {
	// listen form -> dial URL
	fmt.Println(xddr.HTTPLocal("tcp4:0.0.0.0:80").AsURL()) // wildcard -> loopback
	fmt.Println(xddr.GRPCLocal("tcp6:[::]:80").AsURL())    // wildcard -> loopback

	// URL form -> listen form (endpoint pulled out of the gRPC path)
	g, _ := xddr.GRPC("grpc.io:50051").Sanitize()
	fmt.Println(g.Local())
	// Output:
	// http://127.0.0.1:80
	// dns:///[::1]:80
	// tcp:grpc.io:50051
}
