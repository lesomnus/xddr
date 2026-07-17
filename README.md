# xddr

[![Go Reference](https://pkg.go.dev/badge/github.com/lesomnus/xddr.svg)](https://pkg.go.dev/github.com/lesomnus/xddr)

String-typed network addresses and URLs for Go.

```go
u := xddr.HTTP("HTTP://Example.COM:80/foo?bar=42")
u, err := u.Sanitize() // "http://example.com/foo?bar=42"
```

Every type in this package is a named string type — `type URL string`, `type Authority string`, `type Host string`, and so on.
There is no parse step and no parsed struct:
a value **is** the address, and methods parse it lazily on each call.

## Philosophy

- **No `Parse`, only `Sanitize`.**
  A value of any type is just a string; nothing stops you from constructing an invalid one.
  *You* decide when validation is worth paying for and call `Sanitize` at that moment — typically once, at a trust boundary such as loading a config file or receiving user input.
  `Sanitize` validates the value and returns it in the *canonical form* that the rest of the package expects.
  Getters and `With*` setters assume canonical input and do not re-validate.
- **Values are cheap to pass around.**
  Being plain strings, addresses marshal, compare, hash, and log naturally.
  They fit directly in config structs, map keys, and wire formats.
- **Immutable updates.**
  `WithHost`, `WithPort`, ... return a new value and never mutate.
  Each `WithX`-suffixed variant (`WithHostX`, `WithPortX`, ...) is the same operation but panics on error, for when the input is statically known to be valid.

```go
type Config struct {
	Listen xddr.HTTPLocal `json:"listen"` // e.g. ":8080", "0.0.0.0:8080", "unix:/run/api.sock"
}

func run(conf Config) error {
	addr, err := conf.Listen.Sanitize()
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}

	l, err := xddr.Listen(addr)
	if err != nil {
		return err
	}

	fmt.Printf("serving at %s\n", addr.AsURL()) // "http://127.0.0.1:8080"
	return http.Serve(l, nil)
}
```

## Types

### Building blocks

| Type         | Example                                        | Notes                                                        |
| ------------ | ---------------------------------------------- | ------------------------------------------------------------ |
| `URL`        | `https://user:pass@host:1234/foo?k=v#frag`     | *Weak* RFC 3986: `http:example.com` (no `//`) is also valid. |
| `Authority`  | `user:pass@host:80`, `:80`                     | Empty host means "all interfaces" for local use.             |
| `Host`       | `127.0.0.1`, `[::1]`, `example.com`            | Union of `IPv4`, `IPv6`, and `Domain`. IPv6 is bracketed.    |
| `HostPort`   | `example.com:443`, `[::1]:443`                 | `Host` plus a required port.                                 |
| `Domain`     | `sub.example.com`                              | Not IDNA/punycode aware.                                     |
| `IP`         | `127.0.0.1`, `::1`, `` (empty = unspecified)   | Union of `IPv4` and `IPv6`.                                  |
| `IPv4`       | `127.0.0.1`                                    |                                                              |
| `IPv6`       | `::1`, `::ffff:192.0.2.128`                    | `Sanitize` shortens the longest zero run per RFC 5952.       |
| `IPPort`     | `127.0.0.1:80`, `[::1]:80`, `:80`              | IPv6 is bracketed to disambiguate from the port separator.   |
| `IPwithCIDR` | `10.0.0.0/8`, `fd00::/8`                       |                                                              |
| `Filepath`   | `file:/absolute/a.txt`, `file:./relative.txt`  | URL-style file path; authority is optional.                  |

### Local addresses

A `Local` is a `<network>:<address>` pair directly usable with the `net` package —
what you pass to `net.Listen`.

| Type           | Accepts                                     | Canonical examples                       |
| -------------- | ------------------------------------------- | ---------------------------------------- |
| `Local`        | any                                         | `tcp:0.0.0.0:443`, `unix:/run/api.sock`  |
| `TCPLocal`     | TCP only                                    | `tcp::80`, `tcp4:0.0.0.0:80`             |
| `UDPLocal`     | UDP only                                    | `udp::53`, `udp6:[::]:53`                |
| `UnixLocal`    | Unix domain sockets                         | `unix:/run/api.sock`, `unixgram:./x.sock`|
| `TCPUDPLocal`  | TCP or UDP                                  |                                          |
| `TCPUnixLocal` | TCP or Unix                                 |                                          |

`Sanitize` infers what you meant and fills in the blanks:

```go
xddr.TCPLocal(":80").Sanitize()          // "tcp::80" (all interfaces, both stacks)
xddr.TCPLocal("0.0.0.0:80").Sanitize()   // "tcp4:0.0.0.0:80"
xddr.TCPLocal("tcp6::80").Sanitize()     // "tcp6:[::]:80"
xddr.TCPUnixLocal("./x.sock").Sanitize() // "unix:./x.sock"
```

`WithHost` keeps the network family consistent with the new host:

```go
xddr.TCPLocal("tcp::80").WithHost("192.0.2.1")     // "tcp4:192.0.2.1:80"
xddr.TCPLocal("tcp::80").WithHost("[2001:db8::1]") // "tcp6:[2001:db8::1]:80"
xddr.TCPUnixLocal("tcp::80").WithHost("/x.sock")   // "unix:/x.sock"
```

### Protocol-specific types

Each protocol type pairs a URL form with a local (listen) form,
and converts between them:

| URL form | Local form  | Conversion                    |
| -------- | ----------- | ----------------------------- |
| `HTTP`   | `HTTPLocal` | `HTTPLocal.AsURL() HTTP`      |
| `GRPC`   | `GRPCLocal` | `GRPCLocal.AsURL() GRPC`, `GRPC.Local() Local` |
| `ICE`    | `ICELocal`  |                               |

`AsURL` converts a listen address into a URL that a client can dial,
mapping wildcard hosts to loopback:

```go
xddr.HTTPLocal("tcp4:0.0.0.0:80").AsURL() // "http://127.0.0.1:80"
xddr.GRPCLocal("tcp6:[::]:80").AsURL()    // "dns:///[::1]:80"
```

**`HTTP`** knows scheme default ports; `Sanitize` and `WithPort` omit them from the canonical form,
while `Port()` resolves them:

```go
xddr.HTTP("http://foo:80/x?q=1#f").Sanitize() // "http://foo/x?q=1#f"
xddr.HTTP("https://foo").Port()               // 443
```

**`GRPC`** follows the [gRPC name resolution syntax](https://grpc.io/docs/guides/custom-name-resolution/) `scheme://[authority]/endpoint`, where the *endpoint* lives in the URL **path**:

```go
g, _ := xddr.GRPC("grpc.io:50051").Sanitize() // "dns:///grpc.io:50051"
g.Endpoint()                                  // Authority("grpc.io:50051")
g.Host()                                      // Host("grpc.io") — reads the endpoint, not the resolver authority
g.Local()                                     // Local("tcp:grpc.io:50051")

xddr.GRPC("[::1]:50051").Sanitize()           // "dns:///[::1]:50051"
xddr.GRPC("unix:///run/grpc.sock").Local()    // Local("unix:/run/grpc.sock")
```

The URL *authority* is the name resolver; read it with `Authority` (empty means the
default resolver), separate from the endpoint that `Host`/`Endpoint` read from the path.
Because the endpoint lives in the path, generic helpers that follow the plain URL grammar
(`HostOf`, `PortOf`) see the resolver, not the endpoint:

```go
g, _ := xddr.GRPC("dns://8.8.8.8:53/grpc.io:50051").Sanitize()
g.Authority()  // Authority("8.8.8.8:53")    — the resolver
g.Endpoint()   // Authority("grpc.io:50051") — what you actually dial
g.Host()       // Host("grpc.io")
xddr.HostOf(g) // Host("8.8.8.8") — plain URL grammar sees the resolver, not the endpoint
```

> [!WARNING]
> The authority-style target `dns://host:port` (no path) is ambiguous: with no path the
> authority doubles as the endpoint, so `Authority` and `Endpoint` return the same value.
> Bare and path-style inputs avoid this — `Sanitize` normalizes `host:port` to
> `dns:///host:port`, leaving the authority empty.
>
> ```go
> a, _ := xddr.GRPC("dns://grpc.io:50051").Sanitize()
> a.Authority() // Authority("grpc.io:50051") — same as a.Endpoint()
> ```

**`ICE`** covers STUN/TURN URIs per RFC 7064/7065, including default-port elision and
`?transport=` validation:

```go
xddr.ICE("stun://example.com:3478").Sanitize()  // "stun:example.com"
xddr.ICE("turn:example.com?transport=udp").Transport() // "udp"
```

## Generic helpers

Types that are syntactically URLs implement the `URLLike` constraint,
and local address types implement `LocalLike`.
This lets you write functions over any of them:

```go
func dump[T xddr.URLLike](v T) {
	fmt.Println(xddr.SchemeOf(v), xddr.HostOf(v), xddr.PortOf(v))
}

l, err := xddr.Listen(conf.Listen)            // works for any LocalLike
w, err := xddr.WithHost(u, "example.org")     // returns the same type as u
```

Available helpers:

- `URLLike`: `SchemeOf`, `AuthorityOf`, `HostOf`, `PortOf`, `WithHost`, `WithHostX`
- `LocalLike`: `NetworkOf`, `AddressOf`, `Listen`, `ListenPacket`

> [!NOTE]
> Generic helpers interpret the value using the **plain URL grammar** and do not apply
> scheme-specific semantics. `PortOf` returns the port as written (`-1` if absent) without
> resolving scheme defaults, and `HostOf(GRPC("dns://resolver/h:p"))` returns the
> *resolver* (empty for `dns:///h:p`), not the endpoint, because a gRPC target keeps its
> endpoint in the path. Prefer the concrete type's own methods
> (`HTTP.Port`, `GRPC.Host`, ...) when they exist — they shadow the generic behavior
> with protocol-aware logic.

## Sanitize details

`Sanitize` normalizes, not just validates:

- Scheme and host are lowercased.
- Percent-encoded triplets of *unreserved* characters are decoded (`%41` → `A`);
  everything else stays encoded with uppercased hex digits (`%2f` → `%2F`),
  since decoding reserved characters could change the structure of the value.
- IPv6 addresses are shortened per RFC 5952 (`0:0::1` → `::1`).
- Leading zeros are rejected in IPv4 and stripped in ports (`:0080` → `:80`, `:0` stays).
- Ports outside 0–65535 are rejected.
- Scheme default ports are elided by protocol types (`http://foo:80` → `http://foo`).
- Empty userinfo, query, and fragment are removed (`@host` → `host`, `scheme:?#` → `scheme:`).

Errors carry the byte position of the offending character:

```go
_, err := xddr.URL("http://exa mple.com").Sanitize()
// err: [10]: invalid host: [3]: invalid character ' '

var e *xddr.ErrorWithPos
if errors.As(err, &e) {
	fmt.Println(e.Pos()) // 10
}
```

## Non-goals

- **Full RFC 3986 compliance.** `URL` is deliberately *weak*: an opaque part is parsed
  with the same grammar as a hierarchical one, so `http:example.com` has an authority.
  Use `net/url` if you need strict behavior.
- **IDNA / punycode.** `Domain` validates LDH labels only.
- **DNS resolution.** Nothing here touches the network except `Listen`/`ListenPacket`.
