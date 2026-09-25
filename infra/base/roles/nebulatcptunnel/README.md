# infra.base.nebulatcptunnel

Exposes Nebula over an HTTPS tunnel (`chisel` on TCP/443) so a Nebula node can
be reached from networks that only permit http/https egress.

Nebula's transport is UDP-only; a strict http/https network blocks it. This role
runs a `chisel` server that accepts a TLS/WebSocket connection on 443 and
forwards the tunnelled bytes into the host's local Nebula UDP listener. A roaming
client runs `chisel client`, which presents a local UDP port that its Nebula
points at instead of the real (unreachable) UDP endpoint.

The role also installs **nginx on port 80** that 302-redirects non-tunnel HTTP
requests to a configured URL (see below). The implementation daemon is chisel,
hence the `chisel`-named service and paths; the role's variables use the
`nebulatcptunnel_` prefix.

## Where to deploy it

On a **public** host that is **also a Nebula lighthouse + relay**. That matters:
a tunnelled client only has one path out (the tunnel), and UDP hole-punching is
dead on such a network, so the client reaches every *other* mesh peer via the
relay at the tunnel endpoint.

## Server setup (Ansible)

1. **DNS** — create an A record for the tunnel FQDN pointing at the host's
   public IP. chisel provisions a Let's Encrypt cert for it on startup
   (TLS-ALPN-01 on port 443), so this must resolve first.

2. **Credentials** — generate the vault-encrypted tunnel credentials:
   ```
   ./infratool generate_nebulatcptunnel_auth <host>
   ```
   This writes `inventory/host_vars/<host>/nebulatcptunnel.vault.yml`
   (`nebulatcptunnel_auth_user` / `nebulatcptunnel_auth_password`). Print the
   credential again later — in the `user:password` form the client needs — with:
   ```
   ./infratool get_nebulatcptunnel_auth <host>
   ```

3. **Enable** — the role runs on any host where `nebulatcptunnel_tls_domain` is
   set. Set it in that host's `host_vars`.

4. **Firewall** — allow inbound TCP **443** (and **80** for the HTTP redirect)
   to the host on its public interface.

5. Run the playbook. Verify with `systemctl status chisel` and
   `journalctl -u chisel` (first start fetches the LE cert into
   `/var/lib/chisel/.cache/chisel`).

The authfile limits the credential to forwarding **only** to the local Nebula
UDP port — a leaked credential cannot pivot into the host's other networks.

## Non-tunnel HTTP requests

The host exists to serve the tunnel, so any ordinary web request to it should go
somewhere sensible rather than return a bare 404. The nginx redirect
(`nebulatcptunnel_redirect_enabled: true`, default) 302-redirects every
non-tunnel request to `nebulatcptunnel_redirect_url` (default
`https://example.org/`), preserving the request path and query string:

- **Port 80** — nginx returns the 302 directly.
- **Port 443, a normal HTTPS request** — chisel completes the TLS handshake with
  the valid Let's Encrypt cert, then reverse-proxies any request that isn't the
  tunnel handshake to the local nginx (`--backend http://127.0.0.1:80`, fixed),
  which returns the same 302. The tunnel handshake is still recognised and routed
  separately; only non-tunnel traffic reaches the redirect.

Setting `nebulatcptunnel_redirect_enabled: false` skips installing nginx; the
tunnel still reverse-proxies non-tunnel requests to `127.0.0.1:80`, so you must
serve something there yourself or those requests get a 502.

## Client setup (the roaming / corporate-network node)

The restricted client is a normal Nebula node. Two pieces: run `chisel client`
(here in Docker), then point Nebula at it. The examples use `<nebula-port>` for
the server's Nebula listen port and `<local-port>` for the local tunnel mouth —
pick a `<local-port>` *different* from the client's own Nebula listen port to
avoid a bind clash.

Get the `<user>:<password>` value from the vault with
`./infratool get_nebulatcptunnel_auth <host>` (run on the control machine, where
the vault password is available).

1. **Prerequisite** — Docker installed on the client.

2. **Run the tunnel (chisel in Docker)** — runs in the foreground, unnamed, and
   removes the container on exit. `--network host` makes the container bind the
   tunnel mouth on the host's loopback, exactly where Nebula expects it:
   ```
   docker run --rm --network host \
     jpillora/chisel:1.10.1 client --auth <user>:<password> --keepalive 25s \
     --header "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36" \
     https://<tunnel-fqdn>:443 \
     127.0.0.1:<local-port>:127.0.0.1:<nebula-port>/udp
   ```
   Behind a corporate HTTP proxy, add `-e HTTPS_PROXY=http://user:pass@proxyhost:port`
   (or chisel's `--proxy ...`).

   The `--header "User-Agent: …"` is **client-side only** — it sets the User-Agent
   on the WebSocket upgrade request to blend with ordinary HTTPS traffic; the
   server neither needs nor checks it. Use a current, common browser value.

   > `--network host` is a Linux feature. On Docker Desktop (macOS/Windows) it
   > does not expose the container to the host loopback — there, publish the port
   > instead (`-p 127.0.0.1:<local-port>:<local-port>/udp` and bind `0.0.0.0`
   > inside the container), which may require widening the server's authfile.

3. **Point Nebula at the tunnel** — in the client's `nebula.yml`, override the
   lighthouse's endpoint so its only underlay path is the local tunnel mouth:
   ```yaml
   static_host_map:
     "<lighthouse-nebula-ip>":
       - "127.0.0.1:<local-port>"

   lighthouse:
     hosts:
       - "<lighthouse-nebula-ip>"   # the tunnel endpoint; other lighthouses are unreachable here

   relay:
     use_relays: true
     relays:
       - "<lighthouse-nebula-ip>"   # reach the rest of the mesh via this relay

   punchy:
     punch: false                   # hole-punching can't work through the tunnel
   ```
   No MTU change is needed — the tunnel runs over TCP, which segments and
   reassembles regardless of underlay frame size.

4. **Ordering** — the tunnel container must be up before Nebula. Manage it with a
   systemd unit that runs the container in the foreground, and order Nebula after
   it. `/etc/systemd/system/nebula-tunnel.service` (restrict its mode to `0600` —
   it holds the credential):
   ```
   [Unit]
   Description=Nebula-over-HTTPS tunnel (chisel client, Docker)
   After=network-online.target docker.service
   Wants=network-online.target
   Requires=docker.service

   [Service]
   ExecStart=/usr/bin/docker run --rm --network host \
     jpillora/chisel:1.10.1 client --auth <user>:<password> --keepalive 25s \
     --header "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36" \
     https://<tunnel-fqdn>:443 \
     127.0.0.1:<local-port>:127.0.0.1:<nebula-port>/udp
   Restart=on-failure
   RestartSec=5s

   [Install]
   WantedBy=multi-user.target
   ```
   Then add a drop-in on the client's nebula unit so it waits for the tunnel:
   ```
   [Unit]
   Requires=nebula-tunnel.service
   After=nebula-tunnel.service
   ```

## Trade-off to be aware of

Nebula's UDP now rides inside TCP, so under packet loss you get TCP-over-TCP
behaviour (double retransmits, head-of-line blocking). Fine for SSH/admin;
throughput degrades on a lossy link. The only way around it is a UDP transport,
which the corporate network blocks — so this is the accepted cost.
