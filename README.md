# vpn-safe

Keep your RDP/SSH session alive on a remote Linux box while a **full-tunnel
Fortinet SSL VPN** is connected — and get back in automatically when it breaks.

Built and tested on Kali Linux running on AWS EC2, with `xrdp` and
FortiClient / `openfortivpn`. Nothing in it is AWS-specific.

---

## The problem

Connect a corporate FortiClient tunnel on a *remote* machine and you usually
lose that machine. Three distinct failure modes, often mistaken for one:

**1. Default route hijack.** The VPN installs `0.0.0.0/1` and `128.0.0.0/1`.
Both are more specific than your default route, so the reply traffic of your own
RDP/SSH session is swallowed by the tunnel. The box is fine — the return path is
gone. Only a console reboot brings it back.

**2. PMTU black hole.** Cloud instances often run jumbo frames (MTU 9001 on AWS).
The tunnel caps around 1400. When ICMP "fragmentation needed" is filtered —
which is common — large packets vanish silently. RDP sends big bitmaps, so the
screen **freezes** while the TCP connection stays `ESTABLISHED`. Naive watchdogs
never fire, because from their point of view the session is still up.

**3. Ghost tunnel.** Kill the VPN client badly and the tunnel routes may be
removed while the client keeps running. The GUI says "connected", the interface
exists, and no traffic reaches the corporate network.

`vpn-safe` addresses all three.

---

## How it works

| Mechanism | What it does |
| --- | --- |
| **Policy routing** | Marks outbound traffic from ports 3389/22 with `fwmark 0x1` and routes it through a dedicated table that keeps the real LAN gateway. The VPN's `/1` routes no longer capture it. Independent of your client IP, so it works on a dynamic address. |
| **Fixed MSS** | Writes `--set-mss 1200` into outbound SYNs instead of `--clamp-mss-to-pmtu`. The clamp depends on PMTU discovery, i.e. on the very ICMP messages that are filtered when RDP freezes. A hard value depends on nothing. |
| **Tunnel MTU** | Lowers the tunnel interface MTU as soon as it appears. |
| **Watchdog** | Tears the VPN down and restores networking on *either* trigger: no established RDP/SSH session for `DEADMAN_MIN` minutes (clean drop), or an established session whose kernel send queue stays backed up for `STUCK_SEC` seconds (**frozen** screen). |
| **Keeper** | Re-asserts every piece of state each cycle — ip rule, routing table, mangle rules, `rp_filter`, tunnel MTU — and logs each repair. Survives DHCP renewals, NetworkManager, and the VPN client rewriting things. |
| **Route monitor** | Timestamps every kernel route add/delete to a log, so you can see exactly what removed which route and when. |
| **Ghost-tunnel guard** | Never removes tunnel routes while a VPN process is still alive, and re-inserts them if they disappear under a live tunnel. |

Everything is in-memory kernel state: `ip rule`, a secondary routing table,
`iptables -t mangle` rules and two sysctls. **A reboot wipes all of it**, which
makes recovery trivial — there is nothing to undo.

---

## Requirements

- Linux with `iproute2`, `iptables`, `iproute2`'s `ss`, and `pgrep`/`pkill`
- root (`sudo`)
- `xrdp` and/or `sshd` for the sessions you want protected
- A working default route *before* the VPN is connected

`/etc/iproute2/rt_tables` is optional: the table name is cosmetic and the script
falls back to the numeric table ID when the file is absent (common on Kali).

---

## Install

```bash
clone this repo
chmod +x vpn-safe.sh
```

No dependencies to install, no daemon to register.

---

## Usage

Arm **before** connecting the VPN:

```bash
sudo ./vpn-safe.sh arm
# wait for: "READY / PRÊT. Tu peux monter le VPN."
# then connect FortiClient or openfortivpn
```

If `arm` does not reach that final line, **do not connect the VPN** — the
protections are not in place.

| Command | Purpose |
| --- | --- |
| `arm` | Set up routing, MSS, keeper, watchdog and route monitor |
| `status` | Current routing, rules, sessions, tunnel and watchdog state |
| `tune` | Lower the tunnel MTU now (if the watchdog has not seen it yet) |
| `keep` | Re-assert all state immediately, including tunnel routes |
| `diag` | Full state plus log tails — paste this when reporting a problem |
| `hold` | Suspend the watchdog for 30 minutes (long jobs with no RDP attached) |
| `panic` | Kill the VPN and restore networking right now |
| `disarm` | Remove everything: routing, marks, watchdog, monitor |

### Recovering without a reboot

If VPN-side access dies while the client still shows "connected", try this
first — it usually avoids the full disconnect/disarm/arm cycle:

```bash
sudo ./vpn-safe.sh keep
```

---

## Configuration

All settings are environment variables passed to `arm`:

```bash
sudo MSS_VALUE=1000 TUN_MTU=1100 STUCK_SEC=45 ./vpn-safe.sh arm
```

| Variable | Default | Meaning |
| --- | --- | --- |
| `RDP_PORT` | `3389` | Port of the protected RDP service |
| `SSH_PORT` | `22` | Port of the protected SSH service |
| `MSS_VALUE` | `1200` | MSS forced into outbound SYNs. Lower it if RDP still freezes |
| `TUN_MTU` | `1300` | MTU applied to the tunnel interface |
| `DEADMAN_MIN` | `3` | Minutes with no established session before cutting the VPN |
| `STUCK_SEC` | `90` | Seconds of blocked send queue treated as a frozen session |
| `KEEPALIVE_IP` | *(unset)* | VPN-side IP to ping every cycle, against server-side idle timeouts |
| `REPAIR_VPN_ROUTES` | `1` | Re-insert tunnel routes if they vanish under a live tunnel |
| `TABLE_ID` | `100` | Secondary routing table ID |

---

## Logs

| File | Contents |
| --- | --- |
| `/var/log/vpn-safe.log` | Watchdog decisions, `RÉPARÉ` repair lines, panic events |
| `/var/log/vpn-safe-routes.log` | Timestamped kernel route add/delete events |
| `/var/backups/vpn-safety/` | Saved gateway, device and `resolv.conf` for restore |

---

## Troubleshooting

| Symptom | Likely cause | Where to look |
| --- | --- | --- |
| Session dies the instant the VPN connects | Routing not armed | Did `arm` print its final READY line? |
| Screen freezes, connection stays up | MSS/MTU still too high | Lower `MSS_VALUE` and `TUN_MTU` |
| VPN "connected" but no corporate access | Ghost tunnel, or expired server session | `keep`, then `diag` |
| Access dies at a round interval (20 min, 30 min…) | Server-side idle timeout | Set `KEEPALIVE_IP`; ask IT for the portal's `idle-timeout` |
| Docker containers break when the VPN connects | Bridge subnet overlaps the tunnel's routes | See below |

### Docker subnet conflict

Default Docker bridges land in `172.17.0.0/16` and `172.18+`, inside the
`172.16.0.0/12` block that corporate Fortigates very often route. `arm` warns
about this. Fix it in `/etc/docker/daemon.json`:

```json
{
  "bip": "192.168.244.1/24",
  "default-address-pools": [
    { "base": "192.168.248.0/21", "size": 24 }
  ]
}
```

Then `sudo systemctl restart docker` and recreate existing `br-*` bridges
(`docker compose down && docker compose up -d`).

---

## Test the safety net before relying on it

1. `sudo ./vpn-safe.sh arm`
2. Connect the VPN
3. Close your RDP window on purpose
4. Wait `DEADMAN_MIN` + 1 minutes, reconnect

You should get back in, and `/var/log/vpn-safe.log` should show the automatic
cut. Until that test passes, keep a second way in — AWS SSM Session Manager or
the EC2 serial console.

---

## Known limitations

- **IPv4 only.** IPv6 is not marked or protected.
- **State is not persistent.** `arm` must run again after every reboot. That is
  deliberate: a reboot is a guaranteed clean slate.
- Protects traffic by **source port**, so services on non-standard ports need
  `RDP_PORT` / `SSH_PORT` set accordingly.
- `rp_filter` is set to loose mode (`2`) on the primary interface. Strict mode
  drops the reply packets that take the alternate table.
- If the Fortigate expires the session server-side, no local repair can bring it
  back — you must reconnect. The logs distinguish this case.
- Cutting the VPN is a *recovery* action: in-flight work inside the tunnel is
  lost. That is the trade-off against rebooting the instance.

---

## License

MIT.