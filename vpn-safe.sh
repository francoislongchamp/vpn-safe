#!/usr/bin/env bash
#
# vpn-safe.sh — filet de sécurité avant connexion FortiClient / openfortivpn
#
#   sudo ./vpn-safe.sh arm      -> à lancer AVANT de monter le VPN
#   sudo ./vpn-safe.sh status   -> état courant
#   sudo ./vpn-safe.sh tune     -> abaisse le MTU du tunnel (après connexion VPN)
#   sudo ./vpn-safe.sh keep     -> réaffirme l'état maintenant (routage, MSS, routes VPN)
#   sudo ./vpn-safe.sh diag     -> tout l'état + journaux, à me renvoyer en cas de souci
#   sudo ./vpn-safe.sh hold     -> suspend le watchdog 30 min (travail sans RDP)
#   sudo ./vpn-safe.sh panic    -> coupe le VPN et restaure tout, maintenant
#   sudo ./vpn-safe.sh disarm   -> retire tout (routage, marques, watchdog)
#
# Principe : le trafic de réponse de xrdp (3389) et sshd (22) est marqué puis
# routé via une table dédiée qui garde la passerelle du VPC. Les routes
# 0.0.0.0/1 et 128.0.0.0/1 poussées par le VPN ne le capturent donc plus.
# En parallèle, un watchdog coupe le VPN dans deux cas : plus aucune session
# RDP/SSH établie pendant DEADMAN_MIN minutes (coupure franche), ou session
# établie dont la file d'envoi reste bloquée STUCK_SEC secondes (écran FIGÉ,
# signature d'un trou noir PMTU).

set -euo pipefail

RDP_PORT="${RDP_PORT:-3389}"
SSH_PORT="${SSH_PORT:-22}"
TABLE_ID="${TABLE_ID:-100}"
TABLE_NAME="vpnsafe"
MARK="0x1"
RULE_PREF=100
DEADMAN_MIN="${DEADMAN_MIN:-3}"     # minutes sans session avant coupure du VPN
CHECK_SEC=20                        # période de vérification du watchdog
GRACE_SEC=120                       # délai de grâce après montée du tunnel
MSS_VALUE="${MSS_VALUE:-1200}"      # MSS imposé : fiable même si les ICMP sont filtrés
TUN_MTU="${TUN_MTU:-1300}"          # MTU forcé sur le tunnel dès son apparition
STUCK_SEC="${STUCK_SEC:-90}"        # secondes de file d'envoi bloquée = session figée
KEEPALIVE_IP="${KEEPALIVE_IP:-}"     # IP côté VPN à pinger (contre l'idle-timeout Fortigate)
REPAIR_VPN_ROUTES="${REPAIR_VPN_ROUTES:-1}"   # réinsère les routes du tunnel si elles s'évaporent

STATE=/var/backups/vpn-safety
HOLD=/tmp/vpn-safe.hold
PIDFILE=/run/vpn-safe-watchdog.pid
LOG=/var/log/vpn-safe.log
RLOG=/var/log/vpn-safe-routes.log
RMONPID=/run/vpn-safe-routemon.pid

log() { printf '%s  %s\n' "$(date '+%F %T')" "$*" | tee -a "$LOG" >&2; }
die() { log "ERREUR: $*"; exit 1; }

[[ $EUID -eq 0 ]] || die "à lancer avec sudo."

# ---------------------------------------------------------------- découverte
discover() {
  GW=$(ip -4 route show default | awk '/^default/{print $3; exit}')
  DEV=$(ip -4 route show default | awk '/^default/{print $5; exit}')
  [[ -n "${GW:-}" && -n "${DEV:-}" ]] || die "pas de route par défaut trouvée."
  if [[ "$DEV" == ppp* || "$DEV" == tun* ]]; then
    die "le VPN semble DÉJÀ monté (route par défaut via $DEV). Lance 'panic' d'abord."
  fi
}

vpn_up() {
  ip -o link show 2>/dev/null | grep -qE ': (ppp|tun|vpn)[0-9]' && return 0
  pgrep -f 'openfortivpn|forticlient|forticlientsslvpn' >/dev/null 2>&1
}

sessions_live() {
  local n
  n=$( { ss -tnH state established "( sport = :$RDP_PORT or sport = :$SSH_PORT )" \
         2>/dev/null || true; } | wc -l )
  [[ "$n" -gt 0 ]]
}

# Une session RDP figée par un trou noir PMTU reste ÉTABLIE : seule la file
# d'envoi du noyau cesse de se vider. C'est ce signal-là qu'on surveille.
sendq_backlog() {
  local q
  q=$( { ss -tnH state established "( sport = :$RDP_PORT )" 2>/dev/null || true; } \
       | awk '{s+=$2} END{print s+0}' )
  [[ "${q:-0}" -gt 0 ]]
}

tunnel_ifaces() {
  ip -o link show | awk -F': ' '$2 ~ /^(ppp|tun|vpn)[0-9]/ {print $2}'
}

# Abaisse le MTU du tunnel : sans ça les gros bitmaps RDP partent en fumée.
tune_tunnel() {
  local itf done=0
  for itf in $(tunnel_ifaces); do
    if ip link set dev "$itf" mtu "$TUN_MTU" 2>/dev/null; then
      log "MTU de $itf abaissé à $TUN_MTU."; done=1
    fi
  done
  [[ $done -eq 1 ]] || log "aucun tunnel détecté — rien à ajuster."
}

# ------------------------------------------------------------------ docker
check_docker() {
  local bad=0 net
  while read -r net; do
    [[ -z "$net" ]] && continue
    # 172.16.0.0/12 = 172.16.x à 172.31.x : plage très souvent routée par Fortigate
    if [[ "$net" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; then
      log "ATTENTION: réseau Docker $net dans 172.16.0.0/12 — conflit probable avec le VPN."
      bad=1
    fi
  done < <(ip -4 -o addr show | awk '$2 ~ /^(docker|br-)/ {print $4}')

  if [[ $bad -eq 1 ]]; then
    cat >&2 <<'EOF'

  --> Corrige /etc/docker/daemon.json puis redémarre Docker :

      {
        "bip": "192.168.244.1/24",
        "default-address-pools": [
          { "base": "192.168.248.0/21", "size": 24 }
        ]
      }

      sudo systemctl restart docker
      (les bridges br-* existants doivent être recréés : docker compose down && up -d)

EOF
  fi
}

# ------------------------------------------------------------------- sauvegarde
save_state() {
  mkdir -p "$STATE"
  ip -4 route show default > "$STATE/default-route.txt"
  printf '%s\n' "$GW" > "$STATE/gateway.txt"
  printf '%s\n' "$DEV" > "$STATE/device.txt"
  [[ -f /etc/resolv.conf ]] && cp -a /etc/resolv.conf "$STATE/resolv.conf.bak"
  log "état sauvegardé dans $STATE (passerelle $GW via $DEV)"
}

# -------------------------------------------------------------------- routage
setup_routing() {
  # Le nom de table est purement cosmétique : le noyau n'utilise que l'ID.
  # Certaines distributions (Kali, images minimales) ne fournissent pas
  # /etc/iproute2/rt_tables — on le crée si possible, sinon on continue.
  if mkdir -p /etc/iproute2 2>/dev/null; then
    touch /etc/iproute2/rt_tables 2>/dev/null || true
    if [[ -w /etc/iproute2/rt_tables ]] \
       && ! grep -qE "^[[:space:]]*${TABLE_ID}[[:space:]]+${TABLE_NAME}([[:space:]]|\$)" \
            /etc/iproute2/rt_tables 2>/dev/null; then
      echo "${TABLE_ID} ${TABLE_NAME}" >> /etc/iproute2/rt_tables \
        && log "table ${TABLE_ID} nommée '${TABLE_NAME}'."
    fi
  else
    log "note: /etc/iproute2 indisponible — table ${TABLE_ID} utilisée sans nom (sans incidence)."
  fi

  ip route replace default via "$GW" dev "$DEV" table "$TABLE_ID"

  while ip rule del pref "$RULE_PREF" 2>/dev/null; do :; done
  ip rule add pref "$RULE_PREF" fwmark "$MARK" table "$TABLE_ID"

  # rp_filter en mode souple : sinon le noyau jette les paquets au retour
  sysctl -qw net.ipv4.conf.all.rp_filter=2
  sysctl -qw "net.ipv4.conf.${DEV}.rp_filter=2"

  local p
  for p in "$RDP_PORT" "$SSH_PORT"; do
    iptables -t mangle -C OUTPUT -p tcp --sport "$p" -j MARK --set-mark "$MARK" 2>/dev/null \
      || iptables -t mangle -A OUTPUT -p tcp --sport "$p" -j MARK --set-mark "$MARK"
  done

  # MTU : eth0 est en jumbo frames (9001) côté AWS, le tunnel plafonne vers 1400.
  # On impose une MSS FIXE plutôt que --clamp-mss-to-pmtu : ce dernier dépend de
  # la découverte PMTU, c'est-à-dire des ICMP "fragmentation needed"... qui sont
  # précisément filtrés quand le RDP se fige. Une valeur en dur ne dépend de rien.
  while iptables -t mangle -D OUTPUT -p tcp --tcp-flags SYN,RST SYN \
        -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; do :; done
  iptables -t mangle -C OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VALUE" 2>/dev/null \
    || iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VALUE"
  log "MSS imposée à $MSS_VALUE sur les SYN sortants."

  log "routage armé : marque $MARK -> table $TABLE_NAME (default via $GW dev $DEV)"
}

teardown_routing() {
  local p
  for p in "$RDP_PORT" "$SSH_PORT"; do
    while iptables -t mangle -D OUTPUT -p tcp --sport "$p" -j MARK --set-mark "$MARK" 2>/dev/null; do :; done
  done
  while iptables -t mangle -D OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; do :; done
  while iptables -t mangle -D OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VALUE" 2>/dev/null; do :; done
  while ip rule del pref "$RULE_PREF" 2>/dev/null; do :; done
  ip route flush table "$TABLE_ID" 2>/dev/null || true
  log "routage retiré."
}

# -------------------------------------------------------------------- panic
do_panic() {
  log "=== PANIC : coupure du VPN et restauration ==="

  local pat='openfortivpn|forticlient|forticlientsslvpn|fortisslvpn|fortivpn|FortiClient'
  local found
  found=$(pgrep -af "$pat" 2>/dev/null | tr '\n' ';' || true)
  if [[ -n "$found" ]]; then log "processus VPN visés : $found"
  else log "aucun processus VPN reconnu (client GUI sous un autre nom ?)"; fi

  pkill -TERM -f "$pat" 2>/dev/null || true
  for _ in $(seq 1 10); do pgrep -f "$pat" >/dev/null 2>&1 || break; sleep 1; done
  pkill -KILL -f "$pat" 2>/dev/null || true

  # Point critique : ne JAMAIS retirer les routes du tunnel si le client survit.
  # Sinon on fabrique un tunnel fantôme — "VPN connecté" côté client, aucun
  # trafic qui y entre — et il faut tout reconnecter à la main.
  if pgrep -f "$pat" >/dev/null 2>&1; then
    log "ATTENTION: un processus VPN survit. Routes du tunnel CONSERVÉES pour éviter un tunnel fantôme."
    log "           tue-le à la main puis relance 'panic' si besoin."
  else
    local itf
    for itf in $(tunnel_ifaces); do
      ip link set "$itf" down 2>/dev/null || true
    done
    ip route del 0.0.0.0/1 2>/dev/null || true
    ip route del 128.0.0.0/1 2>/dev/null || true
    log "routes du tunnel nettoyées."
  fi

  local gw dev
  gw=$(cat "$STATE/gateway.txt" 2>/dev/null || true)
  dev=$(cat "$STATE/device.txt" 2>/dev/null || true)
  if [[ -n "$gw" && -n "$dev" ]]; then
    ip route replace default via "$gw" dev "$dev" || true
    log "route par défaut restaurée via $gw dev $dev"
  fi

  [[ -f "$STATE/resolv.conf.bak" ]] && cp -a "$STATE/resolv.conf.bak" /etc/resolv.conf || true

  systemctl restart xrdp 2>/dev/null || service xrdp restart 2>/dev/null || true
  log "xrdp redémarré — reconnexion possible."
}

# ------------------------------------------------------------ moniteur routes
# Journalise chaque ajout/suppression de route avec l'heure : c'est ce qui dira
# QUI retire les routes du tunnel au bout de 20 minutes, et quand exactement.
start_routemon() {
  if [[ -f "$RMONPID" ]] && kill -0 "$(cat "$RMONPID")" 2>/dev/null; then return; fi
  setsid nohup bash -c 'ip monitor route | while IFS= read -r l; do
      printf "%s  %s\n" "$(date "+%F %T")" "$l"; done' >> "$RLOG" 2>&1 < /dev/null &
  echo $! > "$RMONPID"
  log "moniteur de routes actif -> $RLOG"
}

stop_routemon() {
  [[ -f "$RMONPID" ]] || return 0
  pkill -TERM -P "$(cat "$RMONPID")" 2>/dev/null || true
  kill "$(cat "$RMONPID")" 2>/dev/null || true
  rm -f "$RMONPID"
}

# ------------------------------------------------------------------- keeper
# Rien ne garantit que notre état survive : un renouvellement DHCP, un
# NetworkManager zélé ou le client VPN lui-même peuvent l'effacer. Le keeper
# revérifie tout à chaque cycle et réinsère ce qui manque, en le journalisant.
keeper() {
  local kgw kdev p itf mtu rpf
  kgw=$(cat "$STATE/gateway.txt" 2>/dev/null || true)
  kdev=$(cat "$STATE/device.txt"  2>/dev/null || true)
  [[ -n "$kgw" && -n "$kdev" ]] || return 0

  ip rule show 2>/dev/null | grep -qE "^${RULE_PREF}:.*fwmark (${MARK}|1) " \
    || { ip rule add pref "$RULE_PREF" fwmark "$MARK" table "$TABLE_ID" 2>/dev/null \
         && log "RÉPARÉ: règle fwmark réinsérée."; }

  ip route show table "$TABLE_ID" 2>/dev/null | grep -q '^default' \
    || { ip route replace default via "$kgw" dev "$kdev" table "$TABLE_ID" 2>/dev/null \
         && log "RÉPARÉ: route par défaut de la table $TABLE_ID réinsérée."; }

  for p in "$RDP_PORT" "$SSH_PORT"; do
    iptables -t mangle -C OUTPUT -p tcp --sport "$p" -j MARK --set-mark "$MARK" 2>/dev/null \
      || { iptables -t mangle -A OUTPUT -p tcp --sport "$p" -j MARK --set-mark "$MARK" 2>/dev/null \
           && log "RÉPARÉ: marquage du port $p réinséré."; }
  done

  iptables -t mangle -C OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VALUE" 2>/dev/null \
    || { iptables -t mangle -A OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --set-mss "$MSS_VALUE" 2>/dev/null \
         && log "RÉPARÉ: MSS $MSS_VALUE réinsérée."; }

  rpf=$(sysctl -n "net.ipv4.conf.${kdev}.rp_filter" 2>/dev/null || echo 2)
  [[ "$rpf" == "2" ]] || { sysctl -qw "net.ipv4.conf.${kdev}.rp_filter=2" 2>/dev/null \
      && log "RÉPARÉ: rp_filter de $kdev remis en mode souple (était $rpf)."; }

  for itf in $(tunnel_ifaces); do
    mtu=$(cat "/sys/class/net/$itf/mtu" 2>/dev/null || echo 0)
    [[ "$mtu" -gt "$TUN_MTU" ]] && ip link set dev "$itf" mtu "$TUN_MTU" 2>/dev/null \
      && log "RÉPARÉ: MTU de $itf ramené à $TUN_MTU (était $mtu)."
  done
}

# Les routes du tunnel ont-elles disparu alors que le tunnel est debout ?
# C'est précisément le symptôme "VPN connecté mais plus d'accès au réseau".
check_vpn_routes() {
  local itf first
  first=$(tunnel_ifaces | head -n1)
  [[ -n "$first" ]] || return 0
  [[ -d "/sys/class/net/$first" ]] || return 0

  if ip route show 2>/dev/null | grep -qE "(^0\.0\.0\.0/1|^128\.0\.0\.0/1|dev ${first})"; then
    return 0
  fi

  log "ANOMALIE: tunnel $first debout mais AUCUNE route ne l'emprunte."
  if [[ "$REPAIR_VPN_ROUTES" == "1" ]]; then
    ip route add 0.0.0.0/1   dev "$first" 2>/dev/null \
      && ip route add 128.0.0.0/1 dev "$first" 2>/dev/null \
      && log "RÉPARÉ: routes 0.0.0.0/1 et 128.0.0.0/1 réinsérées via $first." \
      || log "échec de la réinsertion des routes du tunnel — la session Fortigate a probablement expiré côté serveur."
  fi
}

keepalive() {
  [[ -n "$KEEPALIVE_IP" ]] || return 0
  ping -c1 -W2 "$KEEPALIVE_IP" >/dev/null 2>&1 || true
}

# ------------------------------------------------------------------ watchdog
watchdog_loop() {
  local idle=0 seen_vpn=0 grace=0 stuck=0
  GW=$(cat "$STATE/gateway.txt" 2>/dev/null || true)
  DEV=$(cat "$STATE/device.txt"  2>/dev/null || true)
  log "watchdog démarré (seuil ${DEADMAN_MIN} min, vérif ${CHECK_SEC}s)"
  while true; do
    sleep "$CHECK_SEC"

    if [[ -f "$HOLD" ]]; then
      local age=$(( $(date +%s) - $(stat -c %Y "$HOLD") ))
      if [[ $age -lt 1800 ]]; then idle=0; continue; fi
      rm -f "$HOLD"; log "hold expiré, watchdog réactivé."
    fi

    if ! vpn_up; then idle=0; stuck=0; seen_vpn=0; grace=0; continue; fi

    if [[ $seen_vpn -eq 0 ]]; then
      seen_vpn=1; grace=0; stuck=0
      log "tunnel détecté, délai de grâce ${GRACE_SEC}s."
      tune_tunnel          # abaisse le MTU avant que le RDP n'ait le temps de geler
    fi
    # À chaque cycle : on réaffirme notre état et on surveille celui du tunnel.
    keeper
    check_vpn_routes
    keepalive

    if [[ $grace -lt $GRACE_SEC ]]; then grace=$((grace + CHECK_SEC)); continue; fi

    if sessions_live; then
      idle=0
      # Cas du GEL : la session tient, mais la file d'envoi ne se vide plus.
      if sendq_backlog; then
        stuck=$((stuck + CHECK_SEC))
        log "session RDP établie mais file d'envoi bloquée depuis ${stuck}s"
        if [[ $stuck -ge $STUCK_SEC ]]; then
          log "session figée (trou noir PMTU probable) -> coupure automatique du VPN."
          do_panic
          idle=0; stuck=0; seen_vpn=0; grace=0
        fi
      else
        stuck=0
      fi
    else
      stuck=0
      idle=$((idle + CHECK_SEC))
      log "aucune session RDP/SSH établie depuis ${idle}s"
      if [[ $idle -ge $((DEADMAN_MIN * 60)) ]]; then
        log "seuil atteint -> coupure automatique du VPN."
        do_panic
        idle=0; seen_vpn=0; grace=0
      fi
    fi
  done
}

start_watchdog() {
  if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    log "watchdog déjà actif (pid $(cat "$PIDFILE"))"; return
  fi
  setsid nohup "$0" _watchdog >>"$LOG" 2>&1 < /dev/null &
  echo $! > "$PIDFILE"
  sleep 1
  log "watchdog lancé (pid $(cat "$PIDFILE")), journal : $LOG"
}

stop_watchdog() {
  [[ -f "$PIDFILE" ]] || return 0
  kill "$(cat "$PIDFILE")" 2>/dev/null || true
  rm -f "$PIDFILE"
  log "watchdog arrêté."
}

# ----------------------------------------------------------------- commandes
case "${1:-}" in
  arm)
    discover
    check_docker
    save_state
    setup_routing
    start_routemon
    start_watchdog
    echo
    log "PRÊT. Tu peux monter le VPN."
    echo "  Si la session tombe, le VPN sera coupé seul sous ${DEADMAN_MIN} min :"
    echo "  reconnecte simplement ton RDP, sans redémarrer l'instance."
    ;;
  status)
    discover 2>/dev/null || true
    echo "--- routes par défaut ---"; ip -4 route show default
    echo "--- règles ip ---";          ip rule show | grep -E "^${RULE_PREF}:" || echo "(aucune)"
    echo "--- table ${TABLE_NAME} ---"; ip route show table "$TABLE_ID" 2>/dev/null || echo "(vide)"
    echo "--- mangle OUTPUT ---";       iptables -t mangle -S OUTPUT | grep -E 'MARK|TCPMSS' || echo "(aucune)"
    echo "--- sessions établies ---"
    ss -tnH state established "( sport = :$RDP_PORT or sport = :$SSH_PORT )" 2>/dev/null || true
    echo "--- VPN ---"; vpn_up && echo "tunnel ACTIF" || echo "tunnel inactif"
    echo "--- watchdog ---"
    if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
      then echo "actif (pid $(cat "$PIDFILE"))"; else echo "inactif"; fi
    ;;
  tune)   tune_tunnel ;;
  keep)   keeper; check_vpn_routes ;;
  diag)
    echo "=== routes (main) ==="            ; ip route show
    echo "=== table $TABLE_ID ==="          ; ip route show table "$TABLE_ID" 2>/dev/null
    echo "=== ip rule ==="                  ; ip rule show
    echo "=== mangle OUTPUT ==="            ; iptables -t mangle -S OUTPUT
    echo "=== interfaces tunnel ==="        ; for i in $(tunnel_ifaces); do
                                                echo "$i mtu=$(cat /sys/class/net/$i/mtu 2>/dev/null)"; done
    echo "=== processus VPN ==="            ; pgrep -af 'fortivpn|forticlient|openfortivpn|FortiClient' || echo "(aucun)"
    echo "=== 40 dernieres lignes du journal ===" ; tail -n 40 "$LOG" 2>/dev/null
    echo "=== 60 derniers evenements de route ===" ; tail -n 60 "$RLOG" 2>/dev/null
    ;;
  hold)   touch "$HOLD"; log "watchdog suspendu 30 min." ;;
  panic)  do_panic ;;
  disarm) stop_watchdog; stop_routemon; teardown_routing ;;
  _watchdog) watchdog_loop ;;
  *) sed -n '3,22p' "$0"; exit 1 ;;
esac