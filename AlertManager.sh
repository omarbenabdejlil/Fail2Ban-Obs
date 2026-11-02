#!/usr/bin/env bash
# ==================================================================
#  Alertmanager for the fail2ban / Prometheus / Grafana stack
#  Run as root AFTER the Grafana installer.
#
#  Interactive:  bash alertmanager-install.sh
#  Or non-interactive, e.g.:
#    CHANNEL=telegram TELEGRAM_BOT_TOKEN=123:ABC TELEGRAM_CHAT_ID=123456 bash alertmanager-install.sh
#    CHANNEL=discord  DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/... bash alertmanager-install.sh
#    CHANNEL=slack    SLACK_WEBHOOK_URL=https://hooks.slack.com/services/... bash alertmanager-install.sh
#    CHANNEL=email    SMTP_HOST=smtp.gmail.com:587 SMTP_USER=me@gmail.com SMTP_PASS='app-password' EMAIL_TO=me@gmail.com bash alertmanager-install.sh
# ==================================================================
set -euo pipefail
AM_FALLBACK_VERSION="0.28.1"
G='\033[1;32m'; Y='\033[1;33m'; R='\033[1;31m'; N='\033[0m'
say(){ echo -e "${G}==>${N} $*"; }; warn(){ echo -e "${Y}[!]${N} $*"; }; die(){ echo -e "${R}[x]${N} $*"; exit 1; }
q(){ local s="${1//\'/\'\'}"; printf "'%s'" "$s"; }          # YAML single-quote escaping
ask(){ local v; read -rp "$1" v </dev/tty; printf '%s' "$v"; }
asks(){ local v; read -rsp "$1" v </dev/tty; echo >&2; printf '%s' "$v"; }

[ "$(id -u)" -eq 0 ] || die "Run as root"
[ -f /etc/prometheus/prometheus.yml ] || die "Prometheus not found - run the Grafana installer first"
command -v promtool >/dev/null || die "promtool not found (apt install prometheus)"

# ---------- 1. choose the notification channel ----------
CHANNEL="${CHANNEL:-}"
if [ -z "$CHANNEL" ]; then
  echo
  echo "Where should alerts be sent?"
  echo "  1) Telegram   (recommended: instant on your phone)"
  echo "  2) Discord"
  echo "  3) Email (SMTP, e.g. Gmail with an App Password)"
  echo "  4) Slack"
  echo "  5) Nowhere for now (alerts only visible in Grafana / Alertmanager UI)"
  case "$(ask 'Choice [1-5]: ')" in
    1) CHANNEL=telegram;; 2) CHANNEL=discord;; 3) CHANNEL=email;; 4) CHANNEL=slack;; *) CHANNEL=none;;
  esac
fi

GLOBAL=""
RECEIVER="  - name: default"
case "$CHANNEL" in
  telegram)
    [ -n "${TELEGRAM_BOT_TOKEN:-}" ] || { echo "Create a bot with @BotFather on Telegram and paste its token."; TELEGRAM_BOT_TOKEN="$(asks 'Bot token: ')"; }
    if [ -z "${TELEGRAM_CHAT_ID:-}" ]; then
      echo "Now send any message (e.g. 'hi') to your bot in Telegram, then press Enter."; ask ''
      TELEGRAM_CHAT_ID="$(curl -s "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/getUpdates" \
        | python3 -c 'import sys,json; r=json.load(sys.stdin).get("result",[]); print(r[-1]["message"]["chat"]["id"] if r and "message" in r[-1] else "")' 2>/dev/null || true)"
      [ -n "$TELEGRAM_CHAT_ID" ] && say "Detected chat id: $TELEGRAM_CHAT_ID" || TELEGRAM_CHAT_ID="$(ask 'Could not detect it. Chat id: ')"
    fi
    [[ "$TELEGRAM_CHAT_ID" =~ ^-?[0-9]+$ ]] || die "Telegram chat id must be a number"
    RECEIVER="$RECEIVER
    telegram_configs:
      - bot_token: $(q "$TELEGRAM_BOT_TOKEN")
        chat_id: $TELEGRAM_CHAT_ID
        parse_mode: HTML
        send_resolved: true
        message: '{{ template \"tg.message\" . }}'";;
  discord)
    [ -n "${DISCORD_WEBHOOK_URL:-}" ] || DISCORD_WEBHOOK_URL="$(ask 'Discord webhook URL (Channel settings > Integrations > Webhooks): ')"
    RECEIVER="$RECEIVER
    discord_configs:
      - webhook_url: $(q "$DISCORD_WEBHOOK_URL")
        send_resolved: true
        title: '{{ template \"std.title\" . }}'
        message: '{{ template \"std.text\" . }}'";;
  slack)
    [ -n "${SLACK_WEBHOOK_URL:-}" ] || SLACK_WEBHOOK_URL="$(ask 'Slack incoming webhook URL: ')"
    RECEIVER="$RECEIVER
    slack_configs:
      - api_url: $(q "$SLACK_WEBHOOK_URL")
        send_resolved: true
        title: '{{ template \"std.title\" . }}'
        text: '{{ template \"std.text\" . }}'";;
  email)
    [ -n "${SMTP_HOST:-}" ] || SMTP_HOST="$(ask 'SMTP server:port [smtp.gmail.com:587]: ')"; SMTP_HOST="${SMTP_HOST:-smtp.gmail.com:587}"
    [ -n "${SMTP_USER:-}" ] || SMTP_USER="$(ask 'SMTP username (your email): ')"
    [ -n "${SMTP_PASS:-}" ] || SMTP_PASS="$(asks 'SMTP password (Gmail: an App Password): ')"
    [ -n "${EMAIL_TO:-}" ]  || EMAIL_TO="$(ask "Send alerts to [$SMTP_USER]: ")"; EMAIL_TO="${EMAIL_TO:-$SMTP_USER}"
    GLOBAL="  smtp_smarthost: $(q "$SMTP_HOST")
  smtp_from: $(q "${EMAIL_FROM:-$SMTP_USER}")
  smtp_auth_username: $(q "$SMTP_USER")
  smtp_auth_password: $(q "$SMTP_PASS")
  smtp_require_tls: true"
    RECEIVER="$RECEIVER
    email_configs:
      - to: $(q "$EMAIL_TO")
        send_resolved: true
        headers:
          Subject: '{{ template \"std.title\" . }}'
        text: '{{ template \"std.text\" . }}'";;
  none) warn "No notification channel: alerts will only show in Grafana and the Alertmanager UI.";;
  *) die "Unknown CHANNEL '$CHANNEL' (telegram|discord|slack|email|none)";;
esac

# ---------- 2. install Alertmanager binary ----------
VER="$(curl -s --max-time 8 https://api.github.com/repos/prometheus/alertmanager/releases/latest | sed -n 's/.*"tag_name": *"v\([^"]*\)".*/\1/p' | head -1)"
VER="${VER:-$AM_FALLBACK_VERSION}"
case "$(uname -m)" in x86_64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; armv7l) ARCH=armv7;; *) die "Unsupported CPU $(uname -m)";; esac
if ! /usr/local/bin/alertmanager --version 2>&1 | grep -q "version $VER "; then
  say "Downloading Alertmanager v$VER ($ARCH)"
  TMP="$(mktemp -d)"
  curl -fsSL "https://github.com/prometheus/alertmanager/releases/download/v${VER}/alertmanager-${VER}.linux-${ARCH}.tar.gz" | tar xz -C "$TMP" --strip-components=1
  install -m 755 "$TMP/alertmanager" "$TMP/amtool" /usr/local/bin/
  rm -rf "$TMP"
fi
id alertmanager >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin alertmanager
mkdir -p /etc/alertmanager /var/lib/alertmanager
chown alertmanager:alertmanager /var/lib/alertmanager

# ---------- 3. Alertmanager config ----------
say "Writing /etc/alertmanager/alertmanager.yml (channel: $CHANNEL)"
cat > /etc/alertmanager/templates.tmpl <<'TMPL_EOF'
{{ define "std.title" }}[{{ .Status | toUpper }}{{ if eq .Status "firing" }}:{{ .Alerts.Firing | len }}{{ end }}] {{ .CommonLabels.alertname }} - {{ .CommonLabels.instance | reReplaceAll ":[0-9]+" "" }}{{ end }}
{{ define "std.text" }}{{ range .Alerts }}{{ if eq .Status "firing" }}🔥{{ else }}✅{{ end }} [{{ .Labels.severity | toUpper }}] {{ .Annotations.summary }}
{{ .Annotations.description }}
Started: {{ .StartsAt.Local.Format "2006-01-02 15:04:05" }}{{ if eq .Status "resolved" }} | Resolved: {{ .EndsAt.Local.Format "2006-01-02 15:04:05" }}{{ end }}

{{ end }}{{ end }}
{{ define "tg.message" }}{{ if eq .Status "firing" }}🚨 <b>ALERT</b>{{ else }}✅ <b>RESOLVED</b>{{ end }} — <b>{{ .CommonLabels.alertname }}</b>
🖥 {{ .CommonLabels.instance | reReplaceAll ":[0-9]+" "" }}
{{ range .Alerts }}
{{ if eq .Labels.severity "critical" }}🔴{{ else if eq .Labels.severity "warning" }}🟠{{ else }}🔵{{ end }} {{ .Annotations.summary | html }}
<i>{{ .Annotations.description | html }}</i>
🕒 {{ .StartsAt.Local.Format "2006-01-02 15:04:05" }}{{ if eq .Status "resolved" }} → {{ .EndsAt.Local.Format "15:04:05" }}{{ end }}
{{ end }}{{ end }}
TMPL_EOF

{
  echo "global:"
  echo "  resolve_timeout: 5m"
  [ -n "$GLOBAL" ] && echo "$GLOBAL"
  cat <<'ROUTE_EOF'
templates:
  - /etc/alertmanager/templates.tmpl
route:
  receiver: default
  group_by: [alertname, jail]
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 6h
inhibit_rules:
  - source_matchers: [alertname="Fail2banDown"]
    target_matchers: [alertname=~"SSHBruteForceSpike|BanWave|ManyIPsFailing"]
  - source_matchers: [alertname="NodeExporterDown"]
    target_matchers: [alertname="Fail2banMetricsMissing"]
receivers:
ROUTE_EOF
  echo "$RECEIVER"
} > /etc/alertmanager/alertmanager.yml
chown root:alertmanager /etc/alertmanager/alertmanager.yml; chmod 640 /etc/alertmanager/alertmanager.yml
amtool check-config /etc/alertmanager/alertmanager.yml >/dev/null || { amtool check-config /etc/alertmanager/alertmanager.yml; die "Invalid Alertmanager config"; }

cat > /etc/systemd/system/alertmanager.service <<'SVC_EOF'
[Unit]
Description=Prometheus Alertmanager
After=network-online.target
Wants=network-online.target

[Service]
User=alertmanager
Group=alertmanager
ExecStart=/usr/local/bin/alertmanager \
  --config.file=/etc/alertmanager/alertmanager.yml \
  --storage.path=/var/lib/alertmanager \
  --web.listen-address=127.0.0.1:9093 \
  --cluster.listen-address=
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=yes

[Install]
WantedBy=multi-user.target
SVC_EOF
systemctl stop prometheus-alertmanager 2>/dev/null || true
systemctl disable prometheus-alertmanager 2>/dev/null || true

# ---------- 4. Prometheus rules + alerting ----------
say "Installing alert rules and connecting Prometheus to Alertmanager"
mkdir -p /etc/prometheus/rules
cat > /etc/prometheus/rules/fail2ban.yml <<'RULES_EOF'
groups:
  - name: fail2ban
    rules:
      - alert: Fail2banDown
        expr: fail2ban_up == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "fail2ban is DOWN on {{ $labels.instance }}"
          description: "The fail2ban server does not answer. SSH is no longer protected against brute force."

      - alert: Fail2banMetricsMissing
        expr: absent(fail2ban_up) or (time() - fail2ban_metrics_last_run_seconds) > 300
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "fail2ban metrics are not updated"
          description: "No fresh fail2ban metrics for 5+ minutes. Check: systemctl status f2b-metrics.timer"

      - alert: SSHBruteForceSpike
        expr: sum by (jail) (increase(fail2ban_jail_failed_total{jail="sshd"}[10m])) > 50
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "SSH brute-force spike: {{ $value | humanize }} failed logins in 10 min"
          description: "Unusually high number of failed SSH logins in the last 10 minutes."

      - alert: BanWave
        expr: sum(increase(fail2ban_jail_banned_total[15m])) > 15
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Ban wave: {{ $value | humanize }} IPs banned in 15 min"
          description: "fail2ban banned many IPs in a short time, possibly a coordinated attack."

      - alert: ManyIPsFailing
        expr: sum(fail2ban_jail_failed_current) > 25
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "{{ $value }} IPs are currently failing logins"
          description: "Many different IPs are failing logins at the same time (distributed attack)."

      - alert: DashboardLoginAttack
        expr: sum(increase(fail2ban_jail_failed_total{jail="f2b-dashboard"}[10m])) > 3
        for: 0m
        labels:
          severity: warning
        annotations:
          summary: "Failed logins on the fail2ban web dashboard"
          description: "Someone is guessing the web dashboard password ({{ $value | humanize }} failures in 10 min)."

  - name: host
    rules:
      - alert: NodeExporterDown
        expr: up{job="node"} == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "node_exporter is down"
          description: "Prometheus cannot scrape node_exporter (port 9100). No metrics are collected."

      - alert: HostDiskAlmostFull
        expr: (node_filesystem_avail_bytes{fstype!~"tmpfs|overlay|squashfs|ramfs"} / node_filesystem_size_bytes{fstype!~"tmpfs|overlay|squashfs|ramfs"}) * 100 < 10
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Disk almost full on {{ $labels.mountpoint }}"
          description: "Only {{ $value | printf \"%.1f\" }}% free space left on {{ $labels.mountpoint }}."

      - alert: HostHighMemory
        expr: (1 - node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes) * 100 > 90
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Memory usage above 90%"
          description: "RAM usage is {{ $value | printf \"%.0f\" }}%."

      - alert: HostHighCPU
        expr: (1 - avg(rate(node_cpu_seconds_total{mode="idle"}[5m]))) * 100 > 90
        for: 15m
        labels:
          severity: warning
        annotations:
          summary: "CPU usage above 90% for 15 minutes"
          description: "Average CPU usage is {{ $value | printf \"%.0f\" }}%."

      - alert: HostRebooted
        expr: time() - node_boot_time_seconds < 600
        for: 0m
        labels:
          severity: info
        annotations:
          summary: "Server rebooted"
          description: "The server booted less than 10 minutes ago."
RULES_EOF
promtool check rules /etc/prometheus/rules/fail2ban.yml >/dev/null || { promtool check rules /etc/prometheus/rules/fail2ban.yml; die "Invalid rules"; }

[ -f /etc/prometheus/prometheus.yml.bak-before-alertmanager ] || cp /etc/prometheus/prometheus.yml /etc/prometheus/prometheus.yml.bak-before-alertmanager
cat > /etc/prometheus/prometheus.yml <<'PEOF'
global:
  scrape_interval: 30s
  evaluation_interval: 30s
rule_files:
  - /etc/prometheus/rules/*.yml
alerting:
  alertmanagers:
    - static_configs:
        - targets: ['127.0.0.1:9093']
scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ['127.0.0.1:9090']
  - job_name: node
    static_configs:
      - targets: ['127.0.0.1:9100']
  - job_name: alertmanager
    static_configs:
      - targets: ['127.0.0.1:9093']
PEOF
promtool check config /etc/prometheus/prometheus.yml >/dev/null || { cp /etc/prometheus/prometheus.yml.bak-before-alertmanager /etc/prometheus/prometheus.yml; die "Invalid Prometheus config - restored backup"; }

systemctl daemon-reload
systemctl enable alertmanager >/dev/null 2>&1; systemctl restart alertmanager
systemctl restart prometheus
sleep 3
systemctl is-active --quiet alertmanager || { journalctl -u alertmanager -n 20 --no-pager; die "Alertmanager failed to start"; }

# ---------- 5. Grafana: Alertmanager datasource ----------
if [ -d /etc/grafana/provisioning/datasources ]; then
  cat > /etc/grafana/provisioning/datasources/f2b-alertmanager.yaml <<'DEOF'
apiVersion: 1
datasources:
  - name: Alertmanager
    uid: f2b-alertmanager
    type: alertmanager
    access: proxy
    url: http://127.0.0.1:9093
    jsonData:
      implementation: prometheus
      handleGrafanaManagedAlerts: false
DEOF
  systemctl restart grafana-server && say "Grafana: Alertmanager datasource added"
fi

# ---------- 6. test notification ----------
sleep 2
ENDS="$(date -u -d '+2 min' +%Y-%m-%dT%H:%M:%SZ)"
curl -sf -X POST -H 'Content-Type: application/json' http://127.0.0.1:9093/api/v2/alerts -d "[{
  \"labels\": {\"alertname\": \"InstallTest\", \"severity\": \"info\", \"instance\": \"$(hostname)\"},
  \"annotations\": {\"summary\": \"Alertmanager is working on $(hostname)\", \"description\": \"This is a test alert sent by the installer. It resolves automatically in 2 minutes.\"},
  \"endsAt\": \"$ENDS\"}]" >/dev/null && say "Test alert sent - you should receive it within ~30 seconds" || warn "Could not send the test alert"

echo
echo -e "${G}==================================================================${N}"
echo -e "  Alertmanager v$VER running on 127.0.0.1:9093  (channel: ${Y}$CHANNEL${N})"
echo -e "  Rules:      /etc/prometheus/rules/fail2ban.yml  ($(grep -c 'alert:' /etc/prometheus/rules/fail2ban.yml) alerts)"
echo -e "  Config:     /etc/alertmanager/alertmanager.yml"
echo -e "  See alerts: Grafana > Alerting, or from your PC:"
echo -e "              ssh -L 9093:127.0.0.1:9093 -L 9090:127.0.0.1:9090 root@$(hostname -I | awk '{print $1}')"
echo -e "              then open http://localhost:9093 (Alertmanager) and http://localhost:9090/alerts (Prometheus)"
echo -e "  Re-run with another CHANNEL anytime: bash $0"
echo -e "${G}==================================================================${N}"
