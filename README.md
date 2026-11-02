# 🛡️ Fail2ban Security Dashboard — Prometheus + Grafana

Turn your **fail2ban** data into a live **Grafana** security dashboard: bans, failed SSH attempts, a world map of attackers, top attacking IPs, countries and hosting providers.

One script installs and connects the whole stack on a Debian/Ubuntu server.

---

## 📐 Architecture

```
┌───────────┐   every 30s   ┌──────────────────┐        ┌────────────────┐        ┌────────────┐        ┌───────────┐
│ fail2ban  │ ────────────► │ f2b-metrics.py   │ ─────► │ node_exporter  │ ─────► │ Prometheus │ ─────► │  Grafana  │
│ (jails)   │ fail2ban-     │ (systemd timer)  │ .prom  │ :9100 textfile │ scrape │ :9090 local│ query  │   :3000   │
└───────────┘ client        │ + IP geolocation │  file  │   collector    │  30s   │ 90d retain │        │ dashboard │
                            └──────────────────┘        └────────────────┘        └────────────┘        └───────────┘
```

| Component | Role | Port |
|---|---|---|
| **fail2ban** | Detects brute-force attempts and bans IPs | — |
| **f2b-metrics.py** | Reads `fail2ban-client`, writes Prometheus metrics, adds geolocation (country, city, ISP, ASN) | — |
| **node_exporter** | Exposes the metrics via its textfile collector | `9100` |
| **Prometheus** | Scrapes and stores the time series (localhost only, 90 days) | `127.0.0.1:9090` |
| **Grafana** | Dashboard, provisioned as code | `3000` |

---

## ✅ Prerequisites

- Debian / Ubuntu server (uses `apt`)
- Root access
- `fail2ban` installed and running (`fail2ban-client ping` → `pong`)
- Outbound internet access (apt repos, `apt.grafana.com`, `ip-api.com` for geolocation)

---

## 🚀 Installation

```bash
# 1. Save the script on the server
nano installed.sh        # paste the content, save

# 2. Run it as root
bash installed.sh
```

At the end, the script prints:

```
Grafana:  http://<YOUR_PUBLIC_IP>:3000/
Login:    admin / <generated password>    <- save it now!
```

> ⚠️ The admin password is shown **only once**. Save it.

### Options

| Variable | Default | Description |
|---|---|---|
| `GRAFANA_PORT` | `3000` | Port Grafana listens on |
| `GRAFANA_PASS` | random (20 chars) | Admin password to set on a fresh Grafana install |

```bash
GRAFANA_PORT=3001 GRAFANA_PASS='MyStrongPassword' bash installed.sh
```

The script is **safe to re-run**: it skips what is already installed and keeps your existing Grafana password.

---

## 📦 What the script does

1. **Installs** `prometheus` and `prometheus-node-exporter` with apt
2. **Installs the collector** at `/usr/local/lib/f2b-metrics/f2b-metrics.py`, run every 30s by `f2b-metrics.timer`
3. **Enables node_exporter's textfile collector** (`/var/lib/prometheus/node-exporter`) if needed
4. **Configures Prometheus**: listens on `127.0.0.1:9090` only, scrapes node_exporter every 30s, keeps 90 days. The old config is backed up as `prometheus.yml.bak-before-f2b`
5. **Installs Grafana** from the official repo and provisions:
   - the Prometheus datasource (uid `f2b-prometheus`)
   - the dashboard **Security › Fail2ban — Security Overview**, set as the home page
   - sign-up and anonymous access disabled, admin password changed
6. **Opens the Grafana port** in `ufw` if it is active

---

## 📊 Exported metrics

| Metric | Type | Labels | Description |
|---|---|---|---|
| `fail2ban_up` | gauge | — | `1` if the fail2ban server answers |
| `fail2ban_jails` | gauge | — | Number of active jails |
| `fail2ban_jail_banned_current` | gauge | `jail` | IPs currently banned |
| `fail2ban_jail_banned_total` | counter | `jail` | Bans since fail2ban started |
| `fail2ban_jail_failed_current` | gauge | `jail` | IPs currently failing (not banned yet) |
| `fail2ban_jail_failed_total` | counter | `jail` | Failed attempts since fail2ban started |
| `fail2ban_jail_bantime_seconds` | gauge | `jail` | Ban duration (`-1` = permanent) |
| `fail2ban_jail_findtime_seconds` | gauge | `jail` | Detection window |
| `fail2ban_jail_maxretry` | gauge | `jail` | Failures allowed before a ban |
| `fail2ban_banned_ip` | gauge | `jail, ip, country, country_code, city, isp, asn` | One series per banned IP; value = ban start (unix time) |
| `fail2ban_ip_failures_24h` | gauge | `jail, ip, country, country_code, city, isp, asn` | Failed attempts per IP over the last 24h (from the fail2ban log) |
| `fail2ban_metrics_last_run_seconds` | gauge | — | Time of the last collection |

Geolocation uses [ip-api.com](https://ip-api.com) (batched, cached 30 days in `/var/lib/f2b-metrics/geo.json`).

---

## 🖥️ Dashboard panels

| Section | Panels |
|---|---|
| **Overview** | fail2ban status · Banned now · Failed attempts (24h) · New bans (24h) · Attacking IPs (24h) · Countries banned |
| **Activity** | Failed attempts per interval · Bans per interval · Currently banned IPs · IPs currently failing |
| **Geography** | 🌍 World map of banned IPs by country · Top 15 countries |
| **Investigation** | Banned IPs table (IP, country, city, ISP, ASN, jail, banned since) · Top 30 attacking IPs (24h) |
| **Infrastructure** | Top ISPs / hosting providers · Jail settings (ban time, find time, max retry, totals) |

The **Jail** filter at the top applies to every panel.

> ℹ️ "24h" values and the per-interval graphs need some history: they become accurate after the stack has been running for a few hours / a full day.

---

## 🔍 Checks

```bash
# Collector
systemctl status f2b-metrics.timer
systemctl status f2b-metrics.service
cat /var/lib/prometheus/node-exporter/fail2ban.prom | head

# node_exporter exposes the metrics
curl -s localhost:9100/metrics | grep ^fail2ban

# Prometheus
systemctl status prometheus
curl -s 'http://127.0.0.1:9090/api/v1/query?query=fail2ban_up'

# Grafana
systemctl status grafana-server
curl -s localhost:3000/api/health
```

---

## 🧰 Troubleshooting

| Symptom | Fix |
|---|---|
| `fail2ban metrics not visible on :9100` | Check the collector: `journalctl -u f2b-metrics -n 30`. If `fail2ban.prom` exists but metrics are missing, enable the textfile collector:<br>`sed -i 's\|^ARGS="\|ARGS="--collector.textfile.directory=/var/lib/prometheus/node-exporter \|' /etc/default/prometheus-node-exporter && systemctl restart prometheus-node-exporter` |
| Script seems stuck at "Installing Grafana" | The package is large. Check `ls -la /var/cache/apt/archives/partial/`. If `needrestart` is hanging: `pkill needrestart` |
| Panels show **No data** | Wait 5–10 minutes and set the time range to **Last 6 hours** |
| Decimals in the 24h stats (e.g. `8.27`) | Normal at the beginning (Prometheus extrapolation). Values settle after 24h |
| Country = `Unknown` | ip-api.com unreachable or rate-limited. Retried automatically on the next runs |
| Forgot the Grafana password | `grafana-cli admin reset-admin-password 'NewPassword'` |

---

## 🔐 Security notes

- **Prometheus** listens on `127.0.0.1` only. It is not reachable from the internet.
- **node_exporter** listens on all interfaces by default. If nothing else scrapes it remotely, restrict it:
  ```bash
  sed -i 's|^ARGS="|ARGS="--web.listen-address=127.0.0.1:9100 |' /etc/default/prometheus-node-exporter
  systemctl restart prometheus-node-exporter
  ```
- **Grafana** is exposed over plain HTTP on port `3000`. Use a strong password, and ideally put it behind HTTPS (reverse proxy + domain) or restrict the port to your IP.
- Before sharing screenshots, **hide the address bar** (public IP + port).
- fail2ban is a safety net. The real protection is **SSH key-only authentication** (`PasswordAuthentication no`).

---

## 🗑️ Uninstall

```bash
systemctl disable --now f2b-metrics.timer grafana-server prometheus
rm -f /etc/systemd/system/f2b-metrics.{service,timer}
rm -rf /usr/local/lib/f2b-metrics /var/lib/f2b-metrics
rm -f /var/lib/prometheus/node-exporter/fail2ban.prom
rm -f /etc/grafana/provisioning/datasources/f2b-prometheus.yaml /etc/grafana/provisioning/dashboards/f2b.yaml
rm -f /var/lib/grafana/dashboards/fail2ban.json
apt-get remove -y grafana prometheus      # optional
systemctl daemon-reload
```

---

## 📁 Files

| Path | Content |
|---|---|
| `/usr/local/lib/f2b-metrics/f2b-metrics.py` | Metrics collector |
| `/etc/systemd/system/f2b-metrics.{service,timer}` | 30s collection schedule |
| `/var/lib/prometheus/node-exporter/fail2ban.prom` | Generated metrics |
| `/var/lib/f2b-metrics/geo.json` | Geolocation cache |
| `/etc/prometheus/prometheus.yml` | Prometheus config |
| `/etc/default/prometheus` | Prometheus flags (listen address, retention) |
| `/etc/grafana/provisioning/datasources/f2b-prometheus.yaml` | Grafana datasource |
| `/etc/grafana/provisioning/dashboards/f2b.yaml` | Dashboard provider |
| `/var/lib/grafana/dashboards/fail2ban.json` | The dashboard |
| `/etc/default/grafana-server` | Grafana settings (port, home dashboard, sign-up off) |

---

**Stack:** fail2ban · Python 3 · node_exporter · Prometheus · Grafana
