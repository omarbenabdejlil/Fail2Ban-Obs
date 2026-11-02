cat > /root/f2b-grafana-install.sh <<'F2B_GRAFANA_INSTALLER_EOF'
#!/usr/bin/env bash
# ==================================================================
#  fail2ban -> Prometheus -> Grafana  (all-in-one installer, run as root)
#  Options: GRAFANA_PORT=3000 GRAFANA_PASS='secret' bash f2b-grafana-install.sh
# ==================================================================
set -euo pipefail
GRAFANA_PORT="${GRAFANA_PORT:-3000}"
G='\033[1;32m'; Y='\033[1;33m'; R='\033[1;31m'; N='\033[0m'
say(){ echo -e "${G}==>${N} $*"; }; warn(){ echo -e "${Y}[!]${N} $*"; }; die(){ echo -e "${R}[x]${N} $*"; exit 1; }
[ "$(id -u)" -eq 0 ] || die "Run as root"
command -v fail2ban-client >/dev/null || die "fail2ban not installed"
command -v apt-get >/dev/null || die "This script supports Debian/Ubuntu (apt) only"
export DEBIAN_FRONTEND=noninteractive

# ---------- 1. Prometheus + node_exporter ----------
say "Installing Prometheus + node_exporter (apt)"
apt-get update -qq
apt-get install -y -qq prometheus prometheus-node-exporter curl gpg apt-transport-https >/dev/null

# ---------- 2. fail2ban metrics collector ----------
say "Installing fail2ban metrics collector"
mkdir -p /usr/local/lib/f2b-metrics /var/lib/f2b-metrics
cat > /usr/local/lib/f2b-metrics/f2b-metrics.py <<'COLLECTOR_EOF'
#!/usr/bin/env python3
"""fail2ban -> Prometheus metrics via node_exporter textfile collector.
Usage: f2b-metrics.py /var/lib/prometheus/node-exporter
"""
import datetime, ipaddress, json, os, re, shutil, subprocess, sys, time, urllib.request, collections

OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else "/var/lib/prometheus/node-exporter"
STATE = os.environ.get("F2BM_STATE", "/var/lib/f2b-metrics")
F2B = os.environ.get("F2BM_CLIENT") or shutil.which("fail2ban-client") or "/usr/bin/fail2ban-client"
GEO_FILE = os.path.join(STATE, "geo.json")


def f2b(*args):
    r = subprocess.run([F2B] + list(args), capture_output=True, text=True, timeout=20)
    if r.returncode != 0:
        raise RuntimeError((r.stdout + r.stderr).strip())
    return r.stdout.strip()


def kv(text):
    d = {}
    for line in text.splitlines():
        m = re.match(r"^[\s|`\-]*([A-Za-z][A-Za-z ]*?):\s*(.*)$", line)
        if m:
            d[m.group(1).strip().lower()] = m.group(2).strip()
    return d


def num(s, default=0):
    try:
        return int(str(s).strip().split()[0])
    except Exception:
        return default


def esc(v):
    return str(v if v is not None else "").replace("\\", "\\\\").replace("\n", " ").replace('"', '\\"')


def labels(**kw):
    return "{" + ",".join('%s="%s"' % (k, esc(v)) for k, v in kw.items()) + "}"


# ---------- geo cache (ip-api.com, batched, cached 30 days) ----------
try:
    with open(GEO_FILE) as fh:
        GEO = json.load(fh)
except Exception:
    GEO = {}


def geo_resolve(ips):
    now = time.time()
    missing = []
    for ip in set(ips):
        g = GEO.get(ip)
        try:
            private = not ipaddress.ip_address(ip).is_global
        except ValueError:
            continue
        if private:
            GEO[ip] = {"country": "Private", "cc": "", "city": "", "isp": "", "asn": "", "t": now}
        elif not g or now - g.get("t", 0) > (30 * 86400 if g.get("cc") else 86400):
            missing.append(ip)
    changed = False
    for i in range(0, min(len(missing), 400), 100):  # ip-api: max 100 per batch
        chunk = missing[i:i + 100]
        try:
            req = urllib.request.Request("http://ip-api.com/batch?fields=status,country,countryCode,city,isp,as,query",
                                         data=json.dumps(chunk).encode(), headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=8) as r:
                data = json.load(r)
        except Exception:
            break
        for d in data:
            ok = d.get("status") == "success"
            GEO[d.get("query")] = {"country": d.get("country", "Unknown") if ok else "Unknown",
                                   "cc": d.get("countryCode", "") if ok else "", "city": d.get("city", "") if ok else "",
                                   "isp": d.get("isp", "") if ok else "", "asn": (d.get("as", "") or "").split(" ")[0] if ok else "",
                                   "t": now}
            changed = True
        time.sleep(1)
    if changed:
        os.makedirs(STATE, exist_ok=True)
        with open(GEO_FILE + ".tmp", "w") as fh:
            json.dump(GEO, fh)
        os.replace(GEO_FILE + ".tmp", GEO_FILE)


def geo(ip):
    g = GEO.get(ip) or {}
    return {"country": g.get("country") or "Unknown", "country_code": g.get("cc") or "",
            "city": g.get("city") or "", "isp": g.get("isp") or "", "asn": g.get("asn") or ""}


# ---------- failed attempts per IP in the last 24h (from fail2ban log) ----------
def failures_24h():
    path = None
    try:
        m = re.search(r"(/\S+)", f2b("get", "logtarget"))
        if m and os.path.isfile(m.group(1)):
            path = m.group(1)
    except Exception:
        pass
    if not path:
        return {}
    cutoff = (datetime.datetime.now() - datetime.timedelta(hours=24)).strftime("%Y-%m-%d %H:%M:%S")
    rx = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d).*?\[([^\]\s]+)\]\s+Found\s+([0-9A-Fa-f.:]+)")
    counts = collections.Counter()
    for p in (path + ".1", path):
        if not os.path.isfile(p):
            continue
        with open(p, "rb") as fh:
            fh.seek(0, 2)
            fh.seek(max(0, fh.tell() - 20000000))
            for line in fh.read().decode("utf-8", "replace").splitlines():
                m = rx.match(line)
                if m and m.group(1) >= cutoff:
                    counts[(m.group(2), m.group(3))] += 1
    return counts


def main():
    out = []
    h = lambda name, typ, help_: out.extend(["# HELP %s %s" % (name, help_), "# TYPE %s %s" % (name, typ)])
    try:
        jails = [j.strip() for j in kv(f2b("status")).get("jail list", "").split(",") if j.strip()]
        up = 1
    except Exception:
        jails, up = [], 0
    h("fail2ban_up", "gauge", "1 if the fail2ban server answered")
    out.append("fail2ban_up %d" % up)
    h("fail2ban_jails", "gauge", "Number of active jails")
    out.append("fail2ban_jails %d" % len(jails))

    per = {}
    banned = []
    for j in jails:
        st = kv(f2b("status", j))
        per[j] = st
        since = {}
        try:
            for line in f2b("get", j, "banip", "--with-time").splitlines():
                m = re.match(r"^(\S+)\s+(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)", line.strip())
                if m:
                    since[m.group(1)] = time.mktime(time.strptime(m.group(2), "%Y-%m-%d %H:%M:%S"))
        except Exception:
            pass
        for ip in st.get("banned ip list", "").split():
            banned.append((j, ip, since.get(ip, time.time())))

    fails = failures_24h()
    geo_resolve([b[1] for b in banned] + [ip for (_, ip) in fails])

    for name, key, typ, help_ in [
        ("fail2ban_jail_banned_current", "currently banned", "gauge", "IPs currently banned"),
        ("fail2ban_jail_banned_total", "total banned", "counter", "Bans since fail2ban start"),
        ("fail2ban_jail_failed_current", "currently failed", "gauge", "IPs currently failing (not yet banned)"),
        ("fail2ban_jail_failed_total", "total failed", "counter", "Failed attempts since fail2ban start")]:
        h(name, typ, help_)
        for j in jails:
            out.append("%s%s %d" % (name, labels(jail=j), num(per[j].get(key))))
    for name, key, help_ in [("fail2ban_jail_bantime_seconds", "bantime", "Ban duration (-1 = permanent)"),
                             ("fail2ban_jail_findtime_seconds", "findtime", "Find window"),
                             ("fail2ban_jail_maxretry", "maxretry", "Failures before ban")]:
        h(name, "gauge", help_)
        for j in jails:
            try:
                out.append("%s%s %d" % (name, labels(jail=j), num(f2b("get", j, key))))
            except Exception:
                pass
    h("fail2ban_banned_ip", "gauge", "Currently banned IP; value = ban start (unix seconds)")
    for j, ip, ts in banned:
        out.append("fail2ban_banned_ip%s %d" % (labels(jail=j, ip=ip, **geo(ip)), ts))
    h("fail2ban_ip_failures_24h", "gauge", "Failed attempts per IP in the last 24h (from fail2ban log)")
    for (j, ip), c in fails.items():
        out.append("fail2ban_ip_failures_24h%s %d" % (labels(jail=j, ip=ip, **geo(ip)), c))
    h("fail2ban_metrics_last_run_seconds", "gauge", "Unix time of the last collection")
    out.append("fail2ban_metrics_last_run_seconds %d" % time.time())

    tmp = os.path.join(OUT_DIR, ".fail2ban.prom.tmp")
    with open(tmp, "w") as fh:
        fh.write("\n".join(out) + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, os.path.join(OUT_DIR, "fail2ban.prom"))


if __name__ == "__main__":
    main()
COLLECTOR_EOF
chmod 755 /usr/local/lib/f2b-metrics/f2b-metrics.py

# find node_exporter's textfile directory
TFDIR="$(tr '\0' '\n' < /proc/$(pgrep -o -f prometheus-node-exporter || pgrep -o node_exporter || echo 1)/cmdline 2>/dev/null | sed -n 's/^--collector.textfile.directory=//p' | head -1)"
if [ -z "$TFDIR" ]; then
  TFDIR=/var/lib/prometheus/node-exporter
  F=/etc/default/prometheus-node-exporter; touch "$F"
  if ! grep -q 'collector.textfile.directory' "$F"; then
    if grep -q '^ARGS=' "$F"; then sed -i "s|^ARGS=\"\(.*\)\"|ARGS=\"\1 --collector.textfile.directory=$TFDIR\"|" "$F"
    else echo "ARGS=\"--collector.textfile.directory=$TFDIR\"" >> "$F"; fi
  fi
fi
mkdir -p "$TFDIR"
say "node_exporter textfile dir: $TFDIR"

cat > /etc/systemd/system/f2b-metrics.service <<SEOF
[Unit]
Description=Export fail2ban metrics for Prometheus
After=fail2ban.service
[Service]
Type=oneshot
ExecStart=/usr/bin/env python3 /usr/local/lib/f2b-metrics/f2b-metrics.py $TFDIR
SEOF
cat > /etc/systemd/system/f2b-metrics.timer <<'TEOF'
[Unit]
Description=Collect fail2ban metrics every 30s
[Timer]
OnBootSec=20s
OnUnitActiveSec=30s
AccuracySec=1s
[Install]
WantedBy=timers.target
TEOF
systemctl daemon-reload
systemctl start f2b-metrics.service || warn "first collection failed: journalctl -u f2b-metrics"
systemctl enable --now f2b-metrics.timer >/dev/null 2>&1
systemctl restart prometheus-node-exporter
sleep 3
if curl -s http://127.0.0.1:9100/metrics | grep -q '^fail2ban_up 1'; then say "node_exporter exposes fail2ban metrics ✔"
else warn "fail2ban metrics not visible on :9100 yet - check: curl -s localhost:9100/metrics | grep fail2ban"; fi

# ---------- 3. Prometheus config ----------
say "Configuring Prometheus (localhost only, 90 days retention)"
[ -f /etc/prometheus/prometheus.yml ] && cp -n /etc/prometheus/prometheus.yml /etc/prometheus/prometheus.yml.bak-before-f2b || true
cat > /etc/prometheus/prometheus.yml <<'PEOF'
global:
  scrape_interval: 30s
  evaluation_interval: 30s
scrape_configs:
  - job_name: prometheus
    static_configs:
      - targets: ['127.0.0.1:9090']
  - job_name: node
    static_configs:
      - targets: ['127.0.0.1:9100']
PEOF
F=/etc/default/prometheus; touch "$F"
sed -i '/^ARGS=/d' "$F"
echo 'ARGS="--web.listen-address=127.0.0.1:9090 --storage.tsdb.retention.time=90d"' >> "$F"
systemctl enable prometheus >/dev/null 2>&1; systemctl restart prometheus

# ---------- 4. Grafana ----------
if ! command -v grafana-server >/dev/null && [ ! -x /usr/sbin/grafana-server ] && [ ! -x /usr/share/grafana/bin/grafana ]; then
  say "Installing Grafana (official apt repo)"
  mkdir -p /etc/apt/keyrings
  curl -fsSL https://apt.grafana.com/gpg.key | gpg --dearmor --yes -o /etc/apt/keyrings/grafana.gpg
  echo "deb [signed-by=/etc/apt/keyrings/grafana.gpg] https://apt.grafana.com stable main" > /etc/apt/sources.list.d/grafana.list
  apt-get update -qq && apt-get install -y -qq grafana >/dev/null
fi
say "Provisioning Grafana datasource + dashboard"
mkdir -p /etc/grafana/provisioning/datasources /etc/grafana/provisioning/dashboards /var/lib/grafana/dashboards
cat > /etc/grafana/provisioning/datasources/f2b-prometheus.yaml <<'DEOF'
apiVersion: 1
datasources:
  - name: Prometheus
    uid: f2b-prometheus
    type: prometheus
    access: proxy
    url: http://127.0.0.1:9090
    isDefault: true
    jsonData:
      timeInterval: 30s
DEOF
cat > /etc/grafana/provisioning/dashboards/f2b.yaml <<'DEOF'
apiVersion: 1
providers:
  - name: fail2ban
    folder: Security
    type: file
    allowUiUpdates: true
    options:
      path: /var/lib/grafana/dashboards
DEOF
cat > /var/lib/grafana/dashboards/fail2ban.json <<'DASHBOARD_JSON_EOF'
{
 "uid": "fail2ban-overview",
 "title": "Fail2ban — Security Overview",
 "tags": [
  "fail2ban",
  "security"
 ],
 "timezone": "browser",
 "schemaVersion": 39,
 "version": 1,
 "editable": true,
 "graphTooltip": 1,
 "refresh": "30s",
 "time": {
  "from": "now-24h",
  "to": "now"
 },
 "templating": {
  "list": [
   {
    "name": "jail",
    "label": "Jail",
    "type": "query",
    "datasource": {
     "type": "prometheus",
     "uid": "f2b-prometheus"
    },
    "query": {
     "query": "label_values(fail2ban_jail_banned_current, jail)",
     "refId": "J"
    },
    "definition": "label_values(fail2ban_jail_banned_current, jail)",
    "refresh": 2,
    "multi": true,
    "includeAll": true,
    "allValue": ".*",
    "current": {
     "selected": true,
     "text": [
      "All"
     ],
     "value": [
      "$__all"
     ]
    },
    "sort": 1
   }
  ]
 },
 "annotations": {
  "list": []
 },
 "panels": [
  {
   "id": 1,
   "type": "stat",
   "title": "fail2ban",
   "datasource": {
    "type": "prometheus",
    "uid": "f2b-prometheus"
   },
   "gridPos": {
    "x": 0,
    "y": 0,
    "w": 4,
    "h": 4
   },
   "targets": [
    {
     "refId": "A",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "fail2ban_up",
     "instant": true,
     "legendFormat": "__auto"
    }
   ],
   "description": "Is the fail2ban server answering?",
   "fieldConfig": {
    "defaults": {
     "unit": "short",
     "color": {
      "mode": "fixed",
      "fixedColor": "green"
     },
     "mappings": [
      {
       "type": "value",
       "options": {
        "1": {
         "text": "RUNNING",
         "color": "green"
        },
        "0": {
         "text": "DOWN",
         "color": "red"
        }
       }
      }
     ],
     "thresholds": {
      "mode": "absolute",
      "steps": [
       {
        "color": "red",
        "value": null
       },
       {
        "color": "green",
        "value": 1
       }
      ]
     }
    },
    "overrides": []
   },
   "options": {
    "reduceOptions": {
     "calcs": [
      "lastNotNull"
     ],
     "fields": "",
     "values": false
    },
    "colorMode": "background",
    "graphMode": "none",
    "textMode": "value",
    "justifyMode": "center",
    "orientation": "auto"
   }
  },
  {
   "id": 2,
   "type": "stat",
   "title": "Banned now",
   "datasource": {
    "type": "prometheus",
    "uid": "f2b-prometheus"
   },
   "gridPos": {
    "x": 4,
    "y": 0,
    "w": 4,
    "h": 4
   },
   "targets": [
    {
     "refId": "A",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "sum(fail2ban_jail_banned_current{jail=~\"$jail\"})",
     "instant": true,
     "legendFormat": "__auto"
    }
   ],
   "description": "",
   "fieldConfig": {
    "defaults": {
     "unit": "short",
     "color": {
      "mode": "fixed",
      "fixedColor": "red"
     },
     "mappings": []
    },
    "overrides": []
   },
   "options": {
    "reduceOptions": {
     "calcs": [
      "lastNotNull"
     ],
     "fields": "",
     "values": false
    },
    "colorMode": "value",
    "graphMode": "none",
    "textMode": "value",
    "justifyMode": "center",
    "orientation": "auto"
   }
  },
  {
   "id": 3,
   "type": "stat",
   "title": "Failed attempts (24h)",
   "datasource": {
    "type": "prometheus",
    "uid": "f2b-prometheus"
   },
   "gridPos": {
    "x": 8,
    "y": 0,
    "w": 4,
    "h": 4
   },
   "targets": [
    {
     "refId": "A",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "sum(increase(fail2ban_jail_failed_total{jail=~\"$jail\"}[24h]))",
     "instant": true,
     "legendFormat": "__auto"
    }
   ],
   "description": "",
   "fieldConfig": {
    "defaults": {
     "unit": "short",
     "color": {
      "mode": "fixed",
      "fixedColor": "orange"
     },
     "mappings": []
    },
    "overrides": []
   },
   "options": {
    "reduceOptions": {
     "calcs": [
      "lastNotNull"
     ],
     "fields": "",
     "values": false
    },
    "colorMode": "value",
    "graphMode": "none",
    "textMode": "value",
    "justifyMode": "center",
    "orientation": "auto"
   }
  },
  {
   "id": 4,
   "type": "stat",
   "title": "New bans (24h)",
   "datasource": {
    "type": "prometheus",
    "uid": "f2b-prometheus"
   },
   "gridPos": {
    "x": 12,
    "y": 0,
    "w": 4,
    "h": 4
   },
   "targets": [
    {
     "refId": "A",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "sum(increase(fail2ban_jail_banned_total{jail=~\"$jail\"}[24h]))",
     "instant": true,
     "legendFormat": "__auto"
    }
   ],
   "description": "",
   "fieldConfig": {
    "defaults": {
     "unit": "short",
     "color": {
      "mode": "fixed",
      "fixedColor": "purple"
     },
     "mappings": []
    },
    "overrides": []
   },
   "options": {
    "reduceOptions": {
     "calcs": [
      "lastNotNull"
     ],
     "fields": "",
     "values": false
    },
    "colorMode": "value",
    "graphMode": "none",
    "textMode": "value",
    "justifyMode": "center",
    "orientation": "auto"
   }
  },
  {
   "id": 5,
   "type": "stat",
   "title": "Attacking IPs (24h)",
   "datasource": {
    "type": "prometheus",
    "uid": "f2b-prometheus"
   },
   "gridPos": {
    "x": 16,
    "y": 0,
    "w": 4,
    "h": 4
   },
   "targets": [
    {
     "refId": "A",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "count(fail2ban_ip_failures_24h{jail=~\"$jail\"}) or vector(0)",
     "instant": true,
     "legendFormat": "__auto"
    }
   ],
   "description": "",
   "fieldConfig": {
    "defaults": {
     "unit": "short",
     "color": {
      "mode": "fixed",
      "fixedColor": "yellow"
     },
     "mappings": []
    },
    "overrides": []
   },
   "options": {
    "reduceOptions": {
     "calcs": [
      "lastNotNull"
     ],
     "fields": "",
     "values": false
    },
    "colorMode": "value",
    "graphMode": "none",
    "textMode": "value",
    "justifyMode": "center",
    "orientation": "auto"
   }
  },
  {
   "id": 6,
   "type": "stat",
   "title": "Countries banned",
   "datasource": {
    "type": "prometheus",
    "uid": "f2b-prometheus"
   },
   "gridPos": {
    "x": 20,
    "y": 0,
    "w": 4,
    "h": 4
   },
   "targets": [
    {
     "refId": "A",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "count(count by (country) (fail2ban_banned_ip{jail=~\"$jail\"})) or vector(0)",
     "instant": true,
     "legendFormat": "__auto"
    }
   ],
   "description": "",
   "fieldConfig": {
    "defaults": {
     "unit": "short",
     "color": {
      "mode": "fixed",
      "fixedColor": "blue"
     },
     "mappings": []
    },
    "overrides": []
   },
   "options": {
    "reduceOptions": {
     "calcs": [
      "lastNotNull"
     ],
     "fields": "",
     "values": false
    },
    "colorMode": "value",
    "graphMode": "none",
    "textMode": "value",
    "justifyMode": "center",
    "orientation": "auto"
   }
  },
  {
   "id": 7,
   "type": "timeseries",
   "title": "Failed attempts per interval",
   "datasource": {
    "type": "prometheus",
    "uid": "f2b-prometheus"
   },
   "gridPos": {
    "x": 0,
    "y": 4,
    "w": 12,
    "h": 9
   },
   "targets": [
    {
     "refId": "A",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "sum by (jail) (increase(fail2ban_jail_failed_total{jail=~\"$jail\"}[$__interval]))",
     "legendFormat": "{{jail}}",
     "interval": "5m"
    }
   ],
   "fieldConfig": {
    "defaults": {
     "unit": "short",
     "custom": {
      "drawStyle": "bars",
      "fillOpacity": 70,
      "lineWidth": 1,
      "stacking": {
       "mode": "normal",
       "group": "A"
      },
      "showPoints": "never",
      "barAlignment": 0,
      "axisSoftMin": 0
     },
     "color": {
      "mode": "palette-classic"
     }
    },
    "overrides": []
   },
   "options": {
    "legend": {
     "displayMode": "list",
     "placement": "bottom",
     "showLegend": true
    },
    "tooltip": {
     "mode": "multi",
     "sort": "desc"
    }
   }
  },
  {
   "id": 8,
   "type": "timeseries",
   "title": "Bans per interval",
   "datasource": {
    "type": "prometheus",
    "uid": "f2b-prometheus"
   },
   "gridPos": {
    "x": 12,
    "y": 4,
    "w": 12,
    "h": 9
   },
   "targets": [
    {
     "refId": "A",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "sum by (jail) (increase(fail2ban_jail_banned_total{jail=~\"$jail\"}[$__interval]))",
     "legendFormat": "{{jail}}",
     "interval": "5m"
    }
   ],
   "fieldConfig": {
    "defaults": {
     "unit": "short",
     "custom": {
      "drawStyle": "bars",
      "fillOpacity": 70,
      "lineWidth": 1,
      "stacking": {
       "mode": "normal",
       "group": "A"
      },
      "showPoints": "never",
      "barAlignment": 0,
      "axisSoftMin": 0
     },
     "color": {
      "mode": "palette-classic"
     }
    },
    "overrides": []
   },
   "options": {
    "legend": {
     "displayMode": "list",
     "placement": "bottom",
     "showLegend": true
    },
    "tooltip": {
     "mode": "multi",
     "sort": "desc"
    }
   }
  },
  {
   "id": 9,
   "type": "timeseries",
   "title": "Currently banned IPs",
   "datasource": {
    "type": "prometheus",
    "uid": "f2b-prometheus"
   },
   "gridPos": {
    "x": 0,
    "y": 13,
    "w": 12,
    "h": 8
   },
   "targets": [
    {
     "refId": "A",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "fail2ban_jail_banned_current{jail=~\"$jail\"}",
     "legendFormat": "{{jail}}"
    }
   ],
   "fieldConfig": {
    "defaults": {
     "unit": "short",
     "custom": {
      "drawStyle": "line",
      "fillOpacity": 20,
      "lineWidth": 2,
      "stacking": {
       "mode": "none",
       "group": "A"
      },
      "showPoints": "never",
      "barAlignment": 0,
      "axisSoftMin": 0
     },
     "color": {
      "mode": "palette-classic"
     }
    },
    "overrides": []
   },
   "options": {
    "legend": {
     "displayMode": "list",
     "placement": "bottom",
     "showLegend": true
    },
    "tooltip": {
     "mode": "multi",
     "sort": "desc"
    }
   }
  },
  {
   "id": 10,
   "type": "timeseries",
   "title": "IPs currently failing (not banned yet)",
   "datasource": {
    "type": "prometheus",
    "uid": "f2b-prometheus"
   },
   "gridPos": {
    "x": 12,
    "y": 13,
    "w": 12,
    "h": 8
   },
   "targets": [
    {
     "refId": "A",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "fail2ban_jail_failed_current{jail=~\"$jail\"}",
     "legendFormat": "{{jail}}"
    }
   ],
   "fieldConfig": {
    "defaults": {
     "unit": "short",
     "custom": {
      "drawStyle": "line",
      "fillOpacity": 20,
      "lineWidth": 2,
      "stacking": {
       "mode": "none",
       "group": "A"
      },
      "showPoints": "never",
      "barAlignment": 0,
      "axisSoftMin": 0
     },
     "color": {
      "mode": "palette-classic"
     }
    },
    "overrides": []
   },
   "options": {
    "legend": {
     "displayMode": "list",
     "placement": "bottom",
     "showLegend": true
    },
    "tooltip": {
     "mode": "multi",
     "sort": "desc"
    }
   }
  },
  {
   "id": 11,
   "type": "geomap",
   "title": "Banned IPs by country",
   "datasource": {
    "type": "prometheus",
    "uid": "f2b-prometheus"
   },
   "gridPos": {
    "x": 0,
    "y": 21,
    "w": 15,
    "h": 13
   },
   "targets": [
    {
     "refId": "A",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "count by (country_code, country) (fail2ban_banned_ip{jail=~\"$jail\", country_code!=\"\"})",
     "instant": true,
     "format": "table",
     "legendFormat": "__auto"
    }
   ],
   "fieldConfig": {
    "defaults": {
     "unit": "short",
     "color": {
      "mode": "continuous-YlRd"
     }
    },
    "overrides": []
   },
   "options": {
    "view": {
     "id": "zero",
     "lat": 25,
     "lon": 10,
     "zoom": 1.4,
     "allLayers": true
    },
    "controls": {
     "showZoom": true,
     "mouseWheelZoom": true,
     "showAttribution": true
    },
    "basemap": {
     "type": "carto",
     "name": "Basemap",
     "config": {
      "theme": "dark",
      "showLabels": true
     }
    },
    "layers": [
     {
      "type": "markers",
      "name": "Banned IPs",
      "tooltip": true,
      "location": {
       "mode": "lookup",
       "lookup": "country_code",
       "gazetteer": "public/gazetteer/countries.json"
      },
      "config": {
       "showLegend": true,
       "style": {
        "size": {
         "field": "Value",
         "min": 6,
         "max": 40,
         "fixed": 6
        },
        "color": {
         "field": "Value"
        },
        "opacity": 0.65,
        "symbol": {
         "mode": "fixed",
         "fixed": "img/icons/marker/circle.svg"
        },
        "text": {
         "mode": "field",
         "field": "Value",
         "fixed": ""
        },
        "textConfig": {
         "fontSize": 11,
         "offsetX": 0,
         "offsetY": 0,
         "textAlign": "center",
         "textBaseline": "middle"
        }
       }
      }
     }
    ],
    "tooltip": {
     "mode": "details"
    }
   }
  },
  {
   "id": 12,
   "type": "bargauge",
   "title": "Top countries (banned IPs)",
   "datasource": {
    "type": "prometheus",
    "uid": "f2b-prometheus"
   },
   "gridPos": {
    "x": 15,
    "y": 21,
    "w": 9,
    "h": 13
   },
   "targets": [
    {
     "refId": "A",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "sort_desc(topk(15, count by (country) (fail2ban_banned_ip{jail=~\"$jail\"})))",
     "instant": true,
     "legendFormat": "{{country}}"
    }
   ],
   "fieldConfig": {
    "defaults": {
     "unit": "short",
     "min": 0,
     "color": {
      "mode": "continuous-YlRd"
     }
    },
    "overrides": []
   },
   "options": {
    "orientation": "horizontal",
    "displayMode": "gradient",
    "showUnfilled": true,
    "valueMode": "color",
    "namePlacement": "left",
    "sizing": "manual",
    "minVizHeight": 16,
    "maxVizHeight": 22,
    "reduceOptions": {
     "calcs": [
      "lastNotNull"
     ],
     "fields": "",
     "values": false
    }
   }
  },
  {
   "id": 13,
   "type": "table",
   "title": "Banned IPs",
   "datasource": {
    "type": "prometheus",
    "uid": "f2b-prometheus"
   },
   "gridPos": {
    "x": 0,
    "y": 34,
    "w": 14,
    "h": 14
   },
   "targets": [
    {
     "refId": "A",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "fail2ban_banned_ip{jail=~\"$jail\"} * 1000",
     "instant": true,
     "format": "table",
     "legendFormat": "__auto"
    }
   ],
   "transformations": [
    {
     "id": "organize",
     "options": {
      "excludeByName": {
       "Time": true,
       "__name__": true,
       "instance": true,
       "job": true,
       "country_code": true
      },
      "indexByName": {
       "ip": 0,
       "country": 1,
       "city": 2,
       "isp": 3,
       "asn": 4,
       "jail": 5,
       "Value": 6
      },
      "renameByName": {
       "ip": "IP",
       "jail": "Jail",
       "country": "Country",
       "country_code": "CC",
       "city": "City",
       "isp": "ISP",
       "asn": "ASN",
       "Value": "Banned since"
      }
     }
    }
   ],
   "fieldConfig": {
    "defaults": {
     "custom": {
      "align": "auto",
      "filterable": true,
      "cellOptions": {
       "type": "auto"
      }
     }
    },
    "overrides": [
     {
      "matcher": {
       "id": "byName",
       "options": "Banned since"
      },
      "properties": [
       {
        "id": "unit",
        "value": "dateTimeAsIso"
       }
      ]
     },
     {
      "matcher": {
       "id": "byName",
       "options": "IP"
      },
      "properties": [
       {
        "id": "custom.width",
        "value": 140
       }
      ]
     }
    ]
   },
   "options": {
    "showHeader": true,
    "cellHeight": "sm",
    "footer": {
     "show": true,
     "reducer": [
      "count"
     ],
     "countRows": true,
     "fields": ""
    },
    "sortBy": [
     {
      "displayName": "Banned since",
      "desc": true
     }
    ]
   }
  },
  {
   "id": 14,
   "type": "table",
   "title": "Top attacking IPs (failed attempts, last 24h)",
   "datasource": {
    "type": "prometheus",
    "uid": "f2b-prometheus"
   },
   "gridPos": {
    "x": 14,
    "y": 34,
    "w": 10,
    "h": 14
   },
   "targets": [
    {
     "refId": "A",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "topk(30, fail2ban_ip_failures_24h{jail=~\"$jail\"})",
     "instant": true,
     "format": "table",
     "legendFormat": "__auto"
    }
   ],
   "transformations": [
    {
     "id": "organize",
     "options": {
      "excludeByName": {
       "Time": true,
       "__name__": true,
       "instance": true,
       "job": true,
       "country_code": true,
       "city": true,
       "asn": true
      },
      "indexByName": {
       "ip": 0,
       "country": 1,
       "city": 2,
       "isp": 3,
       "asn": 4,
       "jail": 5,
       "Value": 6
      },
      "renameByName": {
       "ip": "IP",
       "jail": "Jail",
       "country": "Country",
       "country_code": "CC",
       "city": "City",
       "isp": "ISP",
       "asn": "ASN",
       "Value": "Attempts"
      }
     }
    }
   ],
   "fieldConfig": {
    "defaults": {
     "custom": {
      "align": "auto",
      "filterable": true,
      "cellOptions": {
       "type": "auto"
      }
     }
    },
    "overrides": [
     {
      "matcher": {
       "id": "byName",
       "options": "Attempts"
      },
      "properties": [
       {
        "id": "unit",
        "value": "short"
       },
       {
        "id": "custom.cellOptions",
        "value": {
         "type": "gauge",
         "mode": "gradient"
        }
       },
       {
        "id": "color",
        "value": {
         "mode": "continuous-YlRd"
        }
       }
      ]
     },
     {
      "matcher": {
       "id": "byName",
       "options": "IP"
      },
      "properties": [
       {
        "id": "custom.width",
        "value": 140
       }
      ]
     }
    ]
   },
   "options": {
    "showHeader": true,
    "cellHeight": "sm",
    "footer": {
     "show": true,
     "reducer": [
      "count"
     ],
     "countRows": true,
     "fields": ""
    },
    "sortBy": [
     {
      "displayName": "Attempts",
      "desc": true
     }
    ]
   }
  },
  {
   "id": 15,
   "type": "bargauge",
   "title": "Top ISPs / hosting providers (banned IPs)",
   "datasource": {
    "type": "prometheus",
    "uid": "f2b-prometheus"
   },
   "gridPos": {
    "x": 0,
    "y": 48,
    "w": 12,
    "h": 10
   },
   "targets": [
    {
     "refId": "A",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "sort_desc(topk(12, count by (isp) (fail2ban_banned_ip{jail=~\"$jail\", isp!=\"\"})))",
     "instant": true,
     "legendFormat": "{{isp}}"
    }
   ],
   "fieldConfig": {
    "defaults": {
     "unit": "short",
     "min": 0,
     "color": {
      "mode": "continuous-YlRd"
     }
    },
    "overrides": []
   },
   "options": {
    "orientation": "horizontal",
    "displayMode": "gradient",
    "showUnfilled": true,
    "valueMode": "color",
    "namePlacement": "left",
    "sizing": "manual",
    "minVizHeight": 16,
    "maxVizHeight": 22,
    "reduceOptions": {
     "calcs": [
      "lastNotNull"
     ],
     "fields": "",
     "values": false
    }
   }
  },
  {
   "id": 16,
   "type": "table",
   "title": "Jail settings",
   "datasource": {
    "type": "prometheus",
    "uid": "f2b-prometheus"
   },
   "gridPos": {
    "x": 12,
    "y": 48,
    "w": 12,
    "h": 10
   },
   "targets": [
    {
     "refId": "A",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "max by (jail) (fail2ban_jail_bantime_seconds{jail=~\"$jail\"})",
     "instant": true,
     "format": "table"
    },
    {
     "refId": "B",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "max by (jail) (fail2ban_jail_findtime_seconds{jail=~\"$jail\"})",
     "instant": true,
     "format": "table"
    },
    {
     "refId": "C",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "max by (jail) (fail2ban_jail_maxretry{jail=~\"$jail\"})",
     "instant": true,
     "format": "table"
    },
    {
     "refId": "D",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "max by (jail) (fail2ban_jail_banned_current{jail=~\"$jail\"})",
     "instant": true,
     "format": "table"
    },
    {
     "refId": "E",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "max by (jail) (fail2ban_jail_banned_total{jail=~\"$jail\"})",
     "instant": true,
     "format": "table"
    },
    {
     "refId": "F",
     "datasource": {
      "type": "prometheus",
      "uid": "f2b-prometheus"
     },
     "expr": "max by (jail) (fail2ban_jail_failed_total{jail=~\"$jail\"})",
     "instant": true,
     "format": "table"
    }
   ],
   "transformations": [
    {
     "id": "merge",
     "options": {}
    },
    {
     "id": "organize",
     "options": {
      "excludeByName": {
       "Time": true,
       "instance": true,
       "job": true
      },
      "renameByName": {
       "jail": "Jail",
       "Value #A": "Ban time",
       "Value #B": "Find time",
       "Value #C": "Max retry",
       "Value #D": "Banned now",
       "Value #E": "Total bans",
       "Value #F": "Total failures"
      }
     }
    }
   ],
   "fieldConfig": {
    "defaults": {
     "custom": {
      "align": "auto"
     }
    },
    "overrides": [
     {
      "matcher": {
       "id": "byName",
       "options": "Ban time"
      },
      "properties": [
       {
        "id": "unit",
        "value": "s"
       }
      ]
     },
     {
      "matcher": {
       "id": "byName",
       "options": "Find time"
      },
      "properties": [
       {
        "id": "unit",
        "value": "s"
       }
      ]
     },
     {
      "matcher": {
       "id": "byName",
       "options": "Ban time"
      },
      "properties": [
       {
        "id": "mappings",
        "value": [
         {
          "type": "value",
          "options": {
           "-1": {
            "text": "♾ permanent",
            "color": "red"
           }
          }
         }
        ]
       }
      ]
     }
    ]
   },
   "options": {
    "showHeader": true,
    "cellHeight": "sm"
   },
   "description": "Values in seconds; ban time -1 = permanent. Totals reset when fail2ban restarts."
  }
 ]
}
DASHBOARD_JSON_EOF
chown -R grafana:grafana /var/lib/grafana/dashboards
F=/etc/default/grafana-server; touch "$F"
sed -i '/^GF_/d' "$F"
cat >> "$F" <<GEOF
GF_SERVER_HTTP_PORT=$GRAFANA_PORT
GF_USERS_ALLOW_SIGN_UP=false
GF_AUTH_ANONYMOUS_ENABLED=false
GF_ANALYTICS_REPORTING_ENABLED=false
GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH=/var/lib/grafana/dashboards/fail2ban.json
GEOF
systemctl daemon-reload
systemctl enable grafana-server >/dev/null 2>&1; systemctl restart grafana-server
say "Waiting for Grafana to start…"
for i in $(seq 1 60); do curl -sf "http://127.0.0.1:$GRAFANA_PORT/api/health" >/dev/null && break; sleep 2; done

NEWPASS=""
if curl -sf -u admin:admin "http://127.0.0.1:$GRAFANA_PORT/api/user" >/dev/null; then
  NEWPASS="${GRAFANA_PASS:-$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 20)}"
  curl -sf -u admin:admin -X PUT -H 'Content-Type: application/json' \
    "http://127.0.0.1:$GRAFANA_PORT/api/user/password" \
    -d "{\"oldPassword\":\"admin\",\"newPassword\":\"$NEWPASS\",\"confirmNew\":\"$NEWPASS\"}" >/dev/null \
    || { warn "Could not set the admin password automatically - change it at first login"; NEWPASS=""; }
fi

# ---------- 5. firewall ----------
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then ufw allow "$GRAFANA_PORT"/tcp >/dev/null; fi

PUBIP="$(curl -4 -s --max-time 4 https://api.ipify.org || hostname -I | awk '{print $1}')"
echo
echo -e "${G}==================================================================${N}"
echo -e "  Grafana:  ${G}http://${PUBIP}:${GRAFANA_PORT}/${N}   (dashboard: Security › Fail2ban — Security Overview)"
if [ -n "$NEWPASS" ]; then echo -e "  Login:    ${Y}admin${N} / ${Y}${NEWPASS}${N}    <- save it now!"
else echo -e "  Login:    admin / (your existing Grafana password)"; fi
echo -e "  Prometheus: 127.0.0.1:9090 (local only)   Metrics: curl -s localhost:9100/metrics | grep ^fail2ban"
echo -e "${G}==================================================================${N}"
F2B_GRAFANA_INSTALLER_EOF
bash /root/f2b-grafana-install.sh
