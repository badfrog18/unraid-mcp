# unraid-mcp

MCP-Server, der Claude Zugriff auf den Unraid-Server gibt – als Docker-Container direkt auf Unraid.

| Quelle | Wofür |
|---|---|
| Unraid-GraphQL-API (ab 7.2) | System, Array/Disks, Docker-Übersicht, Benachrichtigungen |
| Docker-Socket | Container-Liste mit Restart-Zähler, Logs, Inspect, Stats, Update-Check, Neustart/Start/Stop |
| `docker exec` im CrowdSec-Container | `cscli`-Befehle – **nur lesende**, per Allowlist |

**Rechte:** lesen + Container steuern. Keine beliebigen Shell-Befehle, keine GraphQL-Mutations, keine ändernden `cscli`-Befehle. Container in `PROTECTED_CONTAINERS` können nicht gestoppt werden.

## Tools

| Tool | Zweck |
|---|---|
| `unraid_overview` | OS, Array, Disks/Temperaturen, Container, ungelesene Meldungen |
| `unraid_graphql` | freie Lese-Abfrage gegen die Unraid-API (Schema-Erkundung) |
| `docker_list_containers` | Status, Uptime, **RestartCount**, Health |
| `docker_logs` | Logs mit `tail`, `since` (`15m`, `2h`), `grep` |
| `docker_inspect` | Konfig, Health-Ausgabe, Mounts, Env (Geheimnisse maskiert) |
| `docker_stats` | CPU/RAM je Container |
| `docker_check_updates` | Neuere Image-Version in der Registry? (6 h Cache, `force` ignoriert ihn; Unraid-Anzeige zum Vergleich) |
| `docker_restart` / `docker_start` / `docker_stop` | Steuerung |
| `crowdsec_cscli` | z.B. `metrics`, `bouncers list`, `decisions list`, `alerts list`, `lapi status` |
| `crowdsec_diagnose` | Komplett-Check: Restarts, LAPI/CAPI, Bouncer-Abruf, Sperren je Herkunft, Bouncer-Log (Fehler / Anlegen von Gruppen & Regeln) |

## Einrichtung

### 1. Unraid-API-Key erstellen
*Einstellungen → Management Access → API Keys → Create*, Rolle **Viewer**.
Alternativ im Unraid-Terminal:
```bash
unraid-api apikey --create --name "unraid-mcp" --roles VIEWER --json
```

### 2. Token für Claude erzeugen
```bash
openssl rand -hex 32
```

### 3. Image bereitstellen – eine der beiden Varianten

**A) GitHub (empfohlen):** Repo `badfrog18/unraid-mcp` anlegen und pushen. Die Action baut automatisch `ghcr.io/badfrog18/unraid-mcp:latest`. Das Paket danach unter *GitHub → Packages → unraid-mcp → Settings* auf **public** stellen (oder auf Unraid `docker login ghcr.io`).

**B) Direkt auf Unraid bauen:** Ordner nach `/mnt/user/appdata/unraid-mcp/src` kopieren, dann:
```bash
cd /mnt/user/appdata/unraid-mcp/src && docker build -t unraid-mcp:local .
```
Im Template dann `Repository` = `unraid-mcp:local`.

### 4. Container anlegen
`unraid-mcp.xml` nach `/boot/config/plugins/dockerMan/templates-user/my-unraid-mcp.xml` kopieren.
*Docker → Add Container → Template „unraid-mcp“* wählen, Token und API-Key eintragen, ggf. `BOUNCER_CONTAINER` setzen → Apply.

Oder per CLI:
```bash
docker run -d --name unraid-mcp --restart unless-stopped -p 8790:8790 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e MCP_AUTH_TOKEN=DEIN_TOKEN \
  -e UNRAID_API_URL=http://192.168.178.60/graphql \
  -e UNRAID_API_KEY=DEIN_API_KEY \
  -e CROWDSEC_CONTAINER=crowdsec \
  ghcr.io/badfrog18/unraid-mcp:latest
```

Test: `curl http://192.168.178.60:8790/health` → `{"status":"ok"}`

> Leitet Unraid HTTP auf HTTPS um, `UNRAID_API_URL` auf die https-Adresse setzen; bei selbstsigniertem Zertifikat zusätzlich `UNRAID_VERIFY_TLS=false`.

### 5. Claude Desktop (Windows) verbinden
In `%APPDATA%\Claude\claude_desktop_config.json` unter `mcpServers` ergänzen:
```json
"unraid": {
  "command": "npx",
  "args": [
    "-y", "mcp-remote",
    "http://192.168.178.60:8790/mcp",
    "--allow-http",
    "--header", "Authorization:${UNRAID_MCP_AUTH}"
  ],
  "env": { "UNRAID_MCP_AUTH": "Bearer DEIN_TOKEN" }
}
```
(Die Variable umgeht das Windows-Problem mit Leerzeichen in Argumenten.) Claude Desktop neu starten.

## Sicherheit
* Der Docker-Socket ist mächtig – der Server selbst lässt aber nur die oben genannten Aktionen zu und ist nur mit Token erreichbar.
* Nicht über Cloudflare Tunnel nach außen freigeben; LAN/Tailscale reicht.
* Strenger: [docker-socket-proxy](https://github.com/Tecnativa/docker-socket-proxy) mit `CONTAINERS=1 IMAGES=1 DISTRIBUTION=1 POST=1 EXEC=1` davorschalten und `DOCKER_HOST=tcp://socket-proxy:2375` setzen.

## Lokal testen
```bash
pip install -r requirements.txt
MCP_AUTH_TOKEN=test UNRAID_API_URL=http://192.168.178.60/graphql UNRAID_API_KEY=... python server.py
```
