"""
unraid-mcp – MCP-Server für Unraid (Hybrid)

  * Unraid GraphQL-API (ab Unraid 7.2)  → System, Array, Docker-Übersicht, Benachrichtigungen
  * Docker-Socket                        → Container-Logs, Inspect, Stats, Neustart/Start/Stop
  * docker exec (nur Allowlist)          → CrowdSec `cscli` Lese-Befehle

Rechte-Modell: lesen + Container steuern. Keine beliebigen Befehle, keine GraphQL-Mutations.
Transport: Streamable HTTP unter /mcp, abgesichert per Bearer-Token.
"""

from __future__ import annotations

import csv
import hmac
import io
import json
import logging
import os
import re
from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any

import anyio
import docker
import httpx
from docker.errors import DockerException, NotFound
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

# --------------------------------------------------------------------------- Konfiguration

UNRAID_API_URL = os.getenv("UNRAID_API_URL", "")  # z.B. http://192.168.178.60/graphql
UNRAID_API_KEY = os.getenv("UNRAID_API_KEY", "")
UNRAID_VERIFY_TLS = os.getenv("UNRAID_VERIFY_TLS", "true").lower() in ("1", "true", "yes")

MCP_AUTH_TOKEN = os.getenv("MCP_AUTH_TOKEN", "")
ALLOW_NO_AUTH = os.getenv("ALLOW_NO_AUTH", "false").lower() in ("1", "true", "yes")
MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("MCP_PORT", "8790"))

CROWDSEC_CONTAINER = os.getenv("CROWDSEC_CONTAINER", "crowdsec")
BOUNCER_CONTAINER = os.getenv("BOUNCER_CONTAINER", "")  # leer = automatisch suchen (*bouncer*)

# Container, die über MCP NICHT gestoppt/neu gestartet werden dürfen
PROTECTED_CONTAINERS = {
    c.strip().lower()
    for c in os.getenv("PROTECTED_CONTAINERS", "unraid-mcp").split(",")
    if c.strip()
}

MAX_OUTPUT_CHARS = int(os.getenv("MAX_OUTPUT_CHARS", "60000"))

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"), format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("unraid-mcp")

SENSITIVE_ENV = re.compile(r"(KEY|PASS|PWD|TOKEN|SECRET|CREDENTIAL|AUTH|PRIVATE)", re.I)

# --------------------------------------------------------------------------- Hilfsfunktionen


def _truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> str:
    if len(text) <= limit:
        return text
    return f"[... gekürzt: {len(text) - limit} Zeichen am Anfang ausgelassen ...]\n" + text[-limit:]


def _docker() -> docker.DockerClient:
    # DOCKER_HOST wird respektiert (z.B. tcp://docker-socket-proxy:2375)
    return docker.from_env(timeout=30)


def _get_container(client: docker.DockerClient, name: str):
    try:
        return client.containers.get(name)
    except NotFound:
        # Unscharfe Suche (Groß/Klein, Teilstring)
        matches = [c for c in client.containers.list(all=True) if name.lower() in c.name.lower()]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise ValueError(f"Container '{name}' nicht gefunden.")
        raise ValueError(
            f"'{name}' ist mehrdeutig: " + ", ".join(sorted(c.name for c in matches))
        )


def _mask_env(env: list[str]) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in env or []:
        k, _, v = item.partition("=")
        out[k] = "***" if SENSITIVE_ENV.search(k) else v
    return out


def _mask_cmd(cmd: list[str] | None) -> list[str] | None:
    """Maskiert Geheimnisse in Startargumenten (--token X, --password=X, lange Token-Strings)."""
    if not cmd:
        return cmd
    out: list[str] = []
    hide_next = False
    for arg in cmd:
        if hide_next:
            out.append("***")
            hide_next = False
            continue
        if arg.startswith("-") and SENSITIVE_ENV.search(arg):
            if "=" in arg:
                out.append(arg.split("=", 1)[0] + "=***")
            else:
                out.append(arg)
                hide_next = True
            continue
        if len(arg) >= 40 and re.fullmatch(r"[A-Za-z0-9_\-+/=.]+", arg):
            out.append("***")
            continue
        out.append(arg)
    return out


def _parse_since(since: str | None) -> datetime | None:
    """'15m', '2h', '1d' oder ISO-Zeitpunkt → datetime (UTC)."""
    if not since:
        return None
    m = re.fullmatch(r"(\d+)\s*([smhd])", since.strip())
    if m:
        n, unit = int(m.group(1)), m.group(2)
        delta = {"s": timedelta(seconds=n), "m": timedelta(minutes=n), "h": timedelta(hours=n), "d": timedelta(days=n)}[unit]
        return datetime.now(timezone.utc) - delta
    return datetime.fromisoformat(since.replace("Z", "+00:00"))


async def _run(fn, *args):
    """Blockierende Docker-Arbeit im Thread ausführen; Fehler lesbar an Claude melden."""
    try:
        return await anyio.to_thread.run_sync(fn, *args)
    except ToolError:
        raise
    except ValueError as e:
        raise ToolError(str(e)) from e
    except DockerException as e:
        raise ToolError(f"Docker-Fehler: {e}. Ist /var/run/docker.sock gemountet (bzw. DOCKER_HOST korrekt)?") from e


async def _graphql(query: str, variables: dict | None = None) -> dict:
    if not UNRAID_API_URL or not UNRAID_API_KEY:
        raise RuntimeError("UNRAID_API_URL / UNRAID_API_KEY sind nicht gesetzt.")
    async with httpx.AsyncClient(verify=UNRAID_VERIFY_TLS, timeout=30) as client:
        r = await client.post(
            UNRAID_API_URL,
            json={"query": query, "variables": variables or {}},
            headers={"x-api-key": UNRAID_API_KEY, "Content-Type": "application/json"},
        )
        r.raise_for_status()
        return r.json()


# --------------------------------------------------------------------------- MCP-Server

mcp = MCPServer(
    name="unraid",
    version="0.2.1",
    instructions=(
        "Zugriff auf den Unraid-Server: Systemstatus und Array über die Unraid-GraphQL-API, "
        "Docker-Container (Logs, Inspect, Stats, Neustart) über den Docker-Socket und "
        "CrowdSec-Diagnose über erlaubte cscli-Lesebefehle. Für CrowdSec-Probleme zuerst "
        "crowdsec_diagnose aufrufen."
    ),
)

RO = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
CONTROL = ToolAnnotations(readOnlyHint=False, destructiveHint=True, idempotentHint=False, openWorldHint=False)


# ---------------------------------------------------------------- GraphQL (Unraid-API)


@mcp.tool(annotations=RO)
async def unraid_overview() -> str:
    """Überblick über den Unraid-Server: OS/Version, Array-Status, Disks (Status/Temperatur),
    Docker-Container und ungelesene Benachrichtigungen. Nutzt die Unraid-GraphQL-API."""
    parts = {
        "info": "info { os { hostname distro release uptime } cpu { brand cores threads } versions { core { unraid } } }",
        "array": "array { state capacity { kilobytes { free used total } } "
                 "disks { name status temp numErrors } parities { name status temp } caches { name status temp } }",
        "docker": "docker { containers { names state status autoStart image } }",
        "notifications": "notifications { overview { unread { info warning alert total } } }",
    }
    result: dict[str, Any] = {}
    # Einzeln abfragen, damit ein Schemaunterschied nicht alles blockiert
    for key, q in parts.items():
        try:
            data = await _graphql("query { " + q + " }")
            if data.get("errors"):
                result[key] = {"fehler": [e.get("message") for e in data["errors"]]}
            if data.get("data"):
                result.update(data["data"])
        except Exception as e:  # noqa: BLE001
            result[key] = {"fehler": str(e)}
    return _truncate(json.dumps(result, indent=1, ensure_ascii=False, default=str))


_FORBIDDEN_GQL = re.compile(r"\b(mutation|subscription)\b", re.I)


@mcp.tool(annotations=RO)
async def unraid_graphql(query: str, variables: dict | None = None) -> str:
    """Freie, NUR LESENDE GraphQL-Abfrage gegen die Unraid-API (Mutations sind gesperrt).
    Tipp: Schema erkunden mit `{ __schema { queryType { fields { name } } } }` oder
    `{ __type(name: "Docker") { fields { name type { name kind ofType { name } } } } }`."""
    stripped = re.sub(r"#.*", "", query)
    if _FORBIDDEN_GQL.search(stripped):
        return "Abgelehnt: Mutations/Subscriptions sind über dieses Tool nicht erlaubt."
    try:
        data = await _graphql(query, variables)
    except (httpx.HTTPError, RuntimeError) as e:
        raise ToolError(f"Unraid-API nicht erreichbar: {e}") from e
    return _truncate(json.dumps(data, indent=1, ensure_ascii=False, default=str))


# ---------------------------------------------------------------- Docker (Socket)


@mcp.tool(annotations=RO)
async def docker_list_containers(all: bool = True, name_filter: str | None = None) -> str:
    """Listet Docker-Container mit Status, Uptime, Restart-Zähler, Healthcheck und Image.
    Ein hoher RestartCount oder kurze Uptime deutet auf eine Neustart-Schleife hin."""

    def work() -> list[dict]:
        client = _docker()
        rows = []
        for c in client.containers.list(all=all):
            if name_filter and name_filter.lower() not in c.name.lower():
                continue
            a = c.attrs
            st = a.get("State", {})
            rows.append({
                "name": c.name,
                "status": st.get("Status"),
                "gestartet": st.get("StartedAt"),
                "restart_count": a.get("RestartCount"),
                "health": (st.get("Health") or {}).get("Status"),
                "exit_code": st.get("ExitCode"),
                "image": a.get("Config", {}).get("Image"),
                "restart_policy": a.get("HostConfig", {}).get("RestartPolicy", {}).get("Name"),
            })
        return sorted(rows, key=lambda r: r["name"])

    rows = await _run(work)
    return json.dumps(rows, indent=1, ensure_ascii=False)


@mcp.tool(annotations=RO)
async def docker_logs(
    container: str,
    tail: int = 200,
    since: str | None = None,
    grep: str | None = None,
    timestamps: bool = True,
) -> str:
    """Liest Container-Logs. `since` z.B. '15m', '2h', '1d' oder ISO-Zeit.
    `grep` = Regex-Filter (Groß/Klein egal), wird nach dem Holen angewendet."""
    tail = max(1, min(tail, 5000))

    def work() -> str:
        client = _docker()
        c = _get_container(client, container)
        kwargs: dict[str, Any] = {"tail": tail if not grep else max(tail, 2000), "timestamps": timestamps}
        s = _parse_since(since)
        if s:
            kwargs["since"] = s
        raw = c.logs(stdout=True, stderr=True, **kwargs).decode("utf-8", errors="replace")
        lines = raw.splitlines()
        if grep:
            rx = re.compile(grep, re.I)
            lines = [line for line in lines if rx.search(line)][-tail:]
        header = f"# {c.name} – {len(lines)} Zeilen" + (f" (Filter: {grep})" if grep else "") + "\n"
        return header + "\n".join(lines)

    return _truncate(await _run(work))


@mcp.tool(annotations=RO)
async def docker_inspect(container: str) -> str:
    """Kompakte Konfiguration eines Containers: Status, Restart-Infos, Healthcheck-Ausgabe,
    Ports, Mounts, Netzwerke, Umgebungsvariablen (Geheimnisse werden maskiert)."""

    def work() -> dict:
        client = _docker()
        c = _get_container(client, container)
        a = c.attrs
        st = a.get("State", {})
        health = st.get("Health") or {}
        return {
            "name": c.name,
            "image": a.get("Config", {}).get("Image"),
            "erstellt": a.get("Created"),
            "state": {k: st.get(k) for k in ("Status", "Running", "Restarting", "OOMKilled", "ExitCode", "Error", "StartedAt", "FinishedAt")},
            "restart_count": a.get("RestartCount"),
            "restart_policy": a.get("HostConfig", {}).get("RestartPolicy"),
            "health": {"status": health.get("Status"), "failing_streak": health.get("FailingStreak"),
                        "letzte_checks": [h.get("Output", "")[-300:] for h in (health.get("Log") or [])[-3:]]},
            "ports": a.get("NetworkSettings", {}).get("Ports"),
            "netzwerke": list((a.get("NetworkSettings", {}).get("Networks") or {}).keys()),
            "mounts": [f'{m.get("Source")} -> {m.get("Destination")} ({"rw" if m.get("RW") else "ro"})' for m in a.get("Mounts", [])],
            "env": _mask_env(a.get("Config", {}).get("Env", [])),
            "cmd": _mask_cmd(a.get("Config", {}).get("Cmd")),
            "labels_unraid": {k: v for k, v in (a.get("Config", {}).get("Labels") or {}).items() if "unraid" in k.lower()},
        }

    return json.dumps(await _run(work), indent=1, ensure_ascii=False, default=str)


@mcp.tool(annotations=RO)
async def docker_stats(name_filter: str | None = None) -> str:
    """CPU- und RAM-Verbrauch der laufenden Container (Momentaufnahme)."""

    def work() -> list[dict]:
        client = _docker()
        rows = []
        for c in client.containers.list():
            if name_filter and name_filter.lower() not in c.name.lower():
                continue
            s = c.stats(stream=False)
            cpu = s.get("cpu_stats", {})
            pre = s.get("precpu_stats", {})
            cpu_delta = cpu.get("cpu_usage", {}).get("total_usage", 0) - pre.get("cpu_usage", {}).get("total_usage", 0)
            sys_delta = cpu.get("system_cpu_usage", 0) - pre.get("system_cpu_usage", 0)
            ncpu = cpu.get("online_cpus") or len(cpu.get("cpu_usage", {}).get("percpu_usage") or [1])
            cpu_pct = (cpu_delta / sys_delta * ncpu * 100) if sys_delta > 0 else 0.0
            mem = s.get("memory_stats", {})
            usage = mem.get("usage", 0) - (mem.get("stats", {}) or {}).get("inactive_file", 0)
            rows.append({
                "name": c.name,
                "cpu_%": round(cpu_pct, 1),
                "ram_mb": round(usage / 1048576, 1),
                "ram_limit_mb": round(mem.get("limit", 0) / 1048576),
            })
        return sorted(rows, key=lambda r: r["cpu_%"], reverse=True)

    return json.dumps(await _run(work), indent=1, ensure_ascii=False)


_UPDATE_CACHE: dict[str, tuple[float, dict]] = {}
UPDATE_CACHE_SECONDS = int(os.getenv("UPDATE_CACHE_SECONDS", "21600"))  # 6 h, schont Registry-Limits


def _check_image_sync(client: docker.DockerClient, image_ref: str, image_id: str) -> dict:
    """Vergleicht den lokalen Digest mit dem aktuellen Digest in der Registry.
    Die Abfrage läuft über den Docker-Daemon (/distribution), nutzt also dessen Registry-Logins."""
    import time

    key = f"{image_ref}|{image_id}"
    hit = _UPDATE_CACHE.get(key)
    if hit and time.time() - hit[0] < UPDATE_CACHE_SECONDS:
        return {**hit[1], "aus_cache": True}

    result: dict[str, Any] = {"image": image_ref}
    if image_ref.startswith("sha256:") or "@sha256:" in image_ref:
        result["status"] = "fixiert"  # per Digest gepinnt, kein Tag zum Vergleichen
        return result
    try:
        local = client.images.get(image_id)
        repo_digests = [d.split("@", 1)[1] for d in (local.attrs.get("RepoDigests") or []) if "@" in d]
        result["erstellt"] = local.attrs.get("Created", "")[:19]
    except NotFound:
        repo_digests = []
    if not repo_digests:
        result["status"] = "lokal gebaut / unbekannt"
        return result
    try:
        remote = client.images.get_registry_data(image_ref)
        remote_digest = remote.id
    except DockerException as e:
        result["status"] = "fehler"
        result["fehler"] = str(e)[:200]
        return result
    result["status"] = "aktuell" if remote_digest in repo_digests else "update verfügbar"
    result["lokal"] = repo_digests[0][:19]
    result["registry"] = remote_digest[:19]
    _UPDATE_CACHE[key] = (time.time(), result)
    return result


@mcp.tool(annotations=RO)
async def docker_check_updates(name_filter: str | None = None, force: bool = False) -> str:
    """Prüft für alle (oder gefilterte) Container, ob in der Registry eine neuere Image-Version
    unter demselben Tag liegt. Ergebnisse werden 6 h zwischengespeichert (force=true ignoriert
    den Cache). Wenn die Unraid-API eine eigene Update-Anzeige liefert, steht sie zum Vergleich daneben."""
    if force:
        _UPDATE_CACHE.clear()

    def collect() -> tuple[docker.DockerClient, list]:
        client = _docker()
        cs = [c for c in client.containers.list(all=True)
              if not name_filter or name_filter.lower() in c.name.lower()]
        return client, cs

    client, containers = await _run(collect)

    # Je Image nur einmal abfragen, max. 4 parallel
    by_image: dict[tuple[str, str], list[str]] = {}
    for c in containers:
        ref = c.attrs.get("Config", {}).get("Image", "")
        by_image.setdefault((ref, c.attrs.get("Image", "")), []).append(c.name)

    results: dict[tuple[str, str], dict] = {}
    limiter = anyio.CapacityLimiter(4)

    async def one(key: tuple[str, str]):
        results[key] = await anyio.to_thread.run_sync(_check_image_sync, client, key[0], key[1], limiter=limiter)

    async with anyio.create_task_group() as tg:
        for key in by_image:
            tg.start_soon(one, key)

    # Unraid-eigene Anzeige (optional, Feld kann je nach Version fehlen/null sein)
    unraid_flags: dict[str, Any] = {}
    if UNRAID_API_URL and UNRAID_API_KEY:
        try:
            data = await _graphql("query { docker { containers { names isUpdateAvailable } } }")
            for c in ((data.get("data") or {}).get("docker") or {}).get("containers") or []:
                for n in c.get("names") or []:
                    unraid_flags[n.lstrip("/")] = c.get("isUpdateAvailable")
        except Exception:  # noqa: BLE001
            pass

    rows = []
    for key, names in by_image.items():
        for n in names:
            row = {"container": n, **results[key]}
            if unraid_flags.get(n) is not None:
                row["unraid_meldet_update"] = unraid_flags[n]
            rows.append(row)
    order = {"update verfügbar": 0, "fehler": 1, "lokal gebaut / unbekannt": 2, "fixiert": 3, "aktuell": 4}
    rows.sort(key=lambda r: (order.get(r.get("status"), 9), r["container"]))
    summary = Counter(r.get("status") for r in rows)
    return json.dumps({"zusammenfassung": dict(summary), "container": rows}, indent=1, ensure_ascii=False)


async def _control(container: str, action: str) -> str:
    def work() -> str:
        client = _docker()
        c = _get_container(client, container)
        if c.name.lower() in PROTECTED_CONTAINERS:
            return f"Abgelehnt: '{c.name}' ist geschützt (PROTECTED_CONTAINERS)."
        getattr(c, action)()
        c.reload()
        log.warning("Container %s: %s ausgeführt → %s", c.name, action, c.status)
        return f"{c.name}: {action} ausgeführt, Status jetzt '{c.status}'."

    return await _run(work)


@mcp.tool(annotations=CONTROL)
async def docker_restart(container: str) -> str:
    """Startet einen Container neu."""
    return await _control(container, "restart")


@mcp.tool(annotations=CONTROL)
async def docker_start(container: str) -> str:
    """Startet einen gestoppten Container."""
    return await _control(container, "start")


@mcp.tool(annotations=CONTROL)
async def docker_stop(container: str) -> str:
    """Stoppt einen Container."""
    return await _control(container, "stop")


# ---------------------------------------------------------------- CrowdSec (cscli, nur lesen)

# Erlaubte Befehle (erste ein bis zwei Wörter). Alles hier ist rein lesend.
CSCLI_ALLOWED: set[tuple[str, ...]] = {
    ("version",),
    ("metrics",),
    ("decisions", "list"),
    ("alerts", "list"),
    ("alerts", "inspect"),
    ("bouncers", "list"),
    ("machines", "list"),
    ("hub", "list"),
    ("collections", "list"),
    ("parsers", "list"),
    ("scenarios", "list"),
    ("postoverflows", "list"),
    ("appsec-configs", "list"),
    ("appsec-rules", "list"),
    ("lapi", "status"),
    ("capi", "status"),
    ("console", "status"),
    ("allowlists", "list"),
}
CSCLI_FLAGS = {
    "-o", "--output", "-l", "--limit", "--origin", "--type", "--scope", "--value", "-v",
    "-i", "--ip", "-r", "--range", "--since", "--until", "-a", "--all", "-s", "--scenario",
    "--contained", "-d", "--details",
}
CSCLI_VALUE = re.compile(r"^[A-Za-z0-9_.:/,@=+-]{1,128}$")


def _validate_cscli(args: list[str]) -> str | None:
    if not args:
        return "Leerer Befehl."
    words = [a for a in args if not a.startswith("-")]
    head2 = tuple(words[:2])
    head1 = tuple(words[:1])
    if head1 == ("metrics",):
        # 'metrics', 'metrics show bouncers', 'metrics list' …
        if any(w in ("delete", "add", "remove", "set", "install") for w in words):
            return "Abgelehnt."
    elif head2 not in CSCLI_ALLOWED and head1 not in CSCLI_ALLOWED:
        return f"Nicht erlaubt: {' '.join(words[:2])}. Erlaubt: " + ", ".join(sorted(" ".join(x) for x in CSCLI_ALLOWED))
    for a in args:
        if a.startswith("-"):
            flag = a.split("=", 1)[0]
            if flag not in CSCLI_FLAGS:
                return f"Flag nicht erlaubt: {flag}"
            if "=" in a and not CSCLI_VALUE.match(a.split("=", 1)[1]):
                return f"Ungültiger Wert: {a}"
        elif not CSCLI_VALUE.match(a):
            return f"Ungültiges Argument: {a}"
    return None


def _exec_cscli_sync(args: list[str]) -> tuple[int, str]:
    client = _docker()
    c = _get_container(client, CROWDSEC_CONTAINER)
    if c.status != "running":
        return 1, f"CrowdSec-Container '{c.name}' läuft nicht (Status: {c.status})."
    res = c.exec_run(["cscli", *args], stdout=True, stderr=True, demux=False,
                     environment={"NO_COLOR": "1", "TERM": "dumb"})
    return res.exit_code, (res.output or b"").decode("utf-8", errors="replace")


@mcp.tool(annotations=RO)
async def crowdsec_cscli(args: list[str]) -> str:
    """Führt einen erlaubten, rein lesenden `cscli`-Befehl im CrowdSec-Container aus.
    Beispiele: ["metrics"], ["bouncers","list"], ["decisions","list","--origin","crowdsec"],
    ["alerts","list","-l","20"], ["lapi","status"], ["capi","status"], ["hub","list"].
    Ändernde Befehle (add/delete/install …) sind gesperrt."""
    err = _validate_cscli(args)
    if err:
        return err
    code, out = await _run(_exec_cscli_sync, args)
    return _truncate(f"$ cscli {' '.join(args)}  (exit {code})\n{out}")


def _find_bouncer(client: docker.DockerClient):
    if BOUNCER_CONTAINER:
        return _get_container(client, BOUNCER_CONTAINER)
    cands = [c for c in client.containers.list(all=True) if "bouncer" in c.name.lower()]
    return cands[0] if len(cands) == 1 else (cands or None)


@mcp.tool(annotations=RO)
async def crowdsec_diagnose(log_minutes: int = 60) -> str:
    """Komplett-Check für CrowdSec + Bouncer: Container-Status/Restarts, LAPI/CAPI-Status,
    registrierte Bouncer (letzter Abruf), Anzahl Entscheidungen je Herkunft (crowdsec/CAPI/Listen)
    und auffällige Zeilen im Bouncer-Log (Fehler, Anlegen von Gruppen/Regeln).
    Ideal, wenn der Bouncer ständig Firewall-Regeln erzeugt."""

    def work() -> dict:
        client = _docker()
        report: dict[str, Any] = {}

        def cinfo(c) -> dict:
            a = c.attrs
            st = a.get("State", {})
            return {"name": c.name, "status": st.get("Status"), "gestartet": st.get("StartedAt"),
                    "restart_count": a.get("RestartCount"), "image": a.get("Config", {}).get("Image")}

        # CrowdSec-Container
        try:
            cs = _get_container(client, CROWDSEC_CONTAINER)
            report["crowdsec_container"] = cinfo(cs)
        except Exception as e:  # noqa: BLE001
            report["crowdsec_container"] = {"fehler": str(e)}
            cs = None

        if cs is not None and cs.status == "running":
            for key, args in {
                "version": ["version"],
                "lapi_status": ["lapi", "status"],
                "capi_status": ["capi", "status"],
            }.items():
                code, out = _exec_cscli_sync(args)
                report[key] = out.strip()[-1500:]

            code, out = _exec_cscli_sync(["bouncers", "list", "-o", "json"])
            try:
                bl = json.loads(out)
                report["bouncers"] = [
                    {k: b.get(k) for k in ("name", "ip_address", "type", "version", "last_pull", "revoked", "auth_type")}
                    for b in (bl or [])
                ]
            except json.JSONDecodeError:
                report["bouncers"] = out.strip()[-2000:]

            # Entscheidungen zählen (raw = CSV, deutlich kleiner als JSON)
            code, out = _exec_cscli_sync(["decisions", "list", "--all", "-o", "raw"])
            try:
                rows = list(csv.DictReader(io.StringIO(out)))
                by_origin = Counter(r.get("source") or r.get("origin") or "?" for r in rows)
                by_action = Counter(r.get("action", "?") for r in rows)
                ipv6 = sum(1 for r in rows if ":" in (r.get("ip") or "").split("/")[0].replace("Ip:", "").replace("Range:", ""))
                report["entscheidungen"] = {
                    "gesamt": len(rows),
                    "nach_herkunft": dict(by_origin.most_common()),
                    "nach_aktion": dict(by_action),
                    "davon_ipv6_ca": ipv6,
                }
            except Exception as e:  # noqa: BLE001
                report["entscheidungen"] = {"fehler": str(e), "ausgabe": out[:500]}

        # Bouncer-Container
        try:
            b = _find_bouncer(client)
        except Exception as e:  # noqa: BLE001
            b = None
            report["bouncer_container"] = {"fehler": str(e)}
        if isinstance(b, list):
            report["bouncer_container"] = {"hinweis": "Mehrere Bouncer gefunden – BOUNCER_CONTAINER setzen",
                                            "kandidaten": [x.name for x in b]}
        elif b is None and "bouncer_container" not in report:
            report["bouncer_container"] = {"hinweis": "Kein Container mit 'bouncer' im Namen gefunden"}
        elif b is not None:
            info = cinfo(b)
            info["env"] = _mask_env(b.attrs.get("Config", {}).get("Env", []))
            report["bouncer_container"] = info
            since = datetime.now(timezone.utc) - timedelta(minutes=max(1, log_minutes))
            raw = b.logs(stdout=True, stderr=True, since=since, timestamps=True).decode("utf-8", errors="replace")
            lines = raw.splitlines()
            rx_err = re.compile(r"(error|fatal|panic|fail|unauthori[sz]ed|forbidden|timeout|refused)", re.I)
            rx_create = re.compile(r"((creat|add|new|post|insert).{0,40}(group|rule|policy|object))|((group|rule|policy|object).{0,20}(posted|created|added))", re.I)
            rx_delete = re.compile(r"(delet|remov).{0,40}(group|rule|policy|object)", re.I)
            rx_start = re.compile(r"(starting|started|initiali[sz]|version)", re.I)
            report["bouncer_log"] = {
                "zeitraum_min": log_minutes,
                "zeilen": len(lines),
                "fehler_zeilen": sum(1 for x in lines if rx_err.search(x)),
                "anlegen_zeilen": sum(1 for x in lines if rx_create.search(x)),
                "loeschen_zeilen": sum(1 for x in lines if rx_delete.search(x)),
                "start_zeilen": sum(1 for x in lines if rx_start.search(x)),
                "beispiele_fehler": [x[-300:] for x in lines if rx_err.search(x)][-8:],
                "beispiele_anlegen": [x[-300:] for x in lines if rx_create.search(x)][-8:],
                "letzte_zeilen": [x[-300:] for x in lines[-25:]],
            }
        return report

    report = await _run(work)
    return _truncate(json.dumps(report, indent=1, ensure_ascii=False, default=str))


# --------------------------------------------------------------------------- HTTP + Auth


class BearerAuth:
    """Reine ASGI-Middleware: verlangt 'Authorization: Bearer <MCP_AUTH_TOKEN>'.
    /health bleibt offen (für Docker-Healthcheck)."""

    def __init__(self, app, token: str):
        self.app = app
        self.token = token.encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not self.token:
            return await self.app(scope, receive, send)
        if scope.get("path") == "/health":
            body = b'{"status":"ok"}'
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"application/json")]})
            return await send({"type": "http.response.body", "body": body})
        headers = dict(scope.get("headers") or [])
        auth = headers.get(b"authorization", b"")
        ok = auth.startswith(b"Bearer ") and hmac.compare_digest(auth[7:].strip(), self.token)
        if not ok:
            await send({"type": "http.response.start", "status": 401,
                        "headers": [(b"content-type", b"application/json"),
                                    (b"www-authenticate", b"Bearer")]})
            return await send({"type": "http.response.body", "body": b'{"error":"unauthorized"}'})
        return await self.app(scope, receive, send)


def build_app():
    if not MCP_AUTH_TOKEN and not ALLOW_NO_AUTH:
        raise SystemExit("MCP_AUTH_TOKEN ist nicht gesetzt (oder ALLOW_NO_AUTH=true für Tests).")
    app = mcp.streamable_http_app(host=MCP_HOST)
    return BearerAuth(app, MCP_AUTH_TOKEN)


def main():
    import uvicorn

    log.info("unraid-mcp startet auf %s:%s/mcp (GraphQL: %s, CrowdSec: %s)",
             MCP_HOST, MCP_PORT, UNRAID_API_URL or "—", CROWDSEC_CONTAINER)
    uvicorn.run(build_app(), host=MCP_HOST, port=MCP_PORT, log_level="info", proxy_headers=False)


if __name__ == "__main__":
    main()
