import json
from urllib.parse import urlparse

from django.conf import settings as _settings
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.shortcuts import render
from django.utils import timezone

def _clamp_port(value: int) -> int:
    if value <= 0:
        return 1
    if value > 65535:
        return 65535
    return value


def _offset_port(base: int, offset: int) -> int:
    return _clamp_port(base + offset)


def _default_id_port() -> int:
    return _clamp_port(int(_settings.DEFAULT_ID_PORT))


def _host_without_port(host: str) -> str:
    host = (host or "").strip()
    if host.startswith("["):
        idx = host.find("]")
        if idx > 0:
            return host[1:idx]
    if ":" in host:
        return host.split(":")[0]
    return host


def _split_servers(raw: str) -> list:
    raw = (raw or "").strip()
    if not raw:
        return []
    normalized = raw.replace("\n", ",").replace(";", ",").replace(" ", ",")
    servers = []
    seen = set()
    for item in normalized.split(","):
        server = item.strip()
        if not server or server in seen:
            continue
        seen.add(server)
        servers.append(server)
    return servers


def _strip_ipv6_brackets(host: str) -> str:
    host = (host or "").strip()
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host


def _format_ws_endpoint(scheme: str, host: str, port: int) -> str:
    host = _strip_ipv6_brackets(host)
    if ":" in host:
        host = f"[{host}]"
    return f"{scheme}://{host}:{port}"


def _format_host_port(host: str, port: int) -> str:
    host = _strip_ipv6_brackets(host)
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{port}"


def _parse_server_input(server: str):
    server = (server or "").strip()
    if not server:
        return None
    if "://" in server:
        try:
            parsed = urlparse(server)
            scheme = (parsed.scheme or "").lower()
            if scheme not in ("ws", "wss"):
                return None
            host = (parsed.hostname or "").strip()
            if not host:
                return None
            try:
                port = parsed.port
            except ValueError:
                return None
            host = _strip_ipv6_brackets(host)
            return scheme, host, port
        except Exception:
            return None
    if server.startswith("["):
        end = server.find("]")
        if end <= 0:
            return None
        host = _strip_ipv6_brackets(server[1:end])
        rest = server[end + 1:]
        if not rest:
            return None, host, None
        if not rest.startswith(":"):
            return None
        try:
            port = int(rest[1:])
        except ValueError:
            return None
        if port <= 0 or port > 65535:
            return None
        return None, host, port
    colon_count = server.count(":")
    if colon_count == 1:
        host, port_text = server.rsplit(":", 1)
        if not host:
            return None
        try:
            port = int(port_text)
        except ValueError:
            return None
        if port <= 0 or port > 65535:
            return None
        host = _strip_ipv6_brackets(host)
        return None, host, port
    host = _strip_ipv6_brackets(server)
    if not host:
        return None
    return None, host, None


def _normalize_rendezvous_server(server: str) -> str:
    parsed = _parse_server_input(server)
    if not parsed:
        return ""
    scheme, host, port = parsed
    if scheme and scheme not in ("ws", "wss"):
        return ""
    if scheme == "ws":
        base_port = port or _default_id_port()
        return _format_ws_endpoint("ws", host, base_port)
    if scheme == "wss":
        base_port = port or _default_id_port()
        return _format_ws_endpoint("wss", host, base_port)
    return _format_host_port(host, port or _default_id_port())


def _derive_relay_server(rendezvous_endpoint: str) -> str:
    parsed = _parse_server_input(rendezvous_endpoint)
    if not parsed:
        return ""
    scheme, host, port = parsed
    if not scheme:
        return _format_host_port(host, _offset_port(port or _default_id_port(), 1))
    if scheme in ("wss", "ws"):
        return _format_ws_endpoint(scheme, host, _offset_port(port or _default_id_port(), 1))
    return ""


def _normalize_relay_server(
    server: str,
    rendezvous_endpoint: str = "",
) -> str:
    parsed = _parse_server_input(server)
    if not parsed:
        return ""
    scheme, host, port = parsed
    fallback = _parse_server_input(rendezvous_endpoint)
    fallback_scheme = fallback[0] if fallback else None
    fallback_port = fallback[2] if fallback else None
    if scheme and scheme not in ("ws", "wss"):
        return ""
    if scheme in ("ws", "wss"):
        base = (
            fallback_port or _default_id_port()
            if fallback_scheme in ("ws", "wss")
            else _default_id_port()
        )
        return _format_ws_endpoint(scheme, host, port or _offset_port(base, 1))
    base_service_port = (
        fallback_port or _default_id_port()
        if fallback and not fallback_scheme
        else _default_id_port()
    )
    return _format_host_port(host, port or _offset_port(base_service_port, 1))


def _resolve_webui2_servers():
    raw_id_servers = _split_servers(_settings.ID_SERVER or "")
    id_servers = []
    for item in raw_id_servers:
        normalized = _normalize_rendezvous_server(item)
        if normalized and normalized not in id_servers:
            id_servers.append(normalized)

    raw_relay_servers = _split_servers(getattr(_settings, "RELAY_SERVER", "") or "")
    relay_servers = []
    fallback_rendezvous = id_servers[0] if id_servers else ""
    for item in raw_relay_servers:
        normalized = _normalize_relay_server(
            item,
            fallback_rendezvous,
        )
        if normalized and normalized not in relay_servers:
            relay_servers.append(normalized)

    if not relay_servers and id_servers:
        derived = []
        for rv in id_servers:
            relay = _derive_relay_server(rv)
            if relay and relay not in derived:
                derived.append(relay)
        relay_servers = derived

    return raw_id_servers, id_servers, relay_servers


@login_required(login_url='/api/user_action?action=login')
def index(request):
    api_server = (_settings.API_SERVER or "").strip()
    raw_id_servers, id_servers, relay_servers = _resolve_webui2_servers()
    id_host = id_servers[0] if id_servers else (raw_id_servers[0] if raw_id_servers else "")
    rs_pub_key = (_settings.RS_PUB_KEY or "").strip()
    context = {
        "domain": id_host,
        "api_server": api_server,
        "rs_pub_key": rs_pub_key,
        "id_server": id_host,
        "relay_server": relay_servers[0] if relay_servers else "",
        "id_servers_json": json.dumps(id_servers),
        "id_servers_csv": ",".join(id_servers),
        "relay_servers_json": json.dumps(relay_servers),
        "relay_servers_csv": ",".join(relay_servers),
        "default_id_port": _default_id_port(),
    }
    return render(request, 'webui2.html', context)


@login_required(login_url='/api/user_action?action=login')
def status(request):
    host = _host_without_port(request.get_host())
    raw_id_servers, id_servers, relay_servers = _resolve_webui2_servers()
    id_server = id_servers[0] if id_servers else (raw_id_servers[0] if raw_id_servers else "")
    return JsonResponse({
        "id_server": id_server,
        "id_servers": id_servers,
        "relay_server": relay_servers[0] if relay_servers else "",
        "relay_servers": relay_servers,
        "default_id_port": _default_id_port(),
        "host": host,
        "user": request.user.username or "",
        "is_admin": bool(getattr(request.user, "is_admin", False)),
        "server_time": timezone.now().isoformat(),
    })
