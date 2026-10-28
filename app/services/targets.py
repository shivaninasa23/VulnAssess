"""Strict target validation and allowlist enforcement."""
import ipaddress,socket
from urllib.parse import urlsplit
class TargetError(ValueError): pass
def _allowlist(config):
    values=[x.strip().lower().rstrip(".") for x in config.get("ALLOWED_TARGETS","127.0.0.1,::1,localhost").split(",") if x.strip()]; nets=[]; names=set()
    for value in values:
        try: nets.append(ipaddress.ip_network(value,strict=False))
        except ValueError: names.add(value)
    return nets,names
def validate_target(target,config,allow_url=False):
    raw=(target or "").strip()
    if len(raw)>253 or not raw or any(c in raw for c in "\r\n\x00;|&`$<>\\"): raise TargetError("Enter a valid authorized IP address or hostname.")
    parsed=urlsplit(raw if "://" in raw else "//"+raw)
    if parsed.username or parsed.password or parsed.fragment or ((parsed.query or parsed.path not in ("","/")) and not allow_url): raise TargetError("Credentials, paths, queries, and fragments are not accepted as network targets.")
    try:
        if parsed.port is not None and not 1 <= parsed.port <= 65535: raise TargetError("Invalid target port.")
    except ValueError: raise TargetError("Invalid target port.")
    if parsed.scheme and (not allow_url or parsed.scheme not in ("http","https")): raise TargetError("Only HTTP or HTTPS URLs are supported for web checks.")
    host=(parsed.hostname or "").lower().rstrip(".")
    if not host: raise TargetError("A hostname or IP address is required.")
    try: addrs={ipaddress.ip_address(host)}
    except ValueError:
        if not all(part and len(part)<=63 and part[0]!="-" and part[-1]!="-" and all(ch.isalnum() or ch=="-" for ch in part) for part in host.split(".")): raise TargetError("Invalid hostname.")
        try: addrs={ipaddress.ip_address(row[4][0]) for row in socket.getaddrinfo(host,None,type=socket.SOCK_STREAM)}
        except (OSError,ValueError): raise TargetError("Hostname could not be resolved.")
    networks,names=_allowlist(config)
    if host not in names and not all(any(addr in net for net in networks) for addr in addrs): raise TargetError("Target is outside the configured authorized target allowlist.")
    return host,parsed.scheme or ""
def validate_redirect(url,config):
    host,scheme=validate_target(url,config,allow_url=True)
    if not scheme: raise TargetError("Redirect must use HTTP or HTTPS.")
    return host,scheme
