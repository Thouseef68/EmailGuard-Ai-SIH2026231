# layers/forensics/smtp_traversal.py
"""
Multi-hop SMTP Received-header traversal and FCrDNS validation.
"""
import re
import socket
import ipaddress
from typing import List, Dict, Any, Optional
from email import message_from_bytes

_IP_RE = re.compile(
    r"\[(\d{1,3}(?:\.\d{1,3}){3})\]"
    r"|(?<!\d)(\d{1,3}(?:\.\d{1,3}){3})(?!\d)"
)

_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

_LOOPBACK = ipaddress.ip_network("127.0.0.0/8")


def _is_private(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _PRIVATE_RANGES)
    except ValueError:
        return False


def _is_loopback(ip_str: str) -> bool:
    try:
        return ipaddress.ip_address(ip_str) in _LOOPBACK
    except ValueError:
        return False


def _fcrdns(ip_str: str) -> Dict[str, Any]:
    """
    Forward-confirmed reverse DNS check.

    fcrdns_pass values:
      True  — rDNS hostname found AND forward-resolves back to the same IP   ✅
      False — rDNS hostname found BUT forward-resolves to a DIFFERENT IP      ❌ (real anomaly)
      None  — DNS lookup failed entirely (no record, timeout, NXDOMAIN, etc.) — unknown, don't flag
    """
    result = {
        "ip": ip_str,
        "rdns_hostname": None,
        "fcrdns_pass": None,
        "error": None,
    }
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_str)
        result["rdns_hostname"] = hostname
        # Now forward-resolve the hostname
        try:
            forward_ips = {info[4][0] for info in socket.getaddrinfo(hostname, None)}
            if ip_str in forward_ips:
                result["fcrdns_pass"] = True
            else:
                result["fcrdns_pass"] = False          # real mismatch — flag this
                result["error"] = (
                    f"rDNS={hostname} forward-resolves to {forward_ips}, not {ip_str}"
                )
        except (socket.herror, socket.gaierror) as fwd_exc:
            # hostname exists in rDNS but can't be forward-resolved → unknown
            result["fcrdns_pass"] = None
            result["error"] = f"Forward lookup failed: {fwd_exc}"
    except (socket.herror, socket.gaierror) as exc:
        # No rDNS record at all → unknown, not a failure
        result["fcrdns_pass"] = None
        result["error"] = f"No rDNS record: {exc}"
    return result


def _extract_ips_from_received(header_value: str) -> List[str]:
    hits = _IP_RE.findall(header_value)
    ips = [bracketed or bare for bracketed, bare in hits if bracketed or bare]
    seen = set()
    unique = []
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return unique


def analyze_smtp_chain(eml_bytes: bytes, fcrdns_timeout: float = 2.0) -> Dict[str, Any]:
    socket.setdefaulttimeout(fcrdns_timeout)
    anomalies: List[str] = []

    try:
        msg = message_from_bytes(eml_bytes)
    except Exception as exc:
        return {"error": f"Failed to parse email: {exc}", "chain_suspicious": False}

    received_headers: List[str] = msg.get_all("Received") or []
    received_headers = list(reversed(received_headers))

    hops: List[Dict[str, Any]] = []
    for idx, hdr in enumerate(received_headers):
        ips = _extract_ips_from_received(hdr)
        hops.append({
            "hop_index": idx,
            "header_snippet": hdr[:200],
            "ips_found": ips,
            "public_ips": [ip for ip in ips if not _is_private(ip)],
            "private_ips": [ip for ip in ips if _is_private(ip)],
        })

    # ── Anomaly checks ────────────────────────────────────────────────────

    # 1. No Received headers
    if len(hops) == 0:
        anomalies.append("No Received headers — cannot verify relay chain.")

    # 2. Very few hops for internet mail
    if 0 < len(hops) < 2:
        anomalies.append(
            f"Only {len(hops)} Received hop(s) — suspiciously low for internet mail; "
            "possible header injection."
        )

    # 3. Private IPs in the MIDDLE of the chain only
    #    Skip: hop 0 (originating internal server — link-local/RFC1918 is normal there)
    #          hop N-1 (final local delivery — loopback is normal there)
    #          Any hop whose only private IPs are loopback (127.x — normal MTA handoff)
    middle_hops = hops[1:-1] if len(hops) > 2 else []
    for hop in middle_hops:
        non_loopback_private = [ip for ip in hop["private_ips"] if not _is_loopback(ip)]
        for ip in non_loopback_private:
            anomalies.append(
                f"Private IP {ip} in intermediate hop {hop['hop_index']} "
                "(between two public relays) — possible internal relay or forged header."
            )

    # 4. Duplicate public IPs across non-adjacent hops
    seen_ips: Dict[str, int] = {}
    for hop in hops:
        for ip in hop["public_ips"]:
            if ip in seen_ips and seen_ips[ip] != hop["hop_index"] - 1:
                anomalies.append(
                    f"IP {ip} reappears at hop {hop['hop_index']} "
                    f"(first seen at hop {seen_ips[ip]}) — possible routing loop or replay."
                )
            seen_ips[ip] = hop["hop_index"]

    # ── FCrDNS on unique public IPs ───────────────────────────────────────
    unique_public = list({ip for hop in hops for ip in hop["public_ips"]})
    fcrdns_results: List[Dict[str, Any]] = []
    for ip in unique_public[:5]:
        r = _fcrdns(ip)
        fcrdns_results.append(r)
        # Only flag explicit mismatches (fcrdns_pass=False), NOT DNS errors (fcrdns_pass=None)
        if r["fcrdns_pass"] is False:
            anomalies.append(
                f"FCrDNS FAIL for {ip}: rDNS={r['rdns_hostname']} "
                "does not forward-resolve back to this IP."
            )

    # Originating IP = first public IP in the earliest hop
    originating_ip: Optional[str] = None
    for hop in hops:
        if hop["public_ips"]:
            originating_ip = hop["public_ips"][0]
            break

    return {
        "hop_count": len(hops),
        "hops": hops,
        "originating_ip": originating_ip,
        "anomalies": anomalies,
        "fcrdns_results": fcrdns_results,
        "chain_suspicious": len(anomalies) > 0,
    }