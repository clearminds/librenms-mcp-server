"""LibreNMS MCP Server — FastMCP tools for LibreNMS monitoring."""

import argparse
import logging
import logging.config
import sys
from collections import Counter
from typing import Any

from fastmcp import FastMCP

from clr_librenms_mcp.config import Settings
from clr_librenms_mcp.librenms_client import LibreNMSClient

mcp = FastMCP("LibreNMS")
_client: LibreNMSClient | None = None


# ── System tools ─────────────────────────────────────────────────────


@mcp.tool
def librenms_system() -> dict[str, Any]:
    """Get LibreNMS system information.

    Returns version, database schema, PHP version, and other system details.
    """
    data = _client.get("/api/v0/system")
    return data.get("system", data)


# ── Device tools ─────────────────────────────────────────────────────


@mcp.tool
def librenms_list_devices(
    device_type: str | None = None,
    query: str | None = None,
) -> list[dict[str, Any]]:
    """List all monitored devices.

    Args:
        device_type: Filter type — active, down, ignored, disabled, os,
                     hostname, sysName, location, or None for all.
        query: Search value when using device_type filter.

    Returns list of devices with hostname, sysName, hardware, os, status,
    uptime, and location.
    """
    params = {}
    if device_type:
        params["type"] = device_type
    if query:
        params["query"] = query

    data = _client.get("/api/v0/devices", params=params or None)
    rows = data.get("devices", [])
    return [
        {
            "device_id": d.get("device_id"),
            "hostname": d.get("hostname"),
            "sysName": d.get("sysName"),
            "hardware": d.get("hardware"),
            "os": d.get("os"),
            "status": d.get("status"),
            "status_reason": d.get("status_reason", ""),
            "uptime": d.get("uptime"),
            "location": d.get("location"),
        }
        for d in rows
    ]


@mcp.tool
def librenms_get_device(device: str) -> dict[str, Any]:
    """Get full detail for a single device.

    Args:
        device: Hostname, IP address, or device_id.

    Returns complete device information.
    """
    data = _client.get(f"/api/v0/devices/{device}")
    devices = data.get("devices", [])
    return devices[0] if devices else data


@mcp.tool
def librenms_device_availability(device: str) -> list[dict[str, Any]]:
    """Get device availability percentages.

    Args:
        device: Hostname, IP address, or device_id.

    Returns availability data for 24h, 7d, 30d, and 365d periods.
    """
    data = _client.get(f"/api/v0/devices/{device}/availability")
    return data.get("availability", [])


@mcp.tool
def librenms_device_outages(device: str) -> list[dict[str, Any]]:
    """Get device outage history.

    Args:
        device: Hostname, IP address, or device_id.

    Returns list of outages with going_down and up_again timestamps.
    """
    data = _client.get(f"/api/v0/devices/{device}/outages")
    return data.get("outages", [])


@mcp.tool
def librenms_down_devices() -> list[dict[str, Any]]:
    """List all devices that are currently down.

    Returns only devices with status 0 (down), including the reason.
    """
    data = _client.get("/api/v0/devices", params={"type": "down"})
    rows = data.get("devices", [])
    return [
        {
            "device_id": d.get("device_id"),
            "hostname": d.get("hostname"),
            "sysName": d.get("sysName"),
            "hardware": d.get("hardware"),
            "status_reason": d.get("status_reason", ""),
            "location": d.get("location"),
        }
        for d in rows
    ]


@mcp.tool
def librenms_device_summary() -> dict[str, Any]:
    """Get aggregate device status summary — count by status.

    Returns total device count, how many are up, down, and disabled.
    """
    data = _client.get("/api/v0/devices")
    rows = data.get("devices", [])

    counts = Counter()
    for d in rows:
        status = d.get("status")
        if d.get("disabled"):
            counts["disabled"] += 1
        elif status == 1:
            counts["up"] += 1
        elif status == 0:
            counts["down"] += 1
        else:
            counts["unknown"] += 1

    return {"total_devices": len(rows), "status": dict(counts)}


# ── Alert tools ──────────────────────────────────────────────────────


@mcp.tool
def librenms_list_alerts(
    state: str | None = None,
    severity: str | None = None,
) -> list[dict[str, Any]]:
    """List alerts with optional filters.

    Args:
        state: Filter by state — active, acknowledged, or resolved.
        severity: Filter by severity — ok, warning, critical.

    Returns list of alerts with id, hostname, rule name, severity,
    state, and timestamp.
    """
    params = {}
    state_map = {"active": "1", "acknowledged": "2", "resolved": "0"}
    if state and state.lower() in state_map:
        params["state"] = state_map[state.lower()]
    if severity:
        params["severity"] = severity.lower()

    data = _client.get("/api/v0/alerts", params=params or None)
    rows = data.get("alerts", [])
    return [
        {
            "id": a.get("id"),
            "hostname": a.get("hostname"),
            "rule": a.get("name") or a.get("rule", {}).get("name", ""),
            "severity": a.get("severity"),
            "state": a.get("state"),
            "timestamp": a.get("timestamp"),
        }
        for a in rows
    ]


@mcp.tool
def librenms_get_alert(alert_id: int) -> dict[str, Any]:
    """Get full detail for a single alert.

    Args:
        alert_id: The LibreNMS alert ID.

    Returns complete alert information.
    """
    data = _client.get(f"/api/v0/alerts/{alert_id}")
    alerts = data.get("alerts", [])
    return alerts[0] if alerts else data


@mcp.tool
def librenms_alert_count() -> dict[str, Any]:
    """Get alert count aggregated by state and severity.

    Returns total count and breakdown by state (active, acknowledged,
    resolved) and severity (ok, warning, critical).
    """
    data = _client.get("/api/v0/alerts")
    rows = data.get("alerts", [])

    by_state = Counter()
    by_severity = Counter()
    state_names = {0: "resolved", 1: "active", 2: "acknowledged"}

    for a in rows:
        state = state_names.get(a.get("state"), "unknown")
        by_state[state] += 1
        sev = a.get("severity", "unknown")
        by_severity[sev] += 1

    return {
        "total": len(rows),
        "by_state": dict(by_state.most_common()),
        "by_severity": dict(by_severity.most_common()),
    }


@mcp.tool
def librenms_ack_alert(alert_id: int, note: str = "") -> dict[str, Any]:
    """Acknowledge an alert by ID.

    This is a non-destructive write operation — it marks the alert as
    acknowledged but does not modify device configuration.

    Args:
        alert_id: The alert ID to acknowledge.
        note: Optional note to attach.

    Returns acknowledgement result.
    """
    payload = {"note": note, "until_clear": True}
    status_code, body = _client.put(f"/api/v0/alerts/{alert_id}", payload)
    if 200 <= status_code < 300:
        return {"acknowledged": True, "alert_id": alert_id}
    return {"error": f"HTTP {status_code}", "detail": body}


# ── Alert rule tools ─────────────────────────────────────────────────


@mcp.tool
def librenms_list_alert_rules() -> list[dict[str, Any]]:
    """List all alert rules.

    Returns list of alert rules with id, name, severity, and whether
    they are enabled or disabled.
    """
    data = _client.get("/api/v0/rules")
    rows = data.get("rules", [])
    return [
        {
            "id": r.get("id"),
            "name": r.get("name"),
            "severity": r.get("severity"),
            "disabled": r.get("disabled"),
        }
        for r in rows
    ]


# ── Sensor tools ─────────────────────────────────────────────────────


@mcp.tool
def librenms_list_sensors(device: str | None = None) -> list[dict[str, Any]]:
    """List sensors, optionally filtered by device.

    Args:
        device: Optional hostname, IP, or device_id to filter by.

    Returns list of sensors with id, class, description, current value,
    and threshold limits.
    """
    if device:
        data = _client.get(f"/api/v0/devices/{device}/health")
        return data.get("graphs", [])

    data = _client.get("/api/v0/resources/sensors")
    rows = data.get("sensors", [])
    return [
        {
            "sensor_id": s.get("sensor_id"),
            "device_id": s.get("device_id"),
            "sensor_class": s.get("sensor_class"),
            "sensor_descr": s.get("sensor_descr"),
            "sensor_current": s.get("sensor_current"),
            "sensor_limit": s.get("sensor_limit"),
            "sensor_limit_low": s.get("sensor_limit_low"),
            "sensor_alert": s.get("sensor_alert"),
        }
        for s in rows
    ]


@mcp.tool
def librenms_device_health(
    device: str, health_type: str | None = None
) -> list[dict[str, Any]]:
    """Get health sensors for a device.

    Args:
        device: Hostname, IP address, or device_id.
        health_type: Optional sensor type filter (e.g. temperature,
                     voltage, fanspeed, power, humidity, state).

    Returns list of health sensor data.
    """
    path = f"/api/v0/devices/{device}/health"
    if health_type:
        path = f"{path}/{health_type}"

    data = _client.get(path)
    return data.get("graphs", data.get("sensors", []))


# ── Port tools ───────────────────────────────────────────────────────


@mcp.tool
def librenms_list_ports(device: str) -> list[dict[str, Any]]:
    """List ports/interfaces for a device.

    Args:
        device: Hostname, IP address, or device_id.

    Returns list of ports with name, speed, status, alias, and traffic.
    """
    data = _client.get(f"/api/v0/devices/{device}/ports")
    rows = data.get("ports", [])
    return [
        {
            "port_id": p.get("port_id"),
            "ifName": p.get("ifName"),
            "ifAlias": p.get("ifAlias"),
            "ifSpeed": p.get("ifSpeed"),
            "ifOperStatus": p.get("ifOperStatus"),
            "ifAdminStatus": p.get("ifAdminStatus"),
            "ifType": p.get("ifType"),
        }
        for p in rows
    ]


@mcp.tool
def librenms_search_ports(search: str) -> list[dict[str, Any]]:
    """Search for ports by name, alias, or description.

    Args:
        search: Search string to match against port fields.

    Returns list of matching ports.
    """
    data = _client.get(f"/api/v0/ports/search/{search}")
    rows = data.get("ports", [])
    return [
        {
            "port_id": p.get("port_id"),
            "device_id": p.get("device_id"),
            "ifName": p.get("ifName"),
            "ifAlias": p.get("ifAlias"),
            "ifOperStatus": p.get("ifOperStatus"),
        }
        for p in rows
    ]


@mcp.tool
def librenms_port_by_mac(mac: str) -> list[dict[str, Any]]:
    """Find port(s) associated with a MAC address.

    Args:
        mac: MAC address to search for.

    Returns list of matching ports with device context.
    """
    data = _client.get(f"/api/v0/ports/mac/{mac}")
    return data.get("ports", [])


# ── ARP tools ────────────────────────────────────────────────────────


@mcp.tool
def librenms_arp_lookup(
    query: str, device: str | None = None
) -> list[dict[str, Any]]:
    """Look up ARP entries by IP, MAC, or CIDR subnet.

    Args:
        query: IP address, MAC address, CIDR (e.g. 192.168.1.0/24),
               or "all" (requires device parameter).
        device: Required when query is "all" — hostname or device_id.

    Returns list of ARP entries with MAC, IP, port, and device info.
    """
    params = {}
    if device:
        params["device"] = device

    data = _client.get(
        f"/api/v0/resources/ip/arp/{query}", params=params or None
    )
    return data.get("arp", [])


# ── FDB tools ────────────────────────────────────────────────────────


@mcp.tool
def librenms_fdb(device: str) -> list[dict[str, Any]]:
    """Get FDB (forwarding database / MAC table) for a device.

    Args:
        device: Hostname, IP address, or device_id.

    Returns list of FDB entries with MAC address, VLAN, and port.
    """
    data = _client.get(f"/api/v0/devices/{device}/fdb")
    rows = data.get("ports_fdb", [])
    return [
        {
            "mac_address": f.get("mac_address"),
            "vlan_id": f.get("vlan_id"),
            "port_id": f.get("port_id"),
            "device_id": f.get("device_id"),
        }
        for f in rows
    ]


# ── Inventory tools ──────────────────────────────────────────────────


@mcp.tool
def librenms_inventory(
    device: str, physical_class: str | None = None
) -> list[dict[str, Any]]:
    """Get device hardware inventory.

    Args:
        device: Hostname, IP address, or device_id.
        physical_class: Optional filter — chassis, module, port,
                        powerSupply, fan, sensor, etc.

    Returns list of inventory entries with description, class, name,
    and serial number.
    """
    params = {}
    if physical_class:
        params["entPhysicalClass"] = physical_class

    data = _client.get(
        f"/api/v0/inventory/{device}", params=params or None
    )
    rows = data.get("inventory", [])
    return [
        {
            "entPhysicalIndex": i.get("entPhysicalIndex"),
            "entPhysicalDescr": i.get("entPhysicalDescr"),
            "entPhysicalClass": i.get("entPhysicalClass"),
            "entPhysicalName": i.get("entPhysicalName"),
            "entPhysicalSerialNum": i.get("entPhysicalSerialNum"),
        }
        for i in rows
    ]


# ── IP address tools ────────────────────────────────────────────────


@mcp.tool
def librenms_device_ips(device: str) -> list[dict[str, Any]]:
    """Get all IP addresses assigned to a device.

    Args:
        device: Hostname, IP address, or device_id.

    Returns list of IP addresses with prefix length and port.
    """
    data = _client.get(f"/api/v0/devices/{device}/ip")
    return data.get("addresses", [])


# ── Main entry point ─────────────────────────────────────────────────


def main() -> None:
    """Main entry point for the LibreNMS MCP server."""
    global _client

    settings = Settings()

    parser = argparse.ArgumentParser(description="LibreNMS MCP Server")
    parser.add_argument(
        "--transport", type=str, choices=["stdio", "http"], default=None
    )
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--log-level",
        type=str,
        default=None,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )
    parser.add_argument("--librenms-url", type=str, default=None)
    parser.add_argument("--librenms-token", type=str, default=None)
    args = parser.parse_args()

    creds = settings.load_credentials()

    # CLI args override everything
    transport = args.transport or settings.librenms_transport
    log_level = args.log_level or settings.librenms_log_level
    librenms_url = args.librenms_url or creds.get("url", "")
    librenms_token = args.librenms_token or creds.get("token", "")

    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "console": {
                    "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
                }
            },
            "handlers": {
                "console": {
                    "class": "logging.StreamHandler",
                    "formatter": "console",
                    "stream": "ext://sys.stderr",
                }
            },
            "root": {"level": log_level, "handlers": ["console"]},
        }
    )

    logger = logging.getLogger(__name__)

    if not librenms_url or not librenms_token:
        logger.error("LIBRENMS_URL and LIBRENMS_TOKEN are required")
        sys.exit(1)

    logger.info("Connecting to LibreNMS at %s", librenms_url)
    _client = LibreNMSClient(librenms_url, librenms_token)

    try:
        if transport == "stdio":
            mcp.run(transport="stdio")
        else:
            mcp.run(transport="http", host=args.host, port=args.port)
    except Exception as e:
        logger.error("Failed to start MCP server: %s", e)
        sys.exit(1)
    finally:
        _client.close()


if __name__ == "__main__":
    main()
