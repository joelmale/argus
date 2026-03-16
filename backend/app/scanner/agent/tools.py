"""
Agent Tool Definitions + Execution

This module does two things:
1. Defines the tool schemas that the LLM agent sees (in OpenAI tool-call format).
2. Provides the execute() dispatcher that runs the actual probe when the agent
   calls a tool.

The analogy here is a microscope with interchangeable objective lenses: the
agent decides which lens to look through, and this module swaps it in.

Tool calling is the bridge between the LLM's reasoning (text) and the real
network investigation (code). The agent outputs a tool_call JSON object;
we run the corresponding probe and feed results back.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from app.scanner.models import PortResult

log = logging.getLogger(__name__)

# ─── Tool schemas (OpenAI format — compatible with Ollama tool calling) ──────

TOOL_SCHEMAS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "probe_http",
            "description": (
                "Fetch HTTP or HTTPS headers, page title, and server banner from a web port. "
                "Also checks common admin paths. Very high signal for identifying web UIs, "
                "routers, NAS devices, cameras, and IoT dashboards."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "port": {"type": "integer", "description": "Port number (e.g. 80, 8080, 443)"},
                    "use_https": {"type": "boolean", "description": "True to use HTTPS", "default": False},
                },
                "required": ["port"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "probe_tls",
            "description": (
                "Extract TLS/SSL certificate information. The certificate subject CN and "
                "organization field often directly name the device manufacturer or product. "
                "SANs reveal hostnames the device believes it has. "
                "Self-signed certs are common on LAN devices — don't skip this."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "port": {"type": "integer", "description": "TLS port (default 443)", "default": 443},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "probe_ssh",
            "description": (
                "Grab SSH banner and key exchange algorithms. The banner often reveals "
                "exact OS (Ubuntu, Raspbian, Dropbear for embedded Linux, RouterOS for MikroTik). "
                "Ancient KEX algorithms (group1-sha1) indicate outdated or EOL firmware."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "port": {"type": "integer", "description": "SSH port (default 22)", "default": 22},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "probe_snmp",
            "description": (
                "Query SNMP sysDescr and sysName OIDs. The sysDescr is extremely informative — "
                "it typically contains full hardware description, OS version, and firmware version. "
                "Only works if SNMP community string is correct and port 161/UDP is accessible."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "community": {
                        "type": "string",
                        "description": "SNMP community string",
                        "default": "public",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "probe_mdns",
            "description": (
                "Query mDNS/Bonjour service announcements. Reveals exact device model for "
                "Apple devices, Chromecasts, smart speakers, HomeKit accessories, and "
                "many IoT devices. Very high signal for consumer electronics."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "probe_upnp",
            "description": (
                "Query UPnP/SSDP device description XML. Often contains exact make and model "
                "for routers (NETGEAR, ASUS, TP-Link), smart TVs (Samsung, LG, Sony), "
                "media servers (Plex, Jellyfin), and NAS devices (Synology, QNAP)."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "probe_smb",
            "description": (
                "Query SMB/NetBIOS for computer name, workgroup, OS version, and shares. "
                "Critical for identifying Windows machines, NAS devices running Samba, "
                "and detecting SMBv1 (EternalBlue vulnerability surface)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "port": {"type": "integer", "description": "SMB port (default 445)", "default": 445},
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "final_analysis",
            "description": (
                "Submit your final analysis of the device. Call this when you have gathered "
                "enough information to classify the device with reasonable confidence. "
                "This terminates the investigation."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "device_class": {
                        "type": "string",
                        "enum": [
                            "router", "switch", "access_point", "firewall",
                            "server", "workstation", "nas", "printer",
                            "ip_camera", "smart_tv", "iot_device", "voip", "unknown"
                        ],
                        "description": "Primary device classification",
                    },
                    "confidence": {
                        "type": "number",
                        "description": "Confidence in classification, 0.0–1.0",
                    },
                    "vendor": {"type": "string", "description": "Manufacturer/vendor name if known"},
                    "model": {"type": "string", "description": "Model name/number if known"},
                    "os_guess": {"type": "string", "description": "Operating system if determinable"},
                    "device_role": {
                        "type": "string",
                        "description": "Specific functional role: e.g. 'internet gateway', 'NAS', 'media server', 'home automation hub'",
                    },
                    "open_services_summary": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Human-readable list of key services, e.g. ['SSH 9.3 OpenSSH', 'HTTPS nginx 1.24']",
                    },
                    "security_findings": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                                "title": {"type": "string"},
                                "detail": {"type": "string"},
                            },
                        },
                        "description": "Notable security observations",
                    },
                    "investigation_notes": {
                        "type": "string",
                        "description": "Narrative summary of what you found and how you concluded the classification",
                    },
                    "suggested_tags": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Suggested asset tags, e.g. ['linux', 'managed-switch', 'vlan-aware']",
                    },
                },
                "required": ["device_class", "confidence", "investigation_notes"],
            },
        },
    },
]


# ─── Tool executor ────────────────────────────────────────────────────────────

async def execute(tool_name: str, args: dict[str, Any], ip: str, ports: list[PortResult]) -> str:
    """
    Execute a probe tool and return its result as a string for the agent.
    Errors are returned as descriptive strings — the agent should handle them.
    """
    log.debug("Agent executing tool: %s(%s)", tool_name, args)

    try:
        if tool_name == "probe_http":
            from app.scanner.probes import http
            port = args.get("port", 80)
            use_https = args.get("use_https", False)
            result = await http.probe(ip, port, use_https)
            return result.raw or json.dumps(result.data, indent=2)

        elif tool_name == "probe_tls":
            from app.scanner.probes import tls
            port = args.get("port", 443)
            result = await tls.probe(ip, port)
            return result.raw or json.dumps(result.data, indent=2)

        elif tool_name == "probe_ssh":
            from app.scanner.probes import ssh
            port = args.get("port", 22)
            result = await ssh.probe(ip, port)
            return result.raw or json.dumps(result.data, indent=2)

        elif tool_name == "probe_snmp":
            from app.scanner.probes import snmp
            community = args.get("community", "public")
            result = await snmp.probe(ip, community=community)
            return result.raw or json.dumps(result.data, indent=2)

        elif tool_name == "probe_mdns":
            from app.scanner.probes import mdns
            result = await mdns.probe(ip)
            return result.raw or json.dumps(result.data, indent=2)

        elif tool_name == "probe_upnp":
            from app.scanner.probes import upnp
            result = await upnp.probe(ip)
            return result.raw or json.dumps(result.data, indent=2)

        elif tool_name == "probe_smb":
            from app.scanner.probes import smb
            port = args.get("port", 445)
            result = await smb.probe(ip, port)
            return result.raw or json.dumps(result.data, indent=2)

        else:
            return f"Unknown tool: {tool_name}"

    except Exception as exc:
        log.warning("Tool %s failed: %s", tool_name, exc)
        return f"Tool execution error: {exc}"
