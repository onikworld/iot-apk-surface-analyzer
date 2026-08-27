#!/usr/bin/env python3
"""
IoT APK Surface Analyzer

A small defensive static-analysis tool for Android/IoT companion APKs.
It extracts:
- declared permissions
- exported activities/services/receivers/providers
- URLs and IP-like endpoints found in DEX strings
- references to selected security-sensitive API names

This is intentionally lightweight. It does not claim to prove a vulnerability.
"""

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Any

from androguard.misc import AnalyzeAPK

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

URL_RE = re.compile(
    r"""(?xi)
    \bhttps?://
    [a-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+
    """
)

IP_RE = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b"
)

SENSITIVE_API_KEYWORDS = {
    "WebView / JavaScript": [
        "setJavaScriptEnabled",
        "addJavascriptInterface",
        "loadUrl",
    ],
    "Command execution": [
        "java/lang/Runtime",
        "ProcessBuilder",
        "exec",
    ],
    "Device identifiers": [
        "getDeviceId",
        "getImei",
        "ANDROID_ID",
        "AdvertisingId",
    ],
    "Location": [
        "getLastKnownLocation",
        "requestLocationUpdates",
        "FusedLocationProviderClient",
    ],
    "Camera / microphone": [
        "android/hardware/Camera",
        "CameraManager",
        "MediaRecorder",
        "AudioRecord",
    ],
    "Crypto / TLS": [
        "TrustManager",
        "HostnameVerifier",
        "SSLContext",
        "X509TrustManager",
    ],
    "Dynamic code / reflection": [
        "DexClassLoader",
        "PathClassLoader",
        "java/lang/reflect",
    ],
    "External storage": [
        "getExternalStorage",
        "Environment",
    ],
}

COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")


def _attr(element, name: str):
    return element.get(ANDROID_NS + name)


def _bool_attr(value):
    if value is None:
        return None
    return str(value).strip().lower() == "true"


def extract_exported_components(manifest) -> List[Dict[str, Any]]:
    results = []
    app = manifest.find("application")
    if app is None:
        return results

    for tag in COMPONENT_TAGS:
        for node in app.findall(tag):
            name = _attr(node, "name")
            exported_raw = _attr(node, "exported")
            exported = _bool_attr(exported_raw)
            has_intent_filter = node.find("intent-filter") is not None

            # Android's historical default behavior differs by component/API level.
            # We report "implicit/unknown" instead of pretending certainty.
            if exported_raw is None:
                exported_status = "implicit/unknown"
            else:
                exported_status = exported

            if exported is True or (exported_raw is None and has_intent_filter):
                results.append({
                    "type": tag,
                    "name": name,
                    "exported": exported_status,
                    "has_intent_filter": has_intent_filter,
                    "permission": _attr(node, "permission"),
                })
    return results


def collect_dex_strings(dex_objects) -> List[str]:
    strings = set()
    for dex in dex_objects:
        try:
            for s in dex.get_strings():
                if isinstance(s, bytes):
                    s = s.decode("utf-8", errors="ignore")
                if isinstance(s, str) and s:
                    strings.add(s)
        except Exception:
            continue
    return sorted(strings)


def extract_endpoints(strings: List[str]) -> Dict[str, List[str]]:
    urls, ips = set(), set()
    for s in strings:
        urls.update(m.group(0).rstrip('",);]') for m in URL_RE.finditer(s))
        for m in IP_RE.finditer(s):
            candidate = m.group(0)
            octets = candidate.split(":")[0].split(".")
            if all(0 <= int(x) <= 255 for x in octets):
                ips.add(candidate)
    return {
        "urls": sorted(urls),
        "ip_endpoints": sorted(ips),
    }


def find_sensitive_api_indicators(strings: List[str]) -> Dict[str, List[str]]:
    joined = "\n".join(strings).lower()
    hits = {}
    for category, keywords in SENSITIVE_API_KEYWORDS.items():
        matched = [kw for kw in keywords if kw.lower() in joined]
        if matched:
            hits[category] = matched
    return hits


def analyze(apk_path: Path) -> Dict[str, Any]:
    apk, dex_objects, _analysis = AnalyzeAPK(str(apk_path))
    manifest = apk.get_android_manifest_xml()
    strings = collect_dex_strings(dex_objects)

    return {
        "file": apk_path.name,
        "package": apk.get_package(),
        "app_name": apk.get_app_name(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "permissions": sorted(apk.get_permissions()),
        "exported_components": extract_exported_components(manifest),
        "endpoints": extract_endpoints(strings),
        "sensitive_api_indicators": find_sensitive_api_indicators(strings),
        "notes": [
            "This is a lightweight static triage tool, not a vulnerability scanner.",
            "Exported status can depend on Android version and manifest semantics.",
            "Sensitive API findings are string-based indicators and require manual validation.",
        ],
    }


def print_human(result: Dict[str, Any]) -> None:
    print(f"\n== {result['app_name']} ({result['package']}) ==")
    print(f"APK: {result['file']}")
    print(f"Version: {result['version_name']} ({result['version_code']})")

    print(f"\nPermissions ({len(result['permissions'])})")
    for p in result["permissions"]:
        print(f"  - {p}")

    comps = result["exported_components"]
    print(f"\nPotentially exported components ({len(comps)})")
    for c in comps:
        print(f"  - [{c['type']}] {c['name']} | exported={c['exported']} | permission={c['permission']}")

    urls = result["endpoints"]["urls"]
    ips = result["endpoints"]["ip_endpoints"]
    print(f"\nURLs ({len(urls)})")
    for u in urls[:100]:
        print(f"  - {u}")
    if len(urls) > 100:
        print(f"  ... {len(urls)-100} more")

    print(f"\nIP endpoints ({len(ips)})")
    for ip in ips[:100]:
        print(f"  - {ip}")

    print("\nSensitive API indicators")
    if not result["sensitive_api_indicators"]:
        print("  - None found by the lightweight string matcher")
    else:
        for category, hits in result["sensitive_api_indicators"].items():
            print(f"  - {category}: {', '.join(hits)}")


def main():
    parser = argparse.ArgumentParser(
        description="Defensive static triage for Android/IoT companion APKs."
    )
    parser.add_argument("apk", type=Path, help="Path to an APK you are authorized to analyze")
    parser.add_argument("--json", dest="json_path", type=Path,
                        help="Write full results to a JSON file")
    args = parser.parse_args()

    if not args.apk.exists():
        raise SystemExit(f"APK not found: {args.apk}")
    if args.apk.suffix.lower() != ".apk":
        raise SystemExit("Input file should be an .apk")

    result = analyze(args.apk)
    print_human(result)

    if args.json_path:
        args.json_path.write_text(json.dumps(result, indent=2), encoding="utf-8")
        print(f"\nJSON report written to: {args.json_path}")


if __name__ == "__main__":
    main()
