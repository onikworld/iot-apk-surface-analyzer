# IoT APK Surface Analyzer

A small defensive static-analysis project for **Android/IoT companion applications**.

The tool helps with first-pass security triage by extracting:

- Android permissions
- potentially exported activities, services, receivers, and providers
- URLs and IP-like endpoints embedded in DEX strings
- references to selected security-sensitive Android/Java APIs

I built this project as a small research artifact while exploring **IoT systems security, social-engineering-enabled attack surfaces, and program analysis**.

## Why this project

Many IoT products depend on Android companion apps for pairing, authentication, permissions, remote control, and device management. A socially engineered action can become security-relevant when it causes an app to reach a sensitive state.

This tool is a first step toward studying that problem. It does **not** prove that an app is vulnerable. Instead, it helps identify areas that deserve manual analysis.

## Installation

Python 3.10+ is recommended.

```bash
git clone https://github.com/YOUR-USERNAME/iot-apk-surface-analyzer.git
cd iot-apk-surface-analyzer
python -m venv .venv
```

Activate the environment, then:

```bash
pip install -r requirements.txt
```

## Usage

Only analyze APKs that you own or are authorized to inspect.

```bash
python analyzer.py path/to/app.apk
```

Save a JSON report:

```bash
python analyzer.py path/to/app.apk --json report.json
```

## Example output

```text
== Example IoT App (com.example.iot) ==

Permissions (4)
  - android.permission.CAMERA
  - android.permission.INTERNET
  - android.permission.ACCESS_FINE_LOCATION
  - android.permission.BLUETOOTH_CONNECT

Potentially exported components (1)
  - [activity] com.example.iot.DeepLinkActivity | exported=True

URLs (2)
  - https://api.example.com
  - https://support.example.com

Sensitive API indicators
  - WebView / JavaScript: setJavaScriptEnabled, loadUrl
  - Location: requestLocationUpdates
```

## Current limitations

This is intentionally a small research prototype.

- Sensitive API detection is currently string-based.
- Exported-component interpretation may depend on Android version and manifest behavior.
- URLs may include benign SDK, analytics, documentation, or test endpoints.
- Obfuscation can hide classes, methods, strings, and endpoints.
- Findings require manual validation.

## Possible next steps

I plan to explore:

1. direct method-reference analysis instead of only string matching
2. permission-to-API mapping
3. intent/deep-link extraction
4. taint/data-flow analysis for sensitive sources and sinks
5. comparison of IoT pairing and authentication workflows
6. modeling user-triggered security-sensitive paths relevant to social engineering

## Research context

The broader research question behind this project is:

> How can manipulated user actions expose or activate security-sensitive behavior in IoT companion applications?

A future version could model a path such as:

`Social-engineering trigger -> user action -> app state change -> sensitive API/data flow -> security impact`

## Responsible use

This project is intended for education, defensive research, and analysis of software you are authorized to inspect. It should not be used to access systems or data without permission.

## License

MIT
