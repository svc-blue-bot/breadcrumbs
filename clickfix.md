---
layout: default
title: ClickFix
permalink: /clickfix/
---

# ClickFix

A lab experiment analysing a fake “ClickFix” support tool: what it does, how it persists,
and what artefacts it leaves behind.

## Scenario

- Host OS:
- Initial access:
- Payload / tooling:
- Goal of the exercise:

---

## Timeline

1. User executes installer
2. Tool phones home
3. Persistence is established
4. Cleanup / uninstall attempt

---

## Artefacts

### Disk

- Install path:
- Dropped files:
- Interesting config / logs:

### Registry / Persistence

- Run keys / services:
- Scheduled tasks:
- Other autostart locations:

### Logs & Telemetry

- Event IDs worth watching:
- Network traces:
- EDR / AV alerts (if any):

---

## Detection & Hunting Ideas

- Suggested Sigma-style log conditions
- Example hunt queries (e.g. Splunk / KQL style)
- Things that *won’t* be reliably detectable

---

## Limitations

- Lab environment assumptions
- What might look different on other OS versions / configs
