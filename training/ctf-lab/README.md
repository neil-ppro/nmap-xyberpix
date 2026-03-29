# CTF / training lab (nmap-xyberpix)

Local-only targets for practicing **authorized** scanning workflows with this fork.

## Quick start

```bash
cd training/ctf-lab
docker compose up --build -d
```

Services:

- **web**: HTTP on **127.0.0.1:18080** (nginx + static banner page).

Stop: `docker compose down`.

## Suggested objectives

1. **Host discovery**: `nmap -sn 127.0.0.1` (confirm stack is up).
2. **Port + service**: `nmap -sT -p 18080 127.0.0.1 -sV --reason`
3. **SIEM**: add `--siem-log ./lab.siem.jsonl --siem-tag ctf=lab` and inspect `scan_start` / `port` lines.
4. **Profiles**: in **xyberpix-gui**, load built-in **Polite + SIEM lab**, set targets to `127.0.0.1`, ports `18080`, run scan.

Expected: **open** TCP **18080**, service **http**.

## Profile import (GUI)

The file `profile_ctf_lab.json` matches **xyberpix-gui** `nmap/profiles_v2` shape (v2). To import manually: open **Settings** / use **Save profile** in the GUI after setting fields, or merge the JSON into your platform **QSettings** export—simplest path is to replicate the options in the GUI using this README.

## Scope

The compose file binds to **loopback** only. Do not expose these containers on a shared LAN without hardening images and adding your own network policy.
