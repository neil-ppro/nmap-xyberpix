# `todo/` — upstream archive (not an active checklist)

The `*.txt` files here are **historical Nmap developer / GSoC notes** imported with the tree (per-person backlogs such as Zenmap, Ncat, NSE, nsock). They are **not** maintained as the nmap-xyberpix task list.

**Implication:** There is nothing in this folder that the fork can honestly mark “completed” without actually implementing those upstream-sized items (partial scan results on timeout, Ncat chunked encoding, Zenmap memory audits, etc.).

**Where fork work is tracked instead:**

- Root **`CHANGELOG`** — search for **`[nmap-xyberpix]`** and **`[SIEM]`**.
- **`maint/FORK-FILES.md`** — likely conflict / fork-owned paths.
- **`docs/FORK-MAINTENANCE.md`** — maintainer checklist.

If you want a **live** todo for this repo, use GitHub issues, a project board, or a dedicated file outside this archive (e.g. `todo/nmap-xyberpix-backlog.md`) so it is not confused with these upstream dumps.
