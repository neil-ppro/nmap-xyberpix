# Merging upstream Nmap into nmap-ppro

This fork layers features on top of [Nmap](https://github.com/nmap/nmap). Use this checklist when pulling new upstream releases or `master`.

## 1. Add or refresh the git remote

```bash
git remote add upstream https://github.com/nmap/nmap.git   # if missing
git fetch upstream
```

## 2. Merge or rebase

Choose one (project preference: **merge** preserves fork history on shared branches).

```bash
# Merge upstream mainline (example: master)
git checkout master
git merge upstream/master
# or a tag:
# git merge Nmap-7.98
```

Or use the helper (fetches then merges):

```bash
maint/merge-upstream.sh master
```

Resolve conflicts with preference order:

1. **Security-sensitive** nmap-ppro behavior (MCP policy, `http_offsec`, SIEM) — keep fork logic unless upstream clearly supersedes it.
2. **Upstream bug fixes** — usually take upstream hunks for shared files, then re-apply ppro deltas from `maint/FORK-FILES.md` if needed.
3. **Generated / data files** — use `maint/update-nmap-data.sh` where appropriate after merging.

## 3. Rebuild and validate

```bash
./configure
make
```

```bash
cd mcp-nmap-server && python3 -m venv .venv && .venv/bin/pip install -e '.[dev]' && .venv/bin/python -m pytest tests/ -q
```

```bash
python3 maint/check_zenmap_siem_flags.py
python3 maint/check_offsec_mcp_sync.py
python3 maint/check_mcp_longopt_baseline.py
```

If Nmap’s `long_options[]` in `nmap.cc` changed (upstream added/removed long flags), refresh the committed snapshot and re-audit MCP safe mode:

```bash
python3 maint/update_mcp_longopt_baseline.py
python3 maint/check_mcp_longopt_baseline.py
```

If `./nmap` exists:

```bash
maint/siem_ndjson_smoketest.sh ./nmap
```

## 4. Zenmap and docs

After upstream changes to option parsing:

- Compare **long options** in `nmap.cc` / `nmap.h` (or equivalent) with `zenmap/zenmapCore/NmapOptions.py` and the **SIEM & scan policy** tab in `zenmap/zenmapGUI/OptionBuilder.py` / `profile_editor.xml`.
- Run `maint/check_zenmap_siem_flags.py` (nmap-ppro subset + full `long_options[]` parity vs `LONG_OPTIONS`, using `maint/data/zenmap-nmap-longopt-exceptions.txt` for intentional omissions).
- When `maint/update_mcp_longopt_baseline.py` adds new `nmap.cc` names, either extend `NmapOptions.LONG_OPTIONS` and the profile UI, or add an **exceptions** line with a reason.

Update **man page** / **CHANGELOG** if CLI or SIEM schema changed.

## 5. Where the fork touches the tree

See **[maint/FORK-FILES.md](../maint/FORK-FILES.md)** for a categorized list of ppro-specific and high-churn paths. It is **indicative**, not exhaustive — use `git log`, `git diff upstream/master`, and `[nmap-ppro]` entries in [CHANGELOG](../CHANGELOG) when in doubt.

## 6. Release notes

Add user-visible upstream picks and fork-specific fixes under **[CHANGELOG](../CHANGELOG)** in the same style as existing entries.
