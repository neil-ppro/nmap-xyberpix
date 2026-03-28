# Zenmap install notes (nmap-xyberpix)

Zenmap in this tree targets **Python 3** and **GTK 3** via **PyGObject** (`gi.repository.Gtk`), consistent with upstream Nmap’s current GUI stack.

## Distribution packages (recommended)

Install **Nmap** (or this fork) from your OS so `nmap` and Zenmap’s data files land in the expected prefixes. On many Linux distributions the GUI is a separate package (for example `zenmap` on Debian/Ubuntu).

If you run Zenmap **from a source checkout**, you still need GTK 3 and GObject introspection bindings:

| Platform | Typical packages |
|----------|------------------|
| Debian / Ubuntu | `python3-gi`, `python3-gi-cairo`, `gir1.2-gtk-3.0`, `gir1.2-pango-1.0` |
| Fedora / RHEL | `python3-gobject`, `gtk3` |
| macOS | [Homebrew](https://brew.sh/) `gtk+3`, `pygobject3` (see also the [Nmap install guide](https://nmap.org/book/install.html)) |

## Python / venv

Optional: see [zenmap/requirements.txt](../zenmap/requirements.txt) for a minimal PyPI line (`PyGObject`). The **GTK libraries and `.typelib` files remain system-provided**; the venv only supplies the Python bindings layer.

## Dark mode and HiDPI

- **Dark theme**: GTK respects the desktop theme; some environments also honor `GTK_THEME=Adwaita:dark` when launching Zenmap.
- **HiDPI**: scaling is usually handled by the desktop (Wayland/X11 fractional scaling). For unusual setups, consult your platform’s GTK 3 scaling documentation.

## Related

- Fork overview and security links: [README-nmap-xyberpix.md](../README-nmap-xyberpix.md)
- Building core Nmap: [Nmap Install Guide](https://nmap.org/book/install.html)
