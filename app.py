"""StegoVault - hacker-terminal GUI for encrypted image steganography.

Three modules:
    [ HIDE ]    - encrypt a message/file with a password and embed it in an image.
    [ EXTRACT ] - recover and decrypt a hidden message from a stego image.
    [ DETECT ]  - run steganalysis on any image to judge whether it hides data.

Run with:  python app.py
"""

from __future__ import annotations

import os
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from PIL import Image, ImageTk

from stego import crypto, embed, detect

# --- terminal / "hacker" palette -------------------------------------------
BG = "#050805"          # near-black
PANEL = "#0a0f0a"       # panel black-green
FIELD = "#0d140d"       # input background
GREEN = "#00ff41"       # matrix neon green
GREEN_DIM = "#0aa82e"   # dim green
GREEN_TXT = "#9dffa6"   # readable body green
AMBER = "#ffb000"       # warnings / highlights
RED = "#ff3b3b"         # errors / danger
CYAN = "#22d3ee"
MUTED = "#4c6a4c"       # dim label green-grey
BORDER = "#123a12"

MONO = "Consolas"       # falls back cleanly on Windows
PREVIEW_MAX = (240, 240)

# Bytes the crypto layer adds on top of the raw secret: salt + nonce + GCM tag.
# embed.HEADER_LEN is NOT included - capacity_bytes() already deducts it, so the
# figure below is directly comparable to what that function reports.
OVERHEAD = crypto.SALT_LEN + crypto.NONCE_LEN + crypto.TAG_LEN

BANNER = r"""
 ███████ ████████ ███████  ██████   ██████
 ██         ██    ██      ██       ██    ██
 ███████    ██    █████   ██   ███ ██    ██
      ██    ██    ██      ██    ██ ██    ██
 ███████    ██    ███████  ██████   ██████   V A U L T
"""


def _asset(name: str) -> str:
    """Locate a bundled asset.

    Works both when running from source and when frozen by PyInstaller, which
    unpacks bundled files into a temp dir it advertises as ``sys._MEIPASS``.
    """
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "assets", name)


def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.2f} MB"


class StegoApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("StegoVault :: covert channel toolkit")
        self.geometry("900x680")
        self.minsize(860, 640)
        self.configure(bg=BG)
        try:
            self.iconbitmap(_asset("stegovault.ico"))
        except Exception:
            pass          # the icon is cosmetic - never block startup over it

        self._preview_refs: dict[str, ImageTk.PhotoImage] = {}
        self._preview_widgets: dict[str, tk.Label] = {}
        self._setup_style()
        self._build_header()

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=14, pady=(6, 4))
        self._build_hide_tab(nb)
        self._build_extract_tab(nb)
        self._build_detect_tab(nb)

        self._build_statusbar()
        self._log("system online :: AES-256-GCM | LSB-EMBED | STEGANALYSIS ready")

    # -- styling -------------------------------------------------------------
    def _setup_style(self) -> None:
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure("TNotebook", background=BG, borderwidth=0)
        s.configure("TNotebook.Tab", background=PANEL, foreground=GREEN_DIM,
                    padding=(26, 9), font=(MONO, 10, "bold"), borderwidth=1)
        s.map("TNotebook.Tab",
              background=[("selected", BG)],
              foreground=[("selected", GREEN)],
              bordercolor=[("selected", GREEN)])
        s.configure("TFrame", background=PANEL)
        s.configure("TLabel", background=PANEL, foreground=GREEN_TXT, font=(MONO, 10))
        s.configure("Muted.TLabel", background=PANEL, foreground=MUTED, font=(MONO, 9))
        s.configure("Head.TLabel", background=PANEL, foreground=GREEN, font=(MONO, 11, "bold"))
        s.configure("Accent.TButton", background=BG, foreground=GREEN,
                    font=(MONO, 10, "bold"), borderwidth=1, padding=(16, 9),
                    bordercolor=GREEN, relief="solid")
        s.map("Accent.TButton",
              background=[("active", GREEN_DIM)],
              foreground=[("active", BG)])
        s.configure("Ghost.TButton", background=PANEL, foreground=GREEN_DIM,
                    font=(MONO, 9, "bold"), borderwidth=1, padding=(10, 6),
                    bordercolor=BORDER, relief="solid")
        s.map("Ghost.TButton",
              background=[("active", FIELD)], foreground=[("active", GREEN)])
        s.configure("TEntry", fieldbackground=FIELD, foreground=GREEN,
                    insertcolor=GREEN, borderwidth=1, padding=6, bordercolor=BORDER)
        s.map("TEntry", bordercolor=[("focus", GREEN)])
        s.configure("TRadiobutton", background=PANEL, foreground=GREEN_TXT,
                    font=(MONO, 10))
        s.map("TRadiobutton", background=[("active", PANEL)],
              foreground=[("active", GREEN)])
        s.configure("Cap.Horizontal.TProgressbar", background=GREEN,
                    troughcolor=FIELD, borderwidth=1, bordercolor=BORDER)
        s.configure("Score.Horizontal.TProgressbar", background=AMBER,
                    troughcolor=FIELD, borderwidth=1, bordercolor=BORDER)

    def _build_header(self) -> None:
        head = tk.Frame(self, bg=BG)
        head.pack(fill="x", padx=14, pady=(10, 0))
        banner = tk.Label(head, text=BANNER, bg=BG, fg=GREEN,
                          font=(MONO, 9, "bold"), justify="left", anchor="w")
        banner.pack(anchor="w")
        sub = tk.Label(
            head,
            text="  [ encrypted image steganography + steganalysis ]   root@stegovault:~#",
            bg=BG, fg=GREEN_DIM, font=(MONO, 9), anchor="w")
        sub.pack(anchor="w", pady=(0, 4))
        tk.Frame(head, bg=GREEN, height=1).pack(fill="x")

    def _build_statusbar(self) -> None:
        bar = tk.Frame(self, bg=BG)
        bar.pack(fill="x", side="bottom")
        tk.Frame(bar, bg=GREEN_DIM, height=1).pack(fill="x")
        self.status = tk.Label(bar, text="", bg=BG, fg=GREEN_DIM,
                               font=(MONO, 9), anchor="w", padx=14, pady=5)
        self.status.pack(fill="x")

    def _log(self, msg: str, level: str = "ok") -> None:
        color = {"ok": GREEN_DIM, "warn": AMBER, "err": RED, "hit": GREEN}[level]
        prefix = {"ok": "[*]", "warn": "[!]", "err": "[x]", "hit": "[+]"}[level]
        self.status.configure(text=f"{prefix} {msg}", fg=color)

    # -- shared widgets ------------------------------------------------------
    def _file_row(self, parent, label, var, browse_cmd):
        row = ttk.Frame(parent)
        row.pack(fill="x", pady=6)
        ttk.Label(row, text=label, width=16).pack(side="left")
        ttk.Entry(row, textvariable=var).pack(side="left", fill="x", expand=True, padx=(0, 8))
        ttk.Button(row, text="[ browse ]", style="Ghost.TButton", command=browse_cmd).pack(side="left")
        return row

    def _preview_label(self, parent, key):
        holder = tk.Frame(parent, bg=BG, width=PREVIEW_MAX[0], height=PREVIEW_MAX[1],
                          highlightbackground=BORDER, highlightthickness=1)
        holder.pack_propagate(False)
        lbl = tk.Label(holder, text="[ no signal ]", bg=BG, fg=MUTED, font=(MONO, 9))
        lbl.pack(fill="both", expand=True)
        self._preview_widgets[key] = lbl
        return holder

    def _show_preview(self, key, path):
        lbl = self._preview_widgets[key]
        try:
            img = Image.open(path).convert("RGB")
            img.thumbnail(PREVIEW_MAX)
            photo = ImageTk.PhotoImage(img)
            self._preview_refs[key] = photo
            lbl.configure(image=photo, text="")
        except Exception:
            lbl.configure(image="", text="[ cannot preview ]")

    def _console(self, parent, height, fg=GREEN):
        txt = tk.Text(parent, height=height, bg=BG, fg=fg, insertbackground=GREEN,
                      relief="flat", font=(MONO, 10), wrap="word", padx=10, pady=8,
                      highlightbackground=BORDER, highlightthickness=1)
        return txt

    # ===================================================================
    #  HIDE TAB
    # ===================================================================
    def _build_hide_tab(self, nb):
        tab = ttk.Frame(nb, padding=16)
        nb.add(tab, text="[ HIDE ]")
        left = ttk.Frame(tab); left.pack(side="left", fill="both", expand=True, padx=(0, 16))
        right = ttk.Frame(tab); right.pack(side="left", fill="y")

        ttk.Label(left, text="> 01_ select carrier", style="Head.TLabel").pack(anchor="w")
        self.hide_img = tk.StringVar()
        self._file_row(left, "target_img", self.hide_img, self._pick_hide_image)
        self.cap_label = ttk.Label(left, text="capacity: ---", style="Muted.TLabel")
        self.cap_label.pack(anchor="w")
        self.cap_bar = ttk.Progressbar(left, style="Cap.Horizontal.TProgressbar", maximum=100)
        self.cap_bar.pack(fill="x", pady=(4, 12))

        ttk.Label(left, text="> 02_ payload", style="Head.TLabel").pack(anchor="w")
        self.hide_mode = tk.StringVar(value="text")
        mrow = ttk.Frame(left); mrow.pack(anchor="w", pady=(2, 6))
        ttk.Radiobutton(mrow, text="text", variable=self.hide_mode, value="text",
                        command=self._toggle_hide_mode).pack(side="left", padx=(0, 16))
        ttk.Radiobutton(mrow, text="file", variable=self.hide_mode, value="file",
                        command=self._toggle_hide_mode).pack(side="left")

        # Both payload editors live inside ONE holder that is packed exactly
        # once, right here. Swapping them inside it keeps "03_ crypto key" and
        # the embed button anchored. Packing them straight into `left` would
        # append the re-shown frame to the END of the pack order, dropping the
        # file picker below the button every time the mode changed.
        self.payload_holder = ttk.Frame(left)
        self.payload_holder.pack(fill="both", expand=True)

        self.text_frame = ttk.Frame(self.payload_holder)
        self.msg_text = self._console(self.text_frame, 6)
        self.msg_text.pack(fill="both", expand=True)
        self.msg_text.bind("<KeyRelease>", lambda e: self._update_capacity())

        self.file_frame = ttk.Frame(self.payload_holder)
        self.hide_file = tk.StringVar()
        self._file_row(self.file_frame, "secret_file", self.hide_file, self._pick_secret_file)

        ttk.Label(left, text="> 03_ crypto key", style="Head.TLabel").pack(anchor="w", pady=(12, 0))
        self.hide_pw = tk.StringVar(); self.hide_pw2 = tk.StringVar()
        pr = ttk.Frame(left); pr.pack(fill="x", pady=6)
        ttk.Label(pr, text="passphrase", width=16).pack(side="left")
        ttk.Entry(pr, textvariable=self.hide_pw, show="*").pack(side="left", fill="x", expand=True)
        pr2 = ttk.Frame(left); pr2.pack(fill="x", pady=(0, 10))
        ttk.Label(pr2, text="confirm", width=16).pack(side="left")
        ttk.Entry(pr2, textvariable=self.hide_pw2, show="*").pack(side="left", fill="x", expand=True)

        ttk.Button(left, text=">> ENCRYPT & EMBED", style="Accent.TButton",
                   command=self._do_hide).pack(anchor="w", pady=(4, 0))

        ttk.Label(right, text="[ carrier preview ]", style="Muted.TLabel").pack(anchor="w")
        self._preview_label(right, "hide").pack(pady=(4, 0))
        self._toggle_hide_mode()

    def _toggle_hide_mode(self):
        """Swap the text editor and the file picker inside ``payload_holder``.

        Order within the tab never changes: only the holder's contents do.
        """
        if self.hide_mode.get() == "text":
            self.file_frame.pack_forget()
            self.text_frame.pack(fill="both", expand=True)
        else:
            self.text_frame.pack_forget()
            self.file_frame.pack(fill="x", anchor="n")
        self._update_capacity()

    def _pick_hide_image(self):
        path = filedialog.askopenfilename(
            title="select carrier image",
            filetypes=[("Images", "*.png *.bmp *.tiff *.jpg *.jpeg"), ("All", "*.*")])
        if path:
            self.hide_img.set(path)
            self._show_preview("hide", path)
            self._update_capacity()
            self._log(f"carrier loaded :: {os.path.basename(path)}")

    def _pick_secret_file(self):
        path = filedialog.askopenfilename(title="select file to hide")
        if path:
            self.hide_file.set(path)
            self._update_capacity()

    def _payload_size(self) -> int:
        if self.hide_mode.get() == "text":
            data = len(self.msg_text.get("1.0", "end-1c").encode("utf-8"))
        else:
            p = self.hide_file.get()
            data = os.path.getsize(p) if p and os.path.isfile(p) else 0
        return data + OVERHEAD

    def _update_capacity(self):
        path = self.hide_img.get()
        if not path or not os.path.isfile(path):
            self.cap_label.configure(text="capacity: ---"); self.cap_bar["value"] = 0
            return
        try:
            cap = embed.capacity_bytes(path)
        except Exception:
            self.cap_label.configure(text="capacity: [unreadable]"); return
        used = self._payload_size()
        pct = min(100, used * 100 / cap) if cap > 0 else 100
        self.cap_bar["value"] = pct
        color = GREEN if used <= cap else RED
        self.cap_label.configure(
            text=f"capacity: {_fmt_bytes(cap)}  ::  using ~{_fmt_bytes(used)} ({pct:.0f}%)",
            foreground=color)

    def _do_hide(self):
        img = self.hide_img.get()
        if not img or not os.path.isfile(img):
            self._log("no carrier image selected", "err")
            return messagebox.showerror("StegoVault", "Select a carrier image.")
        pw, pw2 = self.hide_pw.get(), self.hide_pw2.get()
        if not pw:
            self._log("passphrase empty", "err")
            return messagebox.showerror("StegoVault", "Enter a passphrase.")
        if pw != pw2:
            self._log("passphrase mismatch", "err")
            return messagebox.showerror("StegoVault", "Passphrases do not match.")

        if self.hide_mode.get() == "text":
            secret = self.msg_text.get("1.0", "end-1c").encode("utf-8")
            if not secret:
                self._log("payload empty", "err")
                return messagebox.showerror("StegoVault", "The message is empty.")
        else:
            fp = self.hide_file.get()
            if not fp or not os.path.isfile(fp):
                self._log("no payload file", "err")
                return messagebox.showerror("StegoVault", "Select a file to hide.")
            with open(fp, "rb") as f:
                secret = f.read()

        out = filedialog.asksaveasfilename(
            title="save stego image as", defaultextension=".png",
            filetypes=[("PNG image", "*.png")],
            initialfile="stego_" + os.path.splitext(os.path.basename(img))[0] + ".png")
        if not out:
            return
        self._log("encrypting payload...", "warn")

        def work():
            try:
                blob = crypto.encrypt(secret, pw)
                embed.embed(img, blob, out)
                self.after(0, lambda: (
                    self._log(f"payload embedded -> {os.path.basename(out)}", "hit"),
                    messagebox.showinfo("StegoVault",
                        f"[+] SUCCESS\n\nEncrypted {_fmt_bytes(len(secret))} and embedded into:\n{out}\n\n"
                        "The image looks identical but now carries your secret.")))
            except embed.CapacityError as e:
                self.after(0, lambda: (self._log("payload exceeds capacity", "err"),
                                       messagebox.showerror("Too big", str(e))))
            except Exception as e:
                self.after(0, lambda err=e: (self._log(str(err), "err"),
                                             messagebox.showerror("StegoVault", str(err))))

        threading.Thread(target=work, daemon=True).start()

    # ===================================================================
    #  EXTRACT TAB
    # ===================================================================
    def _build_extract_tab(self, nb):
        tab = ttk.Frame(nb, padding=16)
        nb.add(tab, text="[ EXTRACT ]")
        left = ttk.Frame(tab); left.pack(side="left", fill="both", expand=True, padx=(0, 16))
        right = ttk.Frame(tab); right.pack(side="left", fill="y")

        ttk.Label(left, text="> decrypt hidden payload", style="Head.TLabel").pack(anchor="w")
        self.ext_img = tk.StringVar()
        self._file_row(left, "stego_img", self.ext_img, self._pick_ext_image)

        pr = ttk.Frame(left); pr.pack(fill="x", pady=6)
        ttk.Label(pr, text="passphrase", width=16).pack(side="left")
        self.ext_pw = tk.StringVar()
        ttk.Entry(pr, textvariable=self.ext_pw, show="*").pack(side="left", fill="x", expand=True)

        br = ttk.Frame(left); br.pack(anchor="w", pady=6)
        ttk.Button(br, text=">> EXTRACT & DECRYPT", style="Accent.TButton",
                   command=self._do_extract).pack(side="left", padx=(0, 8))
        ttk.Button(br, text="[ save as file ]", style="Ghost.TButton",
                   command=self._save_extracted).pack(side="left")

        ttk.Label(left, text="[ recovered payload ]", style="Muted.TLabel").pack(anchor="w", pady=(10, 2))
        self.ext_out = self._console(left, 10, fg=GREEN)
        self.ext_out.pack(fill="both", expand=True)
        self._extracted_bytes: bytes | None = None

        ttk.Label(right, text="[ stego preview ]", style="Muted.TLabel").pack(anchor="w")
        self._preview_label(right, "ext").pack(pady=(4, 0))

    def _pick_ext_image(self):
        path = filedialog.askopenfilename(
            title="select stego image", filetypes=[("Images", "*.png *.bmp *.tiff"), ("All", "*.*")])
        if path:
            self.ext_img.set(path); self._show_preview("ext", path)
            self._log(f"stego image loaded :: {os.path.basename(path)}")

    def _do_extract(self):
        img = self.ext_img.get()
        if not img or not os.path.isfile(img):
            self._log("no stego image selected", "err")
            return messagebox.showerror("StegoVault", "Select a stego image.")
        pw = self.ext_pw.get()
        if not pw:
            self._log("passphrase empty", "err")
            return messagebox.showerror("StegoVault", "Enter the passphrase.")

        self.ext_out.delete("1.0", "end")
        self._log("scanning LSB channel...", "warn")
        try:
            blob = embed.extract(img)
            plain = crypto.decrypt(blob, pw)
        except embed.NoHiddenDataError as e:
            self._log("no hidden payload found", "warn")
            return messagebox.showwarning("Nothing found", str(e))
        except crypto.DecryptionError as e:
            self._log("decryption failed :: bad key or tampered", "err")
            return messagebox.showerror("Cannot decrypt", str(e))
        except Exception as e:
            self._log(str(e), "err")
            return messagebox.showerror("StegoVault", str(e))

        self._extracted_bytes = plain
        try:
            self.ext_out.configure(fg=GREEN)
            self.ext_out.insert("1.0", plain.decode("utf-8"))
            self._log(f"payload decrypted :: {_fmt_bytes(len(plain))}", "hit")
        except UnicodeDecodeError:
            self.ext_out.configure(fg=AMBER)
            self.ext_out.insert("1.0", f"[ binary payload recovered: {_fmt_bytes(len(plain))} ]\n"
                                       "use [ save as file ] to write it to disk.")
            self._log(f"binary payload recovered :: {_fmt_bytes(len(plain))}", "hit")

    def _save_extracted(self):
        if not self._extracted_bytes:
            return messagebox.showinfo("StegoVault", "Nothing extracted yet.")
        out = filedialog.asksaveasfilename(title="save recovered data")
        if out:
            with open(out, "wb") as f:
                f.write(self._extracted_bytes)
            self._log(f"payload written -> {os.path.basename(out)}", "hit")
            messagebox.showinfo("StegoVault", f"Saved to {out}")

    # ===================================================================
    #  DETECT TAB
    # ===================================================================
    def _build_detect_tab(self, nb):
        tab = ttk.Frame(nb, padding=16)
        nb.add(tab, text="[ DETECT ]")
        left = ttk.Frame(tab); left.pack(side="left", fill="both", expand=True, padx=(0, 16))
        right = ttk.Frame(tab); right.pack(side="left", fill="y")

        ttk.Label(left, text="> steganalysis scan", style="Head.TLabel").pack(anchor="w")
        self.det_img = tk.StringVar()
        self._file_row(left, "scan_target", self.det_img, self._pick_det_image)
        ttk.Button(left, text=">> RUN ANALYSIS", style="Accent.TButton",
                   command=self._do_detect).pack(anchor="w", pady=(4, 12))

        ttk.Label(left, text="[ suspicion score ]", style="Muted.TLabel").pack(anchor="w")
        self.score_bar = ttk.Progressbar(left, style="Score.Horizontal.TProgressbar", maximum=100)
        self.score_bar.pack(fill="x", pady=(4, 4))
        self.verdict_lbl = tk.Label(left, text="[ idle ]", bg=PANEL, fg=MUTED,
                                    font=(MONO, 13, "bold"), anchor="w")
        self.verdict_lbl.pack(anchor="w", pady=(2, 10))

        ttk.Label(left, text="[ analysis log ]", style="Muted.TLabel").pack(anchor="w")
        self.det_out = self._console(left, 10, fg=GREEN_TXT)
        self.det_out.pack(fill="both", expand=True)

        ttk.Label(right, text="[ scan target ]", style="Muted.TLabel").pack(anchor="w")
        self._preview_label(right, "det").pack(pady=(4, 0))

    def _pick_det_image(self):
        path = filedialog.askopenfilename(
            title="select image to analyze",
            filetypes=[("Images", "*.png *.bmp *.tiff *.jpg *.jpeg"), ("All", "*.*")])
        if path:
            self.det_img.set(path); self._show_preview("det", path)
            self._log(f"scan target loaded :: {os.path.basename(path)}")

    def _do_detect(self):
        img = self.det_img.get()
        if not img or not os.path.isfile(img):
            self._log("no scan target selected", "err")
            return messagebox.showerror("StegoVault", "Select an image.")
        self.det_out.delete("1.0", "end")
        self.verdict_lbl.configure(text="[ analyzing... ]", fg=AMBER)
        self._log("running RS analysis + LSB statistics...", "warn")
        self.update_idletasks()

        def work():
            try:
                r = detect.analyze(img)
            except Exception as e:
                self.after(0, lambda err=e: (self._log(str(err), "err"),
                                             messagebox.showerror("StegoVault", str(err))))
                return
            self.after(0, lambda: self._show_detect(r))

        threading.Thread(target=work, daemon=True).start()

    def _show_detect(self, r: dict):
        self.score_bar["value"] = r["score"]
        if r["score"] >= 80:
            color, lvl = RED, "hit"
        elif r["score"] >= 45:
            color, lvl = AMBER, "warn"
        else:
            color, lvl = GREEN, "ok"
        self.verdict_lbl.configure(text=f">> {r['verdict']}  [{r['score']}/100]", fg=color)
        lines = [
            f"marker_present  : {'YES :: StegoVault payload' if r['marker'] else 'no'}",
            f"rs_embed_rate   : {r['rs_rate']:.3f}   (0=clean / 1=fully embedded)",
            f"lsb_ratio       : {r['lsb_ratio']:.4f}   (natural ~0.42-0.48 / hidden ~0.50)",
            "",
            "notes:",
        ]
        lines += [f"  > {n}" for n in r["notes"]]
        self.det_out.insert("1.0", "\n".join(lines))
        self._log(f"scan complete :: score {r['score']}/100", lvl)


if __name__ == "__main__":
    StegoApp().mainloop()
