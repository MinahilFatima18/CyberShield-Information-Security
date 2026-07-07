"""
CyberShield - Information Security Project
==========================================
Run in Thonny (Python 3.7+).
Requirements:  pip install requests opencv-python
Video frames:  place the 'frames' folder next to this file
               (run extract_frames.py once if needed)
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import hashlib, datetime, re, threading, random, math, os, glob

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ═══════════════════════════════════════════════════════════════════════════════
#  COLOUR PALETTE
# ═══════════════════════════════════════════════════════════════════════════════
C = {
    "bg_dark":      "#070b1a",
    "bg_panel":     "#0d1535",
    "bg_sidebar":   "#080e22",
    "bg_input":     "#0a1228",
    "accent_cyan":  "#00e5ff",
    "accent_pink":  "#ff00aa",
    "accent_green": "#00ff88",
    "accent_orange":"#ff8c00",
    "accent_red":   "#ff2244",
    "accent_yellow":"#ffd700",
    "text_white":   "#e8f4ff",
    "text_dim":     "#6a8ab0",
    "border":       "#1a2d5a",
    "sidebar_sel":  "#0d3a6e",
    "btn_blue":     "#1565c0",
}

FONT_HEAD  = ("Consolas", 13, "bold")
FONT_BODY  = ("Consolas", 10)
FONT_SMALL = ("Consolas", 9)
FONT_MONO  = ("Courier New", 9)

# ═══════════════════════════════════════════════════════════════════════════════
#  URL SCANNER
# ═══════════════════════════════════════════════════════════════════════════════
PHISHING_KEYWORDS = [
    "login","signin","secure","verify","account","update","banking",
    "paypal","amazon","apple","microsoft","ebay","password","confirm",
    "credential","wallet","lucky","winner","free","prize","click",
    "urgent","suspended","limited","webscr","cmd=","dispatch","phish","hack",
]
SUSPICIOUS_TLDS = [".xyz",".tk",".ml",".ga",".cf",".gq",".pw",".top",".click",".link"]
SAFE_DOMAINS = [
    "google.com","youtube.com","github.com","wikipedia.org","microsoft.com",
    "apple.com","amazon.com","facebook.com","twitter.com","instagram.com",
    "linkedin.com","openai.com","anthropic.com","stackoverflow.com","reddit.com",
]

def analyse_url(url: str) -> dict:
    result = {
        "risk_score": 0, "risk_level": "Low",
        "status": "safe website", "status_detail": "The website appears safe.",
        "https": False, "domain_age_label": "Unknown",
        "suspicious_kw_count": 0, "url_length": len(url),
        "subdomain_count": 0, "has_hyphens": False, "details": [],
    }
    if not url.startswith(("http://","https://")):
        url = "http://" + url
    score = 0
    if url.startswith("https://"):
        result["https"] = True
    else:
        score += 20
        result["details"].append("No HTTPS – connection is unencrypted")

    try:
        from urllib.parse import urlparse
        parsed   = urlparse(url)
        hostname = parsed.hostname or ""
    except Exception:
        hostname = ""

    parts       = hostname.split(".")
    domain_main = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    if "-" in domain_main:
        result["has_hyphens"] = True
        score += 10
        result["details"].append("Hyphens found in domain name")

    subdomains = len(parts) - 2 if len(parts) > 2 else 0
    result["subdomain_count"] = subdomains
    if subdomains > 2:
        score += 15
        result["details"].append(f"Excessive subdomains ({subdomains})")

    url_lower = url.lower()
    kw_hits   = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
    result["suspicious_kw_count"] = len(kw_hits)
    score += len(kw_hits) * 8
    if kw_hits:
        result["details"].append(f"Suspicious keywords: {', '.join(kw_hits[:5])}")

    if len(url) > 100:
        score += 10
        result["details"].append(f"Very long URL ({len(url)} chars)")

    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            score += 20
            result["details"].append(f"Suspicious TLD: {tld}")
            break

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname):
        score += 25
        result["details"].append("URL uses IP address instead of domain")

    for safe in SAFE_DOMAINS:
        if hostname == safe or hostname.endswith("." + safe):
            score = max(0, score - 30)
            result["domain_age_label"] = "Good"
            result["details"].append(f"Domain matches trusted list: {safe}")
            break
    else:
        result["domain_age_label"] = "Unknown"

    if REQUESTS_AVAILABLE:
        try:
            resp = requests.head(url, timeout=5, allow_redirects=True,
                                 headers={"User-Agent": "CyberShield/1.0"})
            if resp.status_code >= 400:
                score += 10
                result["details"].append(f"HTTP {resp.status_code} response")
            try:
                from urllib.parse import urlparse as _up
                final_host = _up(resp.url).hostname or ""
                if final_host and final_host != hostname:
                    score += 15
                    result["details"].append(f"Redirects to different domain: {final_host}")
            except Exception:
                pass
        except Exception as ex:
            result["details"].append(f"Could not reach URL: {type(ex).__name__}")

    score = max(0, min(100, score))
    result["risk_score"] = score
    if score <= 25:
        result["risk_level"]    = "Low"
        result["status"]        = "safe website"
        result["status_detail"] = "The website appears safe."
    elif score <= 55:
        result["risk_level"]    = "Medium"
        result["status"]        = "suspicious website"
        result["status_detail"] = "Proceed with caution."
    else:
        result["risk_level"]    = "High"
        result["status"]        = "phishing / dangerous"
        result["status_detail"] = "Do NOT visit this website!"

    if not result["details"]:
        result["details"].append("No obvious threats detected.")
    return result

# ═══════════════════════════════════════════════════════════════════════════════
#  RSA HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
def is_prime(n):
    if n < 2: return False
    for i in range(2, int(n**0.5)+1):
        if n % i == 0: return False
    return True

def generate_rsa_keys():
    primes = [p for p in range(50, 300) if is_prime(p)]
    while True:
        p, q = random.sample(primes, 2)
        n, phi = p*q, (p-1)*(q-1)
        e = 65537
        if math.gcd(e, phi) == 1 and n > 127:
            def ext_gcd(a, b):
                if b == 0: return a, 1, 0
                g, x, y = ext_gcd(b, a%b)
                return g, y, x-(a//b)*y
            _, x, _ = ext_gcd(e, phi)
            d = x % phi
            return (e, n), (d, n)

def rsa_encrypt(message, pub_key):
    e, n = pub_key
    return " ".join(str(pow(ord(c), e, n)) for c in message)

def rsa_decrypt(cipher, priv_key):
    d, n = priv_key
    try:
        return "".join(chr(pow(int(x), d, n)) for x in cipher.strip().split())
    except Exception:
        return "Decryption error"

# ═══════════════════════════════════════════════════════════════════════════════
#  COLOUR UTILITY
# ═══════════════════════════════════════════════════════════════════════════════
def _lighten(hex_color, amount=30):
    try:
        h = hex_color.lstrip("#")
        r,g,b = int(h[0:2],16),int(h[2:4],16),int(h[4:6],16)
        return f"#{min(255,r+amount):02x}{min(255,g+amount):02x}{min(255,b+amount):02x}"
    except Exception:
        return hex_color

scan_history = []

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN APP
# ═══════════════════════════════════════════════════════════════════════════════
class CyberShieldApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("CyberShield – Information Security Project")
        self.geometry("1300x800")
        self.minsize(1100, 720)
        self.configure(bg=C["bg_dark"])
        self.resizable(True, True)

        self.rsa_pub = self.rsa_priv = None
        self._gen_rsa_keys()

        # Video frames
        self._video_frames = []
        self._video_idx    = 0
        self._video_job    = None
        self._load_video_frames()

        self._build_ui()
        self._show_page("dashboard")

    def _gen_rsa_keys(self):
        self.rsa_pub, self.rsa_priv = generate_rsa_keys()

    # ── Load video frames from ./frames/ folder ──────────────────────────────
    def _load_video_frames(self):
        base = os.path.dirname(os.path.abspath(__file__))
        frames_dir = os.path.join(base, "frames")
        paths = sorted(glob.glob(os.path.join(frames_dir, "f*.png")))
        if not paths:
            return
        try:
            from PIL import Image, ImageTk
            for p in paths:
                img = Image.open(p).resize((248, 150), Image.LANCZOS)
                self._video_frames.append(ImageTk.PhotoImage(img))
        except ImportError:
            # Fallback: use tkinter PhotoImage directly (PNG only, no resize)
            try:
                for p in paths[::3]:  # every 3rd frame to limit memory
                    self._video_frames.append(tk.PhotoImage(file=p))
            except Exception:
                pass

    def _start_video(self):
        if not self._video_frames or not hasattr(self, "_vid_label"):
            return
        self._animate_video()

    def _animate_video(self):
        if not self._video_frames or not hasattr(self, "_vid_label"):
            return
        try:
            frame = self._video_frames[self._video_idx % len(self._video_frames)]
            self._vid_label.config(image=frame)
            self._vid_label.image = frame
            self._video_idx += 1
            # ~24 fps → 42ms per frame; slow to 80ms for smoothness
            self._video_job = self.after(80, self._animate_video)
        except Exception:
            pass

    # ═════════════════════════════════════════════════════════════════════════
    #  UI SKELETON
    # ═════════════════════════════════════════════════════════════════════════
    def _build_ui(self):
        # Sidebar
        self.sidebar = tk.Frame(self, bg=C["bg_sidebar"], width=205)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        logo_f = tk.Frame(self.sidebar, bg=C["bg_sidebar"])
        logo_f.pack(fill="x", pady=(16,6))
        tk.Label(logo_f, text="🛡", font=("Consolas",32),
                 bg=C["bg_sidebar"], fg=C["accent_cyan"]).pack()
        tk.Label(logo_f, text="CyberShield", font=("Consolas",13,"bold"),
                 bg=C["bg_sidebar"], fg=C["accent_cyan"]).pack()
        tk.Label(logo_f, text="Cybersecurity Awareness",
                 font=FONT_SMALL, bg=C["bg_sidebar"], fg=C["text_dim"],
                 wraplength=170, justify="center").pack(pady=(2,8))

        tk.Frame(self.sidebar, bg=C["border"], height=1).pack(fill="x", padx=10)

        self.nav_buttons = {}
        nav_items = [
            ("🏠  Dashboard",      "dashboard"),
            ("🔍  URL Scanner",    "scanner"),
            ("🔒  SHA-256 Hash",   "sha256"),
            ("🔑  RSA Encryption", "rsa"),
            ("📊  Scan History",   "history"),
            ("📘  IS Concepts",    "concepts"),
            ("ℹ   About",          "about"),
        ]
        for label, key in nav_items:
            btn = tk.Button(
                self.sidebar, text=label, anchor="w",
                font=("Consolas",11), relief="flat", bd=0,
                bg=C["bg_sidebar"], fg=C["text_white"],
                activebackground=C["sidebar_sel"], activeforeground=C["accent_cyan"],
                padx=18, pady=10, cursor="hand2",
                command=lambda k=key: self._show_page(k)
            )
            btn.pack(fill="x")
            btn.bind("<Enter>", lambda e,b=btn: b.config(bg=C["sidebar_sel"], fg=C["accent_cyan"]))
            btn.bind("<Leave>", lambda e,b=btn,k2=key: b.config(
                bg=C["sidebar_sel"] if self._current_page==k2 else C["bg_sidebar"],
                fg=C["accent_cyan"] if self._current_page==k2 else C["text_white"]
            ))
            self.nav_buttons[key] = btn

        self._current_page = "dashboard"

        self.content = tk.Frame(self, bg=C["bg_dark"])
        self.content.pack(side="left", fill="both", expand=True)

        self.pages = {}
        for name, builder in [
            ("dashboard", self._build_dashboard),
            ("scanner",   self._build_scanner),
            ("sha256",    self._build_sha256),
            ("rsa",       self._build_rsa),
            ("history",   self._build_history),
            ("concepts",  self._build_concepts),
            ("about",     self._build_about),
        ]:
            frame = tk.Frame(self.content, bg=C["bg_dark"])
            builder(frame)
            self.pages[name] = frame

    def _show_page(self, name):
        self._current_page = name
        for n, f in self.pages.items():
            f.pack_forget()
        self.pages[name].pack(fill="both", expand=True)
        for key, btn in self.nav_buttons.items():
            btn.config(
                bg=C["sidebar_sel"] if key==name else C["bg_sidebar"],
                fg=C["accent_cyan"] if key==name else C["text_white"]
            )
        if name == "history":
            self._refresh_history()
        if name == "dashboard":
            self._start_video()
        elif self._video_job:
            self.after_cancel(self._video_job)
            self._video_job = None

    # ═════════════════════════════════════════════════════════════════════════
    #  HELPER WIDGETS
    # ═════════════════════════════════════════════════════════════════════════
    def _card(self, parent, title, title_color=None):
        outer = tk.Frame(parent, bg=C["border"], bd=0)
        inner = tk.Frame(outer, bg=C["bg_panel"])
        inner.pack(fill="both", expand=True, padx=1, pady=1)
        if title:
            tk.Label(inner, text=title, font=FONT_HEAD,
                     bg=C["bg_panel"], fg=title_color or C["accent_cyan"]
                     ).pack(anchor="w", padx=14, pady=(10,4))
        return outer, inner

    def _entry(self, parent, placeholder="", width=40):
        e = tk.Entry(parent, font=FONT_BODY, bg=C["bg_input"], fg=C["text_white"],
                     insertbackground=C["accent_cyan"], relief="flat", bd=0,
                     highlightthickness=1, highlightbackground=C["border"],
                     highlightcolor=C["accent_cyan"], width=width)
        if placeholder:
            e.insert(0, placeholder); e.config(fg=C["text_dim"])
            e.bind("<FocusIn>",  lambda ev,en=e,ph=placeholder: (en.delete(0,"end"), en.config(fg=C["text_white"])) if en.get()==ph else None)
            e.bind("<FocusOut>", lambda ev,en=e,ph=placeholder: (en.insert(0,ph), en.config(fg=C["text_dim"])) if not en.get() else None)
        return e

    def _btn(self, parent, text, command, color=None, fg=None, width=None):
        kw = dict(text=text, command=command, font=("Consolas",10,"bold"),
                  relief="flat", bd=0, cursor="hand2", padx=12, pady=7,
                  bg=color or C["accent_cyan"], fg=fg or C["bg_dark"])
        if width: kw["width"] = width
        b = tk.Button(parent, **kw)
        orig = color or C["accent_cyan"]
        b.bind("<Enter>", lambda e: b.config(bg=_lighten(orig)))
        b.bind("<Leave>", lambda e: b.config(bg=orig))
        return b

    # ═════════════════════════════════════════════════════════════════════════
    #  GAUGE  – perfect circle arc, cyan fill
    # ═════════════════════════════════════════════════════════════════════════
    def _draw_gauge(self, canvas, pct, size=110):
        """
        Draw a circular arc gauge centred in the canvas.
        size = canvas width = height (square canvas required).
        """
        canvas.delete("all")
        pad  = 10                      # padding from edge
        r    = (size - 2*pad) // 2     # radius of the arc
        cx   = size // 2               # centre x
        cy   = size // 2               # centre y
        x0, y0 = cx - r, cy - r       # bounding box top-left
        x1, y1 = cx + r, cy + r       # bounding box bottom-right

        # ── Background ring (dark border colour) ────────────────────────────
        canvas.create_arc(x0, y0, x1, y1,
                          start=0, extent=359.9,
                          style="arc", outline=C["border"], width=10)

        # ── Filled arc (clockwise from top = 90°) ───────────────────────────
        if pct > 0:
            fill_color = (C["accent_cyan"]   if pct < 40 else
                          C["accent_orange"] if pct < 70 else
                          C["accent_red"])
            extent = (pct / 100) * 359.9
            canvas.create_arc(x0, y0, x1, y1,
                               start=90, extent=-extent,
                               style="arc", outline=fill_color, width=10)

        # ── Centre text ──────────────────────────────────────────────────────
        canvas.create_text(cx, cy,
                           text=f"{pct}%",
                           font=("Consolas", 14, "bold"),
                           fill=C["text_white"])

    def _draw_risk_bar(self, canvas, pct):
        canvas.delete("all")
        w = canvas.winfo_width() or 220
        h = 16
        canvas.create_rectangle(0, 0, w, h, fill=C["bg_input"], outline="")
        fw = int(w * pct / 100)
        color = (C["accent_cyan"]   if pct < 40 else
                 C["accent_orange"] if pct < 70 else
                 C["accent_red"])
        if fw > 0:
            canvas.create_rectangle(0, 0, fw, h, fill=color, outline="")

    # ═════════════════════════════════════════════════════════════════════════
    #  DASHBOARD
    # ═════════════════════════════════════════════════════════════════════════
    def _build_dashboard(self, page):
        # ── Header bar ───────────────────────────────────────────────────────
        hdr = tk.Frame(page, bg=C["bg_panel"])
        hdr.pack(fill="x")
        tk.Label(hdr, text="🛡  CyberShield", font=("Consolas",24,"bold"),
                 bg=C["bg_panel"], fg=C["accent_cyan"]).pack(side="left", padx=22, pady=12)
        tk.Label(hdr, text="Phishing URL Detector\nStay Safe. Stay Secure.",
                 font=("Consolas",10), bg=C["bg_panel"],
                 fg=C["text_dim"], justify="left").pack(side="left", padx=4)
        self._clock_lbl = tk.Label(hdr, font=FONT_SMALL, bg=C["bg_panel"], fg=C["accent_cyan"])
        self._clock_lbl.pack(side="right", padx=20)
        self._tick_clock()
        tk.Frame(page, bg=C["border"], height=1).pack(fill="x")

        # ── Body (left content | right panel) ────────────────────────────────
        body = tk.Frame(page, bg=C["bg_dark"])
        body.pack(fill="both", expand=True, padx=14, pady=12)

        left = tk.Frame(body, bg=C["bg_dark"])
        left.pack(side="left", fill="both", expand=True, padx=(0,10))

        # ────────────────────────────────────────────────────────────────────
        #  URL SCANNER CARD
        # ────────────────────────────────────────────────────────────────────
        sc_o, sc_i = self._card(left, "🔍  URL Scanner", C["accent_cyan"])
        sc_o.pack(fill="x", pady=(0,10))

        tk.Label(sc_i, text="Enter URL to scan", font=FONT_SMALL,
                 bg=C["bg_panel"], fg=C["text_dim"]).pack(anchor="w", padx=14, pady=(4,0))

        url_row = tk.Frame(sc_i, bg=C["bg_panel"])
        url_row.pack(fill="x", padx=14, pady=(4,8))
        tk.Label(url_row, text="🌐", font=FONT_BODY, bg=C["bg_panel"], fg=C["text_dim"]).pack(side="left")
        self._dash_url_entry = self._entry(url_row, "https://example.com", width=38)
        self._dash_url_entry.pack(side="left", padx=6, ipady=6, expand=True, fill="x")
        self._btn(url_row, "🚀 Scan URL", self._quick_scan, C["accent_cyan"]).pack(side="left")

        # Status + gauge row
        sr = tk.Frame(sc_i, bg=C["bg_panel"])
        sr.pack(fill="x", padx=14, pady=(0,12))

        # Status icon + text block
        self._dash_status_icon = tk.Label(sr, text="✅", font=("Consolas",22),
                                          bg=C["bg_panel"], fg=C["accent_green"])
        self._dash_status_icon.pack(side="left", padx=(0,8))

        st_txt = tk.Frame(sr, bg=C["bg_panel"])
        st_txt.pack(side="left")
        tk.Label(st_txt, text="Status:", font=FONT_SMALL,
                 bg=C["bg_panel"], fg=C["text_dim"]).pack(anchor="w")
        self._dash_status_val = tk.Label(st_txt, text="safe website",
                                         font=("Consolas",12,"bold"),
                                         bg=C["bg_panel"], fg=C["accent_green"])
        self._dash_status_val.pack(anchor="w")
        self._dash_status_detail = tk.Label(st_txt, text="The website appears safe.",
                                            font=FONT_SMALL, bg=C["bg_panel"], fg=C["text_dim"])
        self._dash_status_detail.pack(anchor="w")

        # ── Risk Score gauge (square canvas = perfect circle) ────────────────
        gauge_wrap = tk.Frame(sr, bg=C["bg_panel"])
        gauge_wrap.pack(side="left", padx=(20,0))
        tk.Label(gauge_wrap, text="Risk Score", font=FONT_SMALL,
                 bg=C["bg_panel"], fg=C["text_dim"]).pack()
        self._gauge_canvas = tk.Canvas(gauge_wrap, width=110, height=110,
                                       bg=C["bg_panel"], highlightthickness=0)
        self._gauge_canvas.pack()
        self._draw_gauge(self._gauge_canvas, 18)

        # ── Risk Level bar ───────────────────────────────────────────────────
        bar_wrap = tk.Frame(sr, bg=C["bg_panel"])
        bar_wrap.pack(side="left", padx=(14,0), fill="x", expand=True)
        tk.Label(bar_wrap, text="Risk Level", font=FONT_SMALL,
                 bg=C["bg_panel"], fg=C["text_dim"]).pack(anchor="w")
        self._risk_canvas = tk.Canvas(bar_wrap, height=16, bg=C["bg_panel"], highlightthickness=0)
        self._risk_canvas.pack(fill="x", pady=(4,2))
        self._risk_canvas.bind("<Configure>", lambda e: self._draw_risk_bar(self._risk_canvas, 18))
        lbl_r = tk.Frame(bar_wrap, bg=C["bg_panel"])
        lbl_r.pack(fill="x")
        for t in ("0%", "50%", "100%"):
            tk.Label(lbl_r, text=t, font=FONT_SMALL,
                     bg=C["bg_panel"], fg=C["text_dim"]).pack(side="left", expand=True)

        # ────────────────────────────────────────────────────────────────────
        #  BOTTOM ROW: SHA-256 | RSA | Security Tips
        # ────────────────────────────────────────────────────────────────────
        bot = tk.Frame(left, bg=C["bg_dark"])
        bot.pack(fill="both", expand=True)

        # SHA-256
        sha_o, sha_i = self._card(bot, "🔒  SHA-256 Hash Generator", C["accent_pink"])
        sha_o.pack(side="left", fill="both", expand=True, padx=(0,8))
        tk.Label(sha_i, text="Enter text", font=FONT_SMALL,
                 bg=C["bg_panel"], fg=C["text_dim"]).pack(anchor="w", padx=14, pady=(4,0))
        self._dash_sha_entry = self._entry(sha_i, "hello123", width=22)
        self._dash_sha_entry.pack(padx=14, pady=4, ipady=5, fill="x")
        self._btn(sha_i, "Generate SHA-256",
                  self._dash_do_sha, C["accent_pink"], C["bg_dark"]).pack(padx=14, pady=4, fill="x")
        tk.Label(sha_i, text="Hash Output", font=FONT_SMALL,
                 bg=C["bg_panel"], fg=C["text_dim"]).pack(anchor="w", padx=14)
        self._dash_sha_out = tk.Text(sha_i, font=FONT_MONO, bg=C["bg_input"],
                                     fg=C["accent_green"], height=3, width=28,
                                     relief="flat", bd=0, wrap="word",
                                     highlightthickness=1, highlightbackground=C["border"])
        self._dash_sha_out.pack(padx=14, pady=(0,10), fill="x")

        # RSA
        rsa_o, rsa_i = self._card(bot, "🔑  RSA Encryption Demo", C["accent_cyan"])
        rsa_o.pack(side="left", fill="both", expand=True, padx=(0,8))
        tk.Label(rsa_i, text="Enter message", font=FONT_SMALL,
                 bg=C["bg_panel"], fg=C["text_dim"]).pack(anchor="w", padx=14, pady=(4,0))
        self._dash_rsa_entry = self._entry(rsa_i, "CyberShield Project", width=22)
        self._dash_rsa_entry.pack(padx=14, pady=4, ipady=5, fill="x")
        br = tk.Frame(rsa_i, bg=C["bg_panel"])
        br.pack(padx=14, pady=4, fill="x")
        self._btn(br, "Encrypt 🔒", self._dash_do_encrypt,
                  C["accent_cyan"]).pack(side="left", expand=True, fill="x", padx=(0,4))
        self._btn(br, "Decrypt 🔓", self._dash_do_decrypt,
                  "#7b2ff7", C["text_white"]).pack(side="left", expand=True, fill="x")
        tk.Label(rsa_i, text="Ciphertext", font=FONT_SMALL,
                 bg=C["bg_panel"], fg=C["text_dim"]).pack(anchor="w", padx=14)
        self._dash_rsa_cipher = tk.Text(rsa_i, font=FONT_MONO, bg=C["bg_input"],
                                        fg=C["accent_green"], height=2, width=28,
                                        relief="flat", bd=0, wrap="word",
                                        highlightthickness=1, highlightbackground=C["border"])
        self._dash_rsa_cipher.pack(padx=14, pady=2, fill="x")
        tk.Label(rsa_i, text="Decrypted Text", font=FONT_SMALL,
                 bg=C["bg_panel"], fg=C["text_dim"]).pack(anchor="w", padx=14)
        self._dash_rsa_dec = tk.Label(rsa_i, text="", font=("Consolas",10,"bold"),
                                      bg=C["bg_panel"], fg=C["accent_green"])
        self._dash_rsa_dec.pack(anchor="w", padx=14, pady=(0,10))

        # Security Tips
        tips_o, tips_i = self._card(bot, "🔒  Security Tips", C["accent_green"])
        tips_o.pack(side="left", fill="both", expand=True)
        for tip in ["Always use HTTPS websites",
                    "Avoid sharing OTPs or passwords",
                    "Verify domain names carefully",
                    "Do not click on unknown links",
                    "Keep system & browser updated"]:
            tk.Label(tips_i, text=f"✅  {tip}", font=FONT_SMALL,
                     bg=C["bg_panel"], fg=C["text_white"],
                     anchor="w", wraplength=195, justify="left").pack(anchor="w", padx=14, pady=3)

        # ────────────────────────────────────────────────────────────────────
        #  RIGHT COLUMN  (Threat Analysis + Video)
        # ────────────────────────────────────────────────────────────────────
        right = tk.Frame(body, bg=C["bg_dark"], width=268)
        right.pack(side="right", fill="y")
        right.pack_propagate(False)

        # ── Threat Analysis Card ─────────────────────────────────────────────
        threat_o, threat_i = self._card(right, "⚡  Threat Analysis", C["accent_pink"])
        threat_o.pack(fill="x", pady=(0,8))

        self._threat_labels = {}

        # Header row labels (icon | label | value | tick) — all in one tight row
        threat_rows = [
            ("https_row", "🔒", "HTTPS",              "Yes",          C["accent_green"]),
            ("age_row",   "📅", "Domain Age",          "Good",         C["accent_green"]),
            ("kw_row",    "⚠",  "Suspicious Keywords", "0",            C["accent_green"]),
            ("len_row",   "🔗", "URL Length",          "28 (Normal)",  C["accent_green"]),
            ("sub_row",   "🌐", "Subdomains",          "1 (Normal)",   C["accent_green"]),
            ("hyp_row",   "➖", "Hyphens in Domain",   "No",           C["accent_green"]),
        ]
        for key, icon, label, default, color in threat_rows:
            row = tk.Frame(threat_i, bg=C["bg_panel"])
            row.pack(fill="x", padx=10, pady=3)

            tk.Label(row, text=icon, font=("Consolas",10),
                     bg=C["bg_panel"], fg=color, width=2, anchor="w").pack(side="left")
            tk.Label(row, text=label, font=("Consolas",9),
                     bg=C["bg_panel"], fg=C["text_dim"], anchor="w").pack(side="left", padx=(4,0))

            # tick + value on RIGHT, packed right-to-left
            ok_lbl = tk.Label(row, text="✅", font=("Consolas",9),
                              bg=C["bg_panel"], fg=C["accent_green"], width=2)
            ok_lbl.pack(side="right")
            val_lbl = tk.Label(row, text=default, font=("Consolas",9,"bold"),
                               bg=C["bg_panel"], fg=color, anchor="e")
            val_lbl.pack(side="right", padx=(0,4))

            self._threat_labels[key] = (val_lbl, ok_lbl)

        # Divider
        tk.Frame(threat_i, bg=C["border"], height=1).pack(fill="x", padx=10, pady=(4,0))

        self._scan_time_lbl = tk.Label(threat_i, text="Scan Time: –",
                                       font=("Consolas",8), bg=C["bg_panel"],
                                       fg=C["accent_pink"], anchor="w")
        self._scan_time_lbl.pack(fill="x", padx=10, pady=(3,8))

        # ── Video Motion Panel (below Threat Analysis) ───────────────────────
        vid_o, vid_i = self._card(right, "🎬  CyberShield Motion", C["accent_cyan"])
        vid_o.pack(fill="x", pady=(0,8))

        # Video canvas placeholder (248 wide × 150 tall)
        vid_canvas = tk.Canvas(vid_i, width=248, height=150,
                               bg="#000810", highlightthickness=0)
        vid_canvas.pack(padx=8, pady=(0,4))

        if self._video_frames:
            # Use Label to display PhotoImage frames
            self._vid_label = tk.Label(vid_i, bg="#000810",
                                       relief="flat", bd=0)
            # Replace canvas with label
            vid_canvas.destroy()
            self._vid_label.pack(padx=8, pady=(0,4))
        else:
            # No frames – show fallback animated text on canvas
            vid_canvas.create_text(
                124, 75, text="▶  Motion Graphics\n(install Pillow + opencv\nfor live video)",
                font=("Consolas",9), fill=C["accent_cyan"], justify="center"
            )
            self._vid_label_canvas = vid_canvas

        tk.Label(vid_i, text="Cybersecurity Awareness Motion",
                 font=("Consolas",8), bg=C["bg_panel"],
                 fg=C["text_dim"]).pack(pady=(0,6))

    # ── Clock ────────────────────────────────────────────────────────────────
    def _tick_clock(self):
        now = datetime.datetime.now().strftime("Scan Time: %d %b %Y  |  %I:%M:%S %p")
        try:
            self._clock_lbl.config(text=now)
            self.after(1000, self._tick_clock)
        except Exception:
            pass

    # ── Threat panel update ──────────────────────────────────────────────────
    def _update_threat_panel(self, result):
        def ow(good): return ("✅", C["accent_green"]) if good else ("⚠", C["accent_red"])

        v,ok = self._threat_labels["https_row"]
        good = result["https"]
        v.config(text="Yes" if good else "No",
                 fg=C["accent_green"] if good else C["accent_red"])
        ic,fc = ow(good); ok.config(text=ic, fg=fc)

        v,ok = self._threat_labels["age_row"]
        age  = result["domain_age_label"]
        v.config(text=age, fg=C["accent_green"] if age=="Good" else C["text_dim"])
        ic,fc = ow(age=="Good"); ok.config(text=ic, fg=fc)

        v,ok = self._threat_labels["kw_row"]
        kw   = result["suspicious_kw_count"]
        v.config(text=str(kw), fg=C["accent_green"] if kw==0 else C["accent_red"])
        ic,fc = ow(kw==0); ok.config(text=ic, fg=fc)

        v,ok = self._threat_labels["len_row"]
        ul   = result["url_length"]
        v.config(text=f"{ul} ({'Normal' if ul<=75 else 'Long'})",
                 fg=C["accent_green"] if ul<=75 else C["accent_orange"])
        ic,fc = ow(ul<=75); ok.config(text=ic, fg=fc)

        v,ok = self._threat_labels["sub_row"]
        sub  = result["subdomain_count"]
        v.config(text=f"{sub} ({'Normal' if sub<=2 else 'High'})",
                 fg=C["accent_green"] if sub<=2 else C["accent_red"])
        ic,fc = ow(sub<=2); ok.config(text=ic, fg=fc)

        v,ok = self._threat_labels["hyp_row"]
        hyp  = result["has_hyphens"]
        v.config(text="Yes" if hyp else "No",
                 fg=C["accent_red"] if hyp else C["accent_green"])
        ic,fc = ow(not hyp); ok.config(text=ic, fg=fc)

        self._scan_time_lbl.config(
            text=datetime.datetime.now().strftime("Scan Time: %d %b %Y  %I:%M:%S %p"))

    # ── Quick scan ───────────────────────────────────────────────────────────
    def _quick_scan(self):
        url = self._dash_url_entry.get().strip()
        if not url or url == "https://example.com":
            messagebox.showwarning("CyberShield", "Please enter a URL to scan.")
            return
        def do():
            result = analyse_url(url)
            score  = result["risk_score"]
            scan_history.append({"url": url, "score": score,
                                 "level": result["risk_level"],
                                 "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
            def upd():
                if result["risk_level"] == "Low":
                    icon, color = "✅", C["accent_green"]
                elif result["risk_level"] == "Medium":
                    icon, color = "⚠", C["accent_orange"]
                else:
                    icon, color = "❌", C["accent_red"]
                self._dash_status_icon.config(text=icon, fg=color)
                self._dash_status_val.config(text=result["status"], fg=color)
                self._dash_status_detail.config(text=result["status_detail"])
                self._draw_gauge(self._gauge_canvas, score)
                self._draw_risk_bar(self._risk_canvas, score)
                self._update_threat_panel(result)
            self.after(0, upd)
        threading.Thread(target=do, daemon=True).start()

    # ── SHA-256 dash helpers ─────────────────────────────────────────────────
    def _dash_do_sha(self):
        text = self._dash_sha_entry.get().strip()
        if not text or text == "hello123": text = "hello123"
        h = hashlib.sha256(text.encode()).hexdigest()
        self._dash_sha_out.config(state="normal")
        self._dash_sha_out.delete("1.0","end")
        self._dash_sha_out.insert("1.0", h)
        self._dash_sha_out.config(state="disabled")

    # ── RSA dash helpers ─────────────────────────────────────────────────────
    def _dash_do_encrypt(self):
        msg = self._dash_rsa_entry.get().strip()
        if not msg or msg == "CyberShield Project": msg = "CyberShield Project"
        cipher = rsa_encrypt(msg, self.rsa_pub)
        preview = cipher[:40] + ("..." if len(cipher)>40 else "")
        self._dash_rsa_cipher.config(state="normal")
        self._dash_rsa_cipher.delete("1.0","end")
        self._dash_rsa_cipher.insert("1.0", preview)
        self._dash_rsa_cipher.config(state="disabled")
        self._last_cipher = cipher

    def _dash_do_decrypt(self):
        cipher = getattr(self, "_last_cipher", "")
        if not cipher:
            messagebox.showinfo("CyberShield","Encrypt a message first.")
            return
        plain = rsa_decrypt(cipher, self.rsa_priv)
        self._dash_rsa_dec.config(text=f"{plain} ✅")

    # ═════════════════════════════════════════════════════════════════════════
    #  PAGE: URL SCANNER
    # ═════════════════════════════════════════════════════════════════════════
    def _build_scanner(self, page):
        tk.Label(page, text="🔍  URL Scanner", font=("Consolas",18,"bold"),
                 bg=C["bg_dark"], fg=C["accent_cyan"]).pack(anchor="w", padx=20, pady=(16,4))
        tk.Label(page, text="Paste any URL below and press Scan to check for phishing threats.",
                 font=FONT_SMALL, bg=C["bg_dark"], fg=C["text_dim"]).pack(anchor="w", padx=20)

        in_o, in_i = self._card(page, None)
        in_o.pack(fill="x", padx=20, pady=10)
        row = tk.Frame(in_i, bg=C["bg_panel"])
        row.pack(fill="x", padx=14, pady=12)
        tk.Label(row, text="🌐", font=FONT_BODY, bg=C["bg_panel"], fg=C["text_dim"]).pack(side="left")
        self._sc_url_entry = self._entry(row, "https://example.com", width=60)
        self._sc_url_entry.pack(side="left", padx=8, ipady=7, expand=True, fill="x")
        self._btn(row, "🚀 Scan URL", self._sc_scan, C["accent_cyan"]).pack(side="left")

        res_o, res_i = self._card(page, "📊  Scan Results", C["accent_cyan"])
        res_o.pack(fill="both", expand=True, padx=20, pady=(0,14))

        # Status
        st_r = tk.Frame(res_i, bg=C["bg_panel"])
        st_r.pack(fill="x", padx=14, pady=(4,8))
        self._sc_icon = tk.Label(st_r, text="🛡", font=("Consolas",26),
                                 bg=C["bg_panel"], fg=C["accent_green"])
        self._sc_icon.pack(side="left")
        sf = tk.Frame(st_r, bg=C["bg_panel"])
        sf.pack(side="left", padx=10)
        self._sc_status = tk.Label(sf, text="Awaiting scan...", font=("Consolas",14,"bold"),
                                   bg=C["bg_panel"], fg=C["text_dim"])
        self._sc_status.pack(anchor="w")
        self._sc_detail = tk.Label(sf, text="Enter a URL and click Scan URL.",
                                   font=FONT_SMALL, bg=C["bg_panel"], fg=C["text_dim"])
        self._sc_detail.pack(anchor="w")

        sc_mid = tk.Frame(res_i, bg=C["bg_panel"])
        sc_mid.pack(fill="x", padx=14, pady=4)

        gf = tk.Frame(sc_mid, bg=C["bg_panel"])
        gf.pack(side="left")
        tk.Label(gf, text="Risk Score", font=FONT_SMALL,
                 bg=C["bg_panel"], fg=C["text_dim"]).pack()
        self._sc_gauge = tk.Canvas(gf, width=110, height=110,
                                   bg=C["bg_panel"], highlightthickness=0)
        self._sc_gauge.pack()
        self._sc_gauge_pct = 0
        self._draw_gauge(self._sc_gauge, 0)

        bf = tk.Frame(sc_mid, bg=C["bg_panel"])
        bf.pack(side="left", padx=20, fill="x", expand=True)
        tk.Label(bf, text="Risk Level", font=FONT_SMALL,
                 bg=C["bg_panel"], fg=C["text_dim"]).pack(anchor="w")
        self._sc_bar = tk.Canvas(bf, height=16, bg=C["bg_panel"], highlightthickness=0)
        self._sc_bar.pack(fill="x", pady=4)
        self._sc_bar.bind("<Configure>",
                          lambda e: self._draw_risk_bar(self._sc_bar, self._sc_gauge_pct))
        lr = tk.Frame(bf, bg=C["bg_panel"])
        lr.pack(fill="x")
        for t in ("0%","50%","100%"):
            tk.Label(lr, text=t, font=FONT_SMALL,
                     bg=C["bg_panel"], fg=C["text_dim"]).pack(side="left", expand=True)

        tk.Label(res_i, text="Findings", font=FONT_HEAD,
                 bg=C["bg_panel"], fg=C["accent_cyan"]).pack(anchor="w", padx=14, pady=(8,2))
        self._sc_findings = scrolledtext.ScrolledText(
            res_i, font=FONT_MONO, bg=C["bg_input"], fg=C["accent_green"],
            height=7, relief="flat", bd=0,
            highlightthickness=1, highlightbackground=C["border"])
        self._sc_findings.pack(fill="both", expand=True, padx=14, pady=(0,10))
        self._sc_findings.insert("1.0","No scan performed yet.")
        self._sc_findings.config(state="disabled")

    def _sc_scan(self):
        url = self._sc_url_entry.get().strip()
        if not url or url == "https://example.com":
            messagebox.showwarning("CyberShield","Please enter a URL to scan.")
            return
        self._sc_status.config(text="⏳  Scanning...", fg=C["accent_cyan"])
        self._sc_detail.config(text="Please wait…")
        def do():
            result = analyse_url(url)
            score  = result["risk_score"]
            self._sc_gauge_pct = score
            scan_history.append({"url": url, "score": score,
                                 "level": result["risk_level"],
                                 "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")})
            def upd():
                if result["risk_level"]=="Low":   icon,color = "✅",C["accent_green"]
                elif result["risk_level"]=="Medium": icon,color = "⚠",C["accent_orange"]
                else:                             icon,color = "❌",C["accent_red"]
                self._sc_icon.config(text=icon, fg=color)
                self._sc_status.config(text=result["status"], fg=color)
                self._sc_detail.config(text=result["status_detail"])
                self._draw_gauge(self._sc_gauge, score)
                self._draw_risk_bar(self._sc_bar, score)
                self._sc_findings.config(state="normal")
                self._sc_findings.delete("1.0","end")
                self._sc_findings.insert("1.0",
                    f"URL: {url}\n"
                    f"Risk Score: {score}%  |  Risk Level: {result['risk_level']}\n"
                    f"HTTPS: {'Yes' if result['https'] else 'No'}\n"
                    f"URL Length: {result['url_length']}\n"
                    f"Suspicious Keywords: {result['suspicious_kw_count']}\n"
                    f"Subdomains: {result['subdomain_count']}\n"
                    f"Hyphens in Domain: {'Yes' if result['has_hyphens'] else 'No'}\n"
                    f"Domain Age: {result['domain_age_label']}\n\n"
                    "──── Findings ────\n" +
                    "\n".join(f"• {d}" for d in result["details"])
                )
                self._sc_findings.config(state="disabled")
            self.after(0, upd)
        threading.Thread(target=do, daemon=True).start()

    # ═════════════════════════════════════════════════════════════════════════
    #  PAGE: SHA-256
    # ═════════════════════════════════════════════════════════════════════════
    def _build_sha256(self, page):
        tk.Label(page, text="🔒  SHA-256 Hash Generator", font=("Consolas",18,"bold"),
                 bg=C["bg_dark"], fg=C["accent_pink"]).pack(anchor="w", padx=20, pady=(16,4))
        tk.Label(page,
                 text="SHA-256 is a cryptographic hash function. Even a tiny change produces a completely different hash.",
                 font=FONT_SMALL, bg=C["bg_dark"], fg=C["text_dim"],
                 wraplength=900, justify="left").pack(anchor="w", padx=20)

        co, ci = self._card(page, None)
        co.pack(fill="x", padx=20, pady=14)
        tk.Label(ci, text="Enter Text to Hash", font=FONT_HEAD,
                 bg=C["bg_panel"], fg=C["accent_pink"]).pack(anchor="w", padx=14, pady=(10,2))
        self._sha_entry = self._entry(ci, "Type anything here...", width=60)
        self._sha_entry.pack(padx=14, pady=6, ipady=8, fill="x")
        br = tk.Frame(ci, bg=C["bg_panel"])
        br.pack(padx=14, pady=6, fill="x")
        self._btn(br, "⚙ Generate SHA-256 Hash",
                  self._sha_do_hash, C["accent_pink"], C["bg_dark"]).pack(side="left")
        self._btn(br, "🗑 Clear",
                  lambda: (self._sha_entry.delete(0,"end"),
                           self._sha_out.config(state="normal"),
                           self._sha_out.delete("1.0","end"),
                           self._sha_out.config(state="disabled"),
                           self._sha_copy_lbl.config(text="")),
                  C["border"], C["text_white"]).pack(side="left", padx=8)

        tk.Label(ci, text="Hash Output (SHA-256)", font=FONT_HEAD,
                 bg=C["bg_panel"], fg=C["accent_green"]).pack(anchor="w", padx=14, pady=(10,2))
        self._sha_out = tk.Text(ci, font=("Courier New",11), bg=C["bg_input"],
                                fg=C["accent_green"], height=3, relief="flat", bd=0,
                                wrap="word", highlightthickness=1,
                                highlightbackground=C["border"])
        self._sha_out.pack(padx=14, pady=4, fill="x", ipady=6)
        self._sha_out.config(state="disabled")

        cr = tk.Frame(ci, bg=C["bg_panel"])
        cr.pack(padx=14, pady=(0,6), fill="x")
        self._btn(cr, "📋 Copy Hash", self._sha_copy,
                  C["btn_blue"], C["text_white"]).pack(side="left")
        self._sha_copy_lbl = tk.Label(cr, text="", font=FONT_SMALL,
                                      bg=C["bg_panel"], fg=C["accent_green"])
        self._sha_copy_lbl.pack(side="left", padx=10)

        io, ii = self._card(page, "ℹ  About SHA-256", C["accent_cyan"])
        io.pack(fill="x", padx=20, pady=(0,14))
        tk.Label(ii, font=FONT_BODY, bg=C["bg_panel"], fg=C["text_white"],
                 justify="left", wraplength=850,
                 text=(
                     "SHA-256 (Secure Hash Algorithm 256-bit) is part of the SHA-2 family.\n\n"
                     "• Output is always 256 bits (64 hex characters)\n"
                     "• One-way – cannot be reversed\n"
                     "• Collision-resistant – two inputs extremely unlikely to share a hash\n"
                     "• Used in: digital signatures, blockchain, password storage\n"
                     "• Avalanche effect: changing 1 character completely changes the hash"
                 )).pack(anchor="w", padx=14, pady=(0,10))

        do, di = self._card(page, "🔬  Avalanche Effect Demo", C["accent_orange"])
        do.pack(fill="x", padx=20, pady=(0,14))
        tk.Label(di, text="Changing even one character completely changes the hash:",
                 font=FONT_SMALL, bg=C["bg_panel"], fg=C["text_dim"]).pack(anchor="w", padx=14, pady=4)
        for word in ["hello","Hello","hell0"]:
            h = hashlib.sha256(word.encode()).hexdigest()
            r = tk.Frame(di, bg=C["bg_panel"])
            r.pack(fill="x", padx=14, pady=2)
            tk.Label(r, text=f"{word!r:8}", font=("Courier New",10,"bold"),
                     bg=C["bg_panel"], fg=C["accent_yellow"], width=10).pack(side="left")
            tk.Label(r, text=" → ", font=FONT_BODY, bg=C["bg_panel"], fg=C["text_dim"]).pack(side="left")
            tk.Label(r, text=h, font=("Courier New",9),
                     bg=C["bg_panel"], fg=C["accent_green"]).pack(side="left")
        tk.Frame(di, height=6, bg=C["bg_panel"]).pack()

    def _sha_do_hash(self):
        text = self._sha_entry.get().strip()
        if not text:
            messagebox.showwarning("CyberShield","Please enter text to hash.")
            return
        h = hashlib.sha256(text.encode()).hexdigest()
        self._sha_out.config(state="normal")
        self._sha_out.delete("1.0","end")
        self._sha_out.insert("1.0", h)
        self._sha_out.config(state="disabled")
        self._sha_copy_lbl.config(text="")

    def _sha_copy(self):
        h = self._sha_out.get("1.0","end").strip()
        if h:
            self.clipboard_clear(); self.clipboard_append(h)
            self._sha_copy_lbl.config(text="✅ Copied!")
            self.after(2000, lambda: self._sha_copy_lbl.config(text=""))

    # ═════════════════════════════════════════════════════════════════════════
    #  PAGE: RSA
    # ═════════════════════════════════════════════════════════════════════════
    def _build_rsa(self, page):
        tk.Label(page, text="🔑  RSA Encryption Demo", font=("Consolas",18,"bold"),
                 bg=C["bg_dark"], fg=C["accent_cyan"]).pack(anchor="w", padx=20, pady=(16,4))
        tk.Label(page,
                 text="Public-key cryptosystem. Data encrypted with the public key can only be decrypted with the private key.",
                 font=FONT_SMALL, bg=C["bg_dark"], fg=C["text_dim"],
                 wraplength=900, justify="left").pack(anchor="w", padx=20)

        ko, ki = self._card(page, "🔐  Current RSA Keys", C["accent_yellow"])
        ko.pack(fill="x", padx=20, pady=12)
        kr = tk.Frame(ki, bg=C["bg_panel"])
        kr.pack(fill="x", padx=14, pady=6)
        self._rsa_pub_lbl = tk.Label(kr, text="", font=("Courier New",9),
                                     bg=C["bg_panel"], fg=C["accent_yellow"],
                                     wraplength=380, justify="left")
        self._rsa_pub_lbl.pack(side="left", expand=True, anchor="w")
        self._rsa_priv_lbl = tk.Label(kr, text="", font=("Courier New",9),
                                      bg=C["bg_panel"], fg=C["accent_red"],
                                      wraplength=380, justify="left")
        self._rsa_priv_lbl.pack(side="left", expand=True, anchor="w")
        self._btn(ki, "🔄 Generate New Keys", self._rsa_new_keys,
                  C["btn_blue"], C["text_white"]).pack(anchor="w", padx=14, pady=(0,8))
        self._rsa_update_key_labels()

        eo, ei = self._card(page, "✉  Encrypt / Decrypt", C["accent_cyan"])
        eo.pack(fill="both", expand=True, padx=20, pady=(0,14))
        tk.Label(ei, text="Message to Encrypt", font=FONT_SMALL,
                 bg=C["bg_panel"], fg=C["text_dim"]).pack(anchor="w", padx=14, pady=(6,2))
        self._rsa_msg_entry = self._entry(ei, "Type your secret message here", width=60)
        self._rsa_msg_entry.pack(padx=14, ipady=7, fill="x")
        br = tk.Frame(ei, bg=C["bg_panel"])
        br.pack(padx=14, pady=8, fill="x")
        self._btn(br, "🔒 Encrypt", self._rsa_encrypt, C["accent_cyan"]).pack(side="left", padx=(0,8))
        self._btn(br, "🔓 Decrypt", self._rsa_decrypt, "#7b2ff7", C["text_white"]).pack(side="left")

        tk.Label(ei, text="Ciphertext", font=FONT_SMALL,
                 bg=C["bg_panel"], fg=C["text_dim"]).pack(anchor="w", padx=14)
        self._rsa_cipher_box = scrolledtext.ScrolledText(
            ei, font=FONT_MONO, bg=C["bg_input"], fg=C["accent_green"],
            height=4, relief="flat", bd=0,
            highlightthickness=1, highlightbackground=C["border"])
        self._rsa_cipher_box.pack(fill="x", padx=14, pady=4)

        tk.Label(ei, text="Decrypted Text", font=FONT_SMALL,
                 bg=C["bg_panel"], fg=C["text_dim"]).pack(anchor="w", padx=14)
        self._rsa_dec_lbl = tk.Label(ei, text="", font=("Consolas",12,"bold"),
                                     bg=C["bg_panel"], fg=C["accent_green"])
        self._rsa_dec_lbl.pack(anchor="w", padx=14, pady=(0,10))

        ho, hi = self._card(page, "ℹ  How RSA Works", C["accent_pink"])
        ho.pack(fill="x", padx=20, pady=(0,14))
        tk.Label(hi, font=FONT_BODY, bg=C["bg_panel"], fg=C["text_white"],
                 justify="left", wraplength=850,
                 text=(
                     "1. Key Generation: Choose two large primes p and q. Compute n=p×q and φ(n)=(p-1)(q-1).\n"
                     "2. Public Key: (e, n) where gcd(e, φ) = 1. Commonly e = 65537.\n"
                     "3. Private Key: (d, n) where d × e ≡ 1 (mod φ(n)).\n"
                     "4. Encrypt: C = M^e mod n    |    Decrypt: M = C^d mod n\n\n"
                     "Note: This demo uses small primes for speed. Real RSA uses 2048–4096-bit keys."
                 )).pack(anchor="w", padx=14, pady=(0,10))

    def _rsa_update_key_labels(self):
        e,n = self.rsa_pub; d,_ = self.rsa_priv
        self._rsa_pub_lbl.config(text=f"Public Key\ne = {e}\nn = {n}")
        self._rsa_priv_lbl.config(text=f"Private Key (keep secret!)\nd = {d}\nn = {n}")

    def _rsa_new_keys(self):
        self._gen_rsa_keys()
        self._rsa_update_key_labels()
        self._rsa_cipher_box.delete("1.0","end")
        self._rsa_dec_lbl.config(text="")
        messagebox.showinfo("CyberShield","New RSA key pair generated!")

    def _rsa_encrypt(self):
        msg = self._rsa_msg_entry.get().strip()
        if not msg:
            messagebox.showwarning("CyberShield","Enter a message to encrypt.")
            return
        cipher = rsa_encrypt(msg, self.rsa_pub)
        self._last_rsa_cipher = cipher
        self._rsa_cipher_box.delete("1.0","end")
        self._rsa_cipher_box.insert("1.0", cipher)
        self._rsa_dec_lbl.config(text="")

    def _rsa_decrypt(self):
        cipher = self._rsa_cipher_box.get("1.0","end").strip()
        if not cipher:
            messagebox.showwarning("CyberShield","No ciphertext. Encrypt first.")
            return
        plain = rsa_decrypt(cipher, self.rsa_priv)
        self._rsa_dec_lbl.config(text=f"{plain} ✅")

    # ═════════════════════════════════════════════════════════════════════════
    #  PAGE: HISTORY
    # ═════════════════════════════════════════════════════════════════════════
    def _build_history(self, page):
        tk.Label(page, text="📊  Scan History", font=("Consolas",18,"bold"),
                 bg=C["bg_dark"], fg=C["accent_cyan"]).pack(anchor="w", padx=20, pady=(16,4))
        tk.Label(page, text="All URL scans performed during this session.",
                 font=FONT_SMALL, bg=C["bg_dark"], fg=C["text_dim"]).pack(anchor="w", padx=20)

        br = tk.Frame(page, bg=C["bg_dark"])
        br.pack(anchor="w", padx=20, pady=8)
        self._btn(br, "🔄 Refresh", self._refresh_history,
                  C["btn_blue"], C["text_white"]).pack(side="left")
        self._btn(br, "🗑 Clear History",
                  lambda: (scan_history.clear(), self._refresh_history()),
                  C["accent_red"], C["text_white"]).pack(side="left", padx=8)

        style = ttk.Style(); style.theme_use("clam")
        style.configure("Cyber.Treeview",
                        background=C["bg_input"], foreground=C["text_white"],
                        fieldbackground=C["bg_input"], rowheight=28,
                        font=("Consolas",10))
        style.configure("Cyber.Treeview.Heading",
                        background=C["bg_panel"], foreground=C["accent_cyan"],
                        font=("Consolas",10,"bold"))
        style.map("Cyber.Treeview",
                  background=[("selected",C["sidebar_sel"])],
                  foreground=[("selected",C["accent_cyan"])])

        tf = tk.Frame(page, bg=C["bg_dark"])
        tf.pack(fill="both", expand=True, padx=20, pady=(0,14))
        cols = ("Time","URL","Score","Level")
        self._hist_tree = ttk.Treeview(tf, columns=cols, show="headings",
                                       style="Cyber.Treeview")
        for col,w in zip(cols,[160,480,80,100]):
            self._hist_tree.heading(col, text=col)
            self._hist_tree.column(col, width=w, anchor="center" if col!="URL" else "w")
        vsb = ttk.Scrollbar(tf, orient="vertical", command=self._hist_tree.yview)
        self._hist_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self._hist_tree.pack(fill="both", expand=True)

        self._hist_stats = tk.Label(page, text="", font=FONT_SMALL,
                                    bg=C["bg_dark"], fg=C["text_dim"])
        self._hist_stats.pack(anchor="w", padx=20, pady=(0,10))

    def _refresh_history(self):
        for item in self._hist_tree.get_children():
            self._hist_tree.delete(item)
        for scan in scan_history:
            s = scan["score"]
            tag = "low" if s<40 else ("med" if s<70 else "high")
            self._hist_tree.insert("","end",
                values=(scan["time"],scan["url"],f"{s}%",scan["level"]),
                tags=(tag,))
        self._hist_tree.tag_configure("low",  foreground=C["accent_green"])
        self._hist_tree.tag_configure("med",  foreground=C["accent_orange"])
        self._hist_tree.tag_configure("high", foreground=C["accent_red"])
        total = len(scan_history)
        safe  = sum(1 for s in scan_history if s["score"]<40)
        self._hist_stats.config(
            text=f"Total: {total}  |  Safe: {safe}  |  Suspicious/Dangerous: {total-safe}")

    # ═════════════════════════════════════════════════════════════════════════
    #  PAGE: IS CONCEPTS
    # ═════════════════════════════════════════════════════════════════════════
    def _build_concepts(self, page):
        tk.Label(page, text="📘  Information Security Concepts",
                 font=("Consolas",18,"bold"),
                 bg=C["bg_dark"], fg=C["accent_cyan"]).pack(anchor="w", padx=20, pady=(16,4))

        canvas = tk.Canvas(page, bg=C["bg_dark"], highlightthickness=0)
        sb = ttk.Scrollbar(page, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)

        inner = tk.Frame(canvas, bg=C["bg_dark"])
        wid = canvas.create_window((0,0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(wid, width=e.width))
        canvas.bind_all("<MouseWheel>",
                        lambda e: canvas.yview_scroll(-1 if e.delta>0 else 1,"units"))

        concepts = [
            ("🔐 Phishing", C["accent_red"],
             "Phishing is a cyber attack where attackers disguise themselves as trustworthy entities "
             "to steal sensitive information like usernames, passwords, and credit card details.\n\n"
             "Common types: Email phishing, Spear phishing, Smishing (SMS), Vishing (Voice)\n\n"
             "How to spot phishing URLs:\n"
             "• Misspelled domain names (e.g., paypa1.com)\n"
             "• Excessive subdomains or hyphens\n"
             "• HTTP instead of HTTPS\n"
             "• Suspicious keywords (login, verify, secure, etc.)"),
            ("🔑 Cryptography", C["accent_yellow"],
             "Cryptography is the practice of securing information by transforming it into an unreadable format.\n\n"
             "Symmetric Encryption: Same key for encrypt/decrypt (AES, DES)\n"
             "Asymmetric Encryption: Key pair – public key encrypts, private key decrypts (RSA, ECC)\n"
             "Hash Functions: One-way transformation (SHA-256, MD5)\n\n"
             "Applications: HTTPS, digital signatures, blockchain, password storage"),
            ("🛡 CIA Triad", C["accent_cyan"],
             "The CIA Triad is the foundation of information security:\n\n"
             "• Confidentiality: Accessible only to authorised users – Encryption, access controls\n"
             "• Integrity: Data is accurate and untampered – Hashing, digital signatures\n"
             "• Availability: Systems accessible when needed – Backups, redundancy, DDoS protection"),
            ("🔒 SHA-256", C["accent_pink"],
             "SHA-256 (Secure Hash Algorithm):\n\n"
             "• Fixed 256-bit (64 hex chars) output regardless of input size\n"
             "• Deterministic: same input always produces same hash\n"
             "• Avalanche effect: tiny change → completely different hash\n"
             "• Pre-image resistant: cannot reverse the hash\n"
             "• Used in: Bitcoin mining, SSL certificates, file integrity verification"),
            ("🌐 RSA Encryption", C["accent_green"],
             "RSA (Rivest–Shamir–Adleman):\n\n"
             "  1. Choose two large primes p and q\n"
             "  2. Compute n = p × q (modulus)\n"
             "  3. Compute φ(n) = (p-1)(q-1)\n"
             "  4. Choose e such that gcd(e, φ) = 1\n"
             "  5. Compute d = e⁻¹ mod φ(n)\n"
             "Public Key: (e, n)  |  Private Key: (d, n)\n"
             "Encrypt: C = M^e mod n  |  Decrypt: M = C^d mod n"),
            ("⚠ Common Attacks", C["accent_orange"],
             "Types of Cyber Attacks:\n\n"
             "• Man-in-the-Middle (MITM): Attacker intercepts communication\n"
             "• SQL Injection: Malicious SQL code inserted into input fields\n"
             "• Cross-Site Scripting (XSS): Injecting scripts into web pages\n"
             "• Brute Force: Trying all possible passwords\n"
             "• DDoS: Flooding a server to make it unavailable\n"
             "• Social Engineering: Manipulating people into revealing information"),
            ("✅ Best Practices", C["accent_green"],
             "Cybersecurity Best Practices:\n\n"
             "• Always use HTTPS websites for sensitive transactions\n"
             "• Use strong, unique passwords (12+ chars, mixed case, numbers, symbols)\n"
             "• Enable Two-Factor Authentication (2FA) wherever possible\n"
             "• Keep software, OS, and browsers updated\n"
             "• Never click on suspicious links in emails or messages\n"
             "• Use a reputable antivirus and firewall\n"
             "• Backup important data regularly\n"
             "• Be cautious on public Wi-Fi – use a VPN"),
        ]
        for title, color, body in concepts:
            co, ci = self._card(inner, title, color)
            co.pack(fill="x", padx=16, pady=6)
            tk.Label(ci, text=body, font=FONT_BODY, bg=C["bg_panel"],
                     fg=C["text_white"], justify="left", wraplength=850
                     ).pack(anchor="w", padx=14, pady=(0,10))

    # ═════════════════════════════════════════════════════════════════════════
    #  PAGE: ABOUT
    # ═════════════════════════════════════════════════════════════════════════
    def _build_about(self, page):
        tk.Label(page, text="ℹ  About CyberShield", font=("Consolas",18,"bold"),
                 bg=C["bg_dark"], fg=C["accent_cyan"]).pack(anchor="w", padx=20, pady=(16,4))

        co, ci = self._card(page, "🛡  CyberShield – Information Security Project", C["accent_cyan"])
        co.pack(fill="x", padx=20, pady=12)
        tk.Label(ci, font=FONT_BODY, bg=C["bg_panel"], fg=C["text_white"], justify="left",
                 text=(
                     "CyberShield is an educational cybersecurity toolkit demonstrating core IS concepts.\n\n"
                     "Features:\n"
                     "  🔍  Phishing URL Scanner    – Heuristic + live HTTP analysis\n"
                     "  🔒  SHA-256 Hash Generator  – Compute cryptographic hashes\n"
                     "  🔑  RSA Encryption Demo     – Generate keys, encrypt, decrypt\n"
                     "  📊  Scan History            – Track all scans this session\n"
                     "  📘  IS Concepts             – Key cybersecurity concepts\n\n"
                     "Stack: Python 3 · tkinter · hashlib · requests · opencv (video)\n\n"
                     "Purpose: Information Security coursework demonstration."
                 )).pack(anchor="w", padx=14, pady=(0,12))

        to, ti = self._card(page, "🛡  Quick Security Reminders", C["accent_green"])
        to.pack(fill="x", padx=20, pady=(0,14))
        for tip in [
            "Always verify the URL before entering credentials.",
            "Use a password manager for unique, strong passwords.",
            "Enable 2-factor authentication on all important accounts.",
            "Report phishing emails – don't just delete them.",
            "A padlock 🔒 means HTTPS, not necessarily safe content.",
        ]:
            tk.Label(ti, text=f"✅  {tip}", font=FONT_BODY,
                     bg=C["bg_panel"], fg=C["text_white"],
                     anchor="w", wraplength=900, justify="left").pack(anchor="w", padx=14, pady=4)
        tk.Frame(ti, height=6, bg=C["bg_panel"]).pack()


# ═══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = CyberShieldApp()
    app.mainloop()
