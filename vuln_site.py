"""
VulnLab - a deliberately vulnerable multi-page website for LOCAL security practice only.

    pip install flask lxml
    python vuln_site.py        ->  http://127.0.0.1:5000

Open /payloads in the running site for the full list of test payloads.
NEVER expose this to a network. Run it in a VM or container if possible.
"""
import base64, hashlib, hmac, html, json, os, pickle, sqlite3, subprocess, urllib.request
from flask import Flask, request, redirect, session, make_response, render_template_string, send_from_directory

app = Flask(__name__)
app.secret_key = "123456"                      # weak hardcoded secret
DB, JWT_SECRET = "vuln.db", "secret"
os.makedirs("uploads", exist_ok=True)

LAYOUT = """<!doctype html><html><head><meta charset=utf-8><title>VulnLab - {{T}}</title>
<style>
body{font:15px system-ui,sans-serif;background:#0f172a;color:#e2e8f0;margin:0}
nav{background:#1e293b;padding:12px 24px;display:flex;gap:16px;flex-wrap:wrap;align-items:center}
nav a{color:#7dd3fc;text-decoration:none} nav b{color:#f87171;margin-right:12px}
main{max-width:960px;margin:24px auto;padding:0 24px}
a{color:#7dd3fc} input,textarea,button{padding:8px;margin:4px 0;border-radius:6px;border:1px solid #475569;background:#1e293b;color:#e2e8f0}
button{background:#dc2626;border:0;cursor:pointer} table{border-collapse:collapse;width:100%}
td,th{border:1px solid #334155;padding:6px 10px;text-align:left;vertical-align:top} code,pre{background:#1e293b;padding:2px 6px;border-radius:4px;word-break:break-all;white-space:pre-wrap}
.card{background:#1e293b;border-radius:10px;padding:14px 18px;margin:10px 0}
.warn{color:#fbbf24}
</style></head><body>
<nav><b>VulnLab</b><a href="/">Home</a><a href="/login">Login</a><a href="/register">Register</a>
<a href="/shop">Shop</a><a href="/guestbook">Guestbook</a><a href="/search?q=a">Search</a>
<a href="/tools">Tools</a><a href="/payloads">Payloads</a><a href="/admin">Admin</a></nav>
<main><h2>{{T}}</h2>{{B}}</main></body></html>"""


def page(title, body):
    return LAYOUT.replace("{{T}}", title).replace("{{B}}", body)


def db():
    return sqlite3.connect(DB)


def init_db():
    c = db()
    c.executescript("""
    DROP TABLE IF EXISTS users; DROP TABLE IF EXISTS posts; DROP TABLE IF EXISTS products;
    CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, secret TEXT);
    CREATE TABLE posts(id INTEGER PRIMARY KEY, author TEXT, body TEXT);
    CREATE TABLE products(id INTEGER PRIMARY KEY, name TEXT, price REAL, stock INTEGER);
    INSERT INTO users VALUES (1,'admin','admin123','admin','FLAG{admin_secret_123}');
    INSERT INTO users VALUES (2,'alice','password1','user','alice private note: card 4111-1111-1111-1111');
    INSERT INTO users VALUES (3,'bob','qwerty','user','bob private note');
    INSERT INTO products VALUES (1,'Laptop',999.0,5),(2,'Phone',599.0,10),(3,'Headphones',99.0,0);
    INSERT INTO posts VALUES (1,'alice','Welcome to the guestbook!');
    """)
    c.commit()


# (vulnerability, sample link, test payload)
LABS = [
    ("SQLi - auth bypass", "/login", "username: admin' --   password: anything"),
    ("SQLi - UNION", "/search?q=a", "' UNION SELECT id,username,password FROM users --"),
    ("SQLi - blind boolean", "/product?id=1", "1 AND (SELECT substr(password,1,1) FROM users WHERE id=1)='a'"),
    ("SQLi - error based", "/search?q=a", "'"),
    ("Reflected XSS", "/hello?name=guest", "<script>alert(document.domain)</script>"),
    ("Stored XSS", "/guestbook", "<img src=x onerror=alert(document.cookie)>"),
    ("DOM XSS", "/dom", "/dom#<img src=x onerror=alert(1)>"),
    ("Command injection", "/tools", "127.0.0.1; id   |   127.0.0.1 && whoami   |   $(id)"),
    ("Path traversal / LFI", "/read?file=app.txt", "../../../../etc/passwd"),
    ("IDOR", "/profile/1", "Change the ID: /profile/2, /profile/3 ..."),
    ("Open redirect", "/redirect?url=/", "https://example.com"),
    ("SSRF", "/fetch?url=http://127.0.0.1:5000/", "http://127.0.0.1:5000/admin   |   file:///etc/passwd"),
    ("Insecure deserialization", "/load", "base64 of a pickle with __reduce__ -> os.system"),
    ("SSTI (Jinja2)", "/template?name=guest", "{{7*7}}   |   {{config}}   |   {{request.application.__globals__}}"),
    ("XXE", "/xml", '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>'),
    ("Code injection (eval)", "/calc?expr=1%2B1", "__import__('os').popen('id').read()"),
    ("JWT alg=none / weak secret", "/api/token?user=alice", "Forge token with alg none or sign with key 'secret', role=admin"),
    ("Mass assignment", "/register", "Add field role=admin to the POST body"),
    ("Insecure cookie", "/whoami", 'Edit cookie auth = base64({"user":"x","role":"admin"})'),
    ("Predictable reset token", "/reset", "token = first 8 chars of md5(username)"),
    ("User enumeration", "/reset", "Different message for existing/non-existing users"),
    ("No rate limit / brute force", "/login", "Run hydra/Burp Intruder against /login"),
    ("Price tampering / logic flaw", "/shop", "Set price=0.01 or qty=-5 in the checkout request"),
    ("CSRF", "/change_password?new=hacked", "<img src='http://127.0.0.1:5000/change_password?new=pwned'>"),
    ("Unrestricted file upload", "/upload", "Upload .html with script or .py/.php; fetch at /uploads/<name>"),
    ("Broken access control", "/admin", "Open directly, no login required"),
    ("Sensitive file exposure", "/robots.txt", "/.env   /backup.sql   /robots.txt"),
    ("Clickjacking / CORS / no headers", "/", "iframe the site from another origin; check response headers"),
]


@app.route("/")
def index():
    rows = "".join(f'<tr><td>{i}</td><td>{v}</td><td><a href="{u}">{u}</a></td></tr>' for i, (v, u, _) in enumerate(LABS, 1))
    return page("Home", f'<p class=warn>Intentionally vulnerable. Local use only.</p>'
                        f'<table><tr><th>#</th><th>Vulnerability</th><th>Try it</th></tr>{rows}</table>')


@app.route("/payloads")
def payloads():
    rows = "".join(f"<tr><td>{html.escape(v)}</td><td>{html.escape(u)}</td><td><code>{html.escape(p)}</code></td></tr>" for v, u, p in LABS)
    return page("Payloads", f"<table><tr><th>Vulnerability</th><th>Endpoint</th><th>Payload</th></tr>{rows}</table>")


@app.route("/tools")
def tools():
    return page("Tools", """
    <div class=card><b>Ping</b><form action=/ping><input name=host value=127.0.0.1><button>Ping</button></form></div>
    <div class=card><b>Read file</b><form action=/read><input name=file value=app.txt><button>Read</button></form></div>
    <div class=card><b>Fetch URL</b><form action=/fetch><input name=url value=http://127.0.0.1:5000/><button>Fetch</button></form></div>
    <div class=card><b>Calculator</b><form action=/calc><input name=expr value="2+2"><button>Calc</button></form></div>
    <div class=card><b>Greeting</b><form action=/template><input name=name value=guest><button>Go</button></form></div>
    <div class=card><b>XML parser</b><form action=/xml method=post><textarea name=xml rows=4 cols=60><x>hi</x></textarea><br><button>Parse</button></form></div>
    <div class=card><b>Deserialize</b><form action=/load><input name=data placeholder=base64-pickle><button>Load</button></form></div>
    <div class=card><b>Upload</b> <a href=/upload>go to upload</a> | <a href=/dom>DOM XSS lab</a> | <a href=/reset>Password reset</a> | <a href=/api/token?user=alice>JWT</a></div>""")


# ---------- Auth ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        u, p = request.form["user"], request.form["pass"]
        q = f"SELECT id,username,role FROM users WHERE username='{u}' AND password='{p}'"   # SQLi
        try:
            row = db().execute(q).fetchone()
        except Exception as e:
            return page("Login", f"<pre>SQL error: {e}\nQuery: {q}</pre>")                  # verbose errors
        if row:
            session["user"] = row[1]
            r = make_response(page("Login", f"Welcome {row[1]} ({row[2]})"))
            r.set_cookie("auth", base64.b64encode(json.dumps({"user": row[1], "role": row[2]}).encode()).decode())
            return r                                                                         # unsigned cookie, no HttpOnly
        msg = "<p class=warn>Invalid login</p>"                                              # no rate limiting
    return page("Login", msg + "<form method=post>User<br><input name=user><br>Pass<br><input name=pass type=password><br><button>Login</button></form>")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = request.form
        c = db()
        c.execute("INSERT INTO users(username,password,role,secret) VALUES (?,?,?,?)",
                  (f["user"], f["pass"], f.get("role", "user"), ""))                         # mass assignment, plaintext pw
        c.commit()
        return page("Register", "Registered as role: " + html.escape(f.get("role", "user")))
    return page("Register", "<form method=post>User<br><input name=user><br>Pass<br><input name=pass><br><input type=hidden name=role value=user><button>Register</button></form>")


@app.route("/whoami")
def whoami():
    try:
        d = json.loads(base64.b64decode(request.cookies.get("auth", "")))
    except Exception:
        return page("Who am I", "Not logged in")
    extra = "<b>FLAG{cookie_tampering}</b>" if d.get("role") == "admin" else ""
    return page("Who am I", f"{d}<br>{extra}")


@app.route("/reset", methods=["GET", "POST"])
def reset():
    if request.method == "POST":
        u = request.form["user"]
        if not db().execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone():
            return page("Reset", "User does not exist")                                      # user enumeration
        tok = hashlib.md5(u.encode()).hexdigest()[:8]                                         # predictable token
        return page("Reset", f"Reset token sent (debug: {tok}). Use /reset/confirm?user={u}&token={tok}&new=pw")
    return page("Reset", "<form method=post><input name=user placeholder=username><button>Send token</button></form>")


@app.route("/reset/confirm")
def reset_confirm():
    u, t, n = request.args.get("user", ""), request.args.get("token", ""), request.args.get("new", "")
    if t == hashlib.md5(u.encode()).hexdigest()[:8]:
        c = db(); c.execute("UPDATE users SET password=? WHERE username=?", (n, u)); c.commit()
        return page("Reset", "Password reset")
    return page("Reset", "Bad token")


@app.route("/change_password", methods=["GET", "POST"])
def change_password():                                                                        # CSRF: GET works, no token
    c = db()
    c.execute("UPDATE users SET password=? WHERE username=?", (request.values.get("new", ""), session.get("user", "admin")))
    c.commit()
    return page("Change password", "Password changed")


# ---------- JWT ----------
def b64u(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def b64d(s): return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@app.route("/api/token")
def token():
    h = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = b64u(json.dumps({"user": request.args.get("user", "guest"), "role": "user"}).encode())
    s = b64u(hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
    return page("JWT", f"<code>{h}.{p}.{s}</code><p>Send as header <code>Authorization: Bearer &lt;token&gt;</code> to /api/me</p>")


@app.route("/api/me")
def api_me():
    try:
        h, p, s = request.headers.get("Authorization", "").replace("Bearer ", "").split(".")
        alg = json.loads(b64d(h)).get("alg")
        if alg != "none":                                                                     # alg=none accepted
            good = b64u(hmac.new(JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
            if not hmac.compare_digest(s, good):
                return "bad signature", 401
        d = json.loads(b64d(p))
        return {"claims": d, "flag": "FLAG{jwt_pwned}" if d.get("role") == "admin" else None}
    except Exception as e:
        return str(e), 400


# ---------- SQL injection ----------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    try:
        rows = db().execute(f"SELECT id,username,role FROM users WHERE username LIKE '%{q}%'").fetchall()
    except Exception as e:
        return page("Search", f"<pre>SQL error: {e}</pre>")
    return page("Search", f"Results for {q}:<pre>{rows}</pre>")                               # also reflected XSS


@app.route("/product")
def product():
    pid = request.args.get("id", "1")
    try:
        r = db().execute(f"SELECT name,stock FROM products WHERE id={pid}").fetchone()        # blind SQLi
    except Exception:
        r = None
    return page("Product", "In stock" if r and r[1] > 0 else "Not available")


# ---------- XSS ----------
@app.route("/hello")
def hello():
    return page("Hello", f"Hello {request.args.get('name', '')}")


@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    c = db()
    if request.method == "POST":
        c.execute("INSERT INTO posts(author,body) VALUES (?,?)", (session.get("user", "anon"), request.form["body"]))
        c.commit()
    posts = "".join(f"<div class=card><b>{a}</b>: {b}</div>" for a, b in c.execute("SELECT author,body FROM posts"))
    return page("Guestbook", f"<form method=post><input name=body size=50><button>Post</button></form>{posts}")


@app.route("/dom")
def dom():
    return page("DOM XSS", '<div id=out></div><script>document.getElementById("out").innerHTML="Hash: "+decodeURIComponent(location.hash.slice(1))</script>')


# ---------- Injection / file / network ----------
@app.route("/ping")
def ping():
    o = subprocess.run(f"ping -c 1 {request.args.get('host', '127.0.0.1')}", shell=True, capture_output=True, text=True)
    return page("Ping", f"<pre>{o.stdout}{o.stderr}</pre>")


@app.route("/read")
def read():
    try:
        return page("Read", f"<pre>{html.escape(open(request.args.get('file', '')).read())}</pre>")
    except Exception as e:
        return page("Read", str(e))


@app.route("/fetch")
def fetch():
    try:
        return page("Fetch", f"<pre>{html.escape(urllib.request.urlopen(request.args.get('url', ''), timeout=5).read().decode(errors='replace'))}</pre>")
    except Exception as e:
        return page("Fetch", str(e))


@app.route("/calc")
def calc():
    try:
        return page("Calc", str(eval(request.args.get("expr", "0"))))                         # eval injection
    except Exception as e:
        return page("Calc", str(e))


@app.route("/template")
def template():
    return render_template_string("<h3>Hello " + request.args.get("name", "guest") + "</h3>")  # SSTI


@app.route("/xml", methods=["GET", "POST"])
def xml():
    if request.method == "GET":
        return page("XML", "<form method=post><textarea name=xml rows=6 cols=70></textarea><br><button>Parse</button></form>")
    try:
        from lxml import etree
        root = etree.fromstring(request.form["xml"].encode(), etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False))
        return page("XML", f"<pre>{html.escape(''.join(root.itertext()))}</pre>")             # XXE
    except ImportError:
        return page("XML", "pip install lxml")
    except Exception as e:
        return page("XML", html.escape(str(e)))


@app.route("/load")
def load():
    d = request.args.get("data")
    if not d:
        return page("Deserialize", "<form><input name=data size=60 placeholder=base64-pickle><button>Load</button></form>")
    return page("Deserialize", html.escape(str(pickle.loads(base64.b64decode(d)))))          # insecure deserialization


# ---------- Access control / misc ----------
@app.route("/profile/<int:uid>")
def profile(uid):                                                                             # IDOR
    return page("Profile", f"<pre>{db().execute('SELECT * FROM users WHERE id=?', (uid,)).fetchone()}</pre>")


@app.route("/admin")
def admin():                                                                                  # no auth check
    return page("Admin", f"<pre>{db().execute('SELECT * FROM users').fetchall()}</pre>")


@app.route("/redirect")
def open_redirect():
    return redirect(request.args.get("url", "/"))


@app.route("/shop", methods=["GET", "POST"])
def shop():
    if request.method == "POST":
        qty, price = float(request.form["qty"]), float(request.form["price"])                # client-side price, negative qty
        return page("Shop", f"Order placed. Total charged: ${qty * price:.2f}")
    rows = "".join(f"<tr><td>{n}</td><td>${p}</td><td><form method=post><input type=hidden name=price value={p}>"
                   f"<input name=qty value=1 size=3><button>Buy</button></form></td></tr>"
                   for n, p in db().execute("SELECT name,price FROM products"))
    return page("Shop", f"<table><tr><th>Item</th><th>Price</th><th></th></tr>{rows}</table>")


@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        f = request.files["file"]
        f.save(os.path.join("uploads", f.filename))                                           # no validation
        return page("Upload", f'Saved: <a href="/uploads/{f.filename}">/uploads/{f.filename}</a>')
    return page("Upload", "<form method=post enctype=multipart/form-data><input type=file name=file><button>Upload</button></form>")


@app.route("/uploads/<path:name>")
def uploaded(name):
    return send_from_directory("uploads", name)                                               # serves HTML/JS -> stored XSS


@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /admin\nDisallow: /backup.sql\nDisallow: /.env", 200, {"Content-Type": "text/plain"}


@app.route("/.env")
def env():
    return "DB_PASSWORD=supersecret\nAWS_KEY=AKIAFAKEFAKEFAKE1234\nSECRET_KEY=123456", 200, {"Content-Type": "text/plain"}


@app.route("/backup.sql")
def backup():
    return "INSERT INTO users VALUES (1,'admin','admin123');", 200, {"Content-Type": "text/plain"}


@app.after_request
def headers(r):
    r.headers["Access-Control-Allow-Origin"] = "*"                                            # open CORS; no CSP / X-Frame-Options
    r.headers["Server"] = "VulnLab/1.0 Flask debug"
    return r


if __name__ == "__main__":
    open("app.txt", "w").write("hello from app.txt")
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)                                          # Werkzeug debugger enabled
