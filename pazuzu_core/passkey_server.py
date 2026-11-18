"""A small page on this PC for registering and using the passkey.

Run on the owner's PC only. It answers on http://localhost:<port>/ and nothing
else: passkeys need a site name the browser trusts, and "localhost" is one.
It never talks to the firewall and never holds a firewall key; it only turns
a passkey touch into a yes or no for one plan digest.

    python -m pazuzu_core.passkey_server register
    python -m pazuzu_core.passkey_server approve --digest <digest> --line "what changes"

Guards, each tested:
* the Host header must be exactly localhost:<this port> (a different name or
  port is refused, which also stops DNS rebinding);
* every POST must come from this page's own origin and be JSON;
* the page loads nothing from outside and runs only its own script;
* a second passkey can only be added after an existing one approves it.
If the passkey is lost there is no back door: reset and enroll again.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import threading
import time
import webbrowser
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable

from pazuzu_core import passkey as pk

DEFAULT_PORT = 8766
RP_ID = "localhost"
RP_NAME = "Hanbi"
REGISTER_DIGEST = "register-a-passkey"
ADD_DIGEST = "add-a-passkey"
MAX_PASSKEYS = 5
ADD_WINDOW_SECONDS = 120
MAX_BODY = 64 * 1024
LABEL_MAX = 40


@dataclass(frozen=True)
class Pending:
    """The one plan waiting for approval: its digest and what it will do."""

    digest: str
    lines: tuple[str, ...]


class Service:
    """The logic behind the page. No HTTP in here, so it is easy to test."""

    def __init__(self, creds_path: Path, origin: str, pending: Pending | None = None,
                 clock: Callable[[], float] = time.time):
        self.path = Path(creds_path)
        self.origin = origin
        # Other pages on this device that may show the approval (the manager). Approving only:
        # a new passkey can still be registered from the setup page's own address alone.
        self.approve_origins: tuple[str, ...] = ()
        self.pending = pending
        self._clock = clock
        self._lock = threading.Lock()
        self._issuer = pk.Issuer(clock=clock)
        self._creds = pk.load_credentials(self.path)
        self._add_until = 0.0
        self.approved = threading.Event()
        self.registered = threading.Event()

    # -- what the page shows
    def state(self) -> dict:
        with self._lock:
            return {
                "passkeys": [c.label or "passkey" for c in self._creds],
                "pending": (None if self.pending is None else
                            {"digest": self.pending.digest,
                             "lines": list(self.pending.lines)}),
                "approved": self.approved.is_set(),
                "can_add": self._clock() < self._add_until,
            }

    # -- registering
    def register_begin(self) -> dict:
        with self._lock:
            self._check_can_register()
            challenge = self._issuer.issue(REGISTER_DIGEST)
            return {"challenge": challenge.value, "rp_id": RP_ID,
                    "rp_name": RP_NAME,
                    "exclude": [c.credential_id for c in self._creds]}

    def register_finish(self, label, attestation: str, client: str) -> dict:
        with self._lock:
            self._check_can_register()
            client_bytes = pk.unb64url(client)
            challenge = self._issuer.take(_challenge_of(client_bytes))
            if challenge.digest != REGISTER_DIGEST:
                raise pk.PasskeyError("that was not asked for as a new passkey")
            cred = pk.register(
                attestation_object=pk.unb64url(attestation),
                client_data_json=client_bytes, challenge=challenge.value,
                rp_id=RP_ID, origin=self.origin, label=_clean_label(label))
            if any(c.credential_id == cred.credential_id for c in self._creds):
                raise pk.PasskeyError("that passkey is already registered")
            self._creds = self._creds + (cred,)
            pk.save_credentials(self.path, self._creds)
            self._add_until = 0.0
            self.registered.set()
            return {"ok": True, "count": len(self._creds)}

    def _check_can_register(self) -> None:
        if len(self._creds) >= MAX_PASSKEYS:
            raise pk.PasskeyError(f"there is room for {MAX_PASSKEYS} passkeys")
        if self._creds and self._clock() >= self._add_until:
            raise pk.PasskeyError(
                "approve with a passkey you already have before adding another")

    # -- approving
    def approve_begin(self, purpose: str) -> dict:
        with self._lock:
            digest = self._digest_for(purpose)
            if not self._creds:
                raise pk.PasskeyError("there is no passkey yet: register one first")
            challenge = self._issuer.issue(digest)
            return {"challenge": challenge.value, "rp_id": RP_ID,
                    "allow": [c.credential_id for c in self._creds]}

    def approve_finish(self, purpose: str, credential_id: str, client: str,
                       auth: str, signature: str) -> dict:
        with self._lock:
            digest = self._digest_for(purpose)
            self._creds = pk.verify_approval(
                self._issuer, self._creds, expected_digest=digest,
                credential_id=credential_id,
                client_data_json=pk.unb64url(client),
                authenticator_data=pk.unb64url(auth),
                signature=pk.unb64url(signature), rp_id=RP_ID,
                origin=(self.origin, *self.approve_origins))
            pk.save_credentials(self.path, self._creds)
            if purpose == "plan":
                self.approved.set()
            else:
                self._add_until = self._clock() + ADD_WINDOW_SECONDS
            return {"ok": True}

    def _digest_for(self, purpose: str) -> str:
        if purpose == "plan":
            if self.pending is None:
                raise pk.PasskeyError("there is no change waiting for approval")
            return self.pending.digest
        if purpose == "add":
            return ADD_DIGEST
        raise pk.PasskeyError("unknown request")


def _challenge_of(client_bytes: bytes) -> str:
    try:
        return json.loads(client_bytes.decode("utf-8"))["challenge"]
    except (ValueError, KeyError, TypeError, UnicodeDecodeError) as exc:
        raise pk.PasskeyError("the browser's record could not be read") from exc


def _clean_label(label) -> str:
    text = "".join(ch for ch in str(label or "") if ch.isprintable()).strip()
    return text[:LABEL_MAX] or "passkey"


# --- the page --------------------------------------------------------------------

PAGE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hanbi passkey</title>
<style nonce="NONCE">
:root{color-scheme:light dark;--bg:#fff;--fg:#1a1d21;--mut:#5a6270;--line:#d5d9e0;--acc:#1f5fbf;--bad:#b3261e}
@media (prefers-color-scheme:dark){:root{--bg:#14171b;--fg:#e8eaee;--mut:#9aa3b0;--line:#2c323b;--acc:#7fb0ff;--bad:#ff8a80}}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:34rem;margin:0 auto;padding:2rem 1rem}
h1{font-size:1.4rem;margin:0 0 .5rem}p{margin:.5rem 0}.mut{color:var(--mut)}
ul{padding-left:1.2rem}li{margin:.25rem 0}
code{font-family:ui-monospace,monospace;font-size:.95em}
.card{border:1px solid var(--line);border-radius:10px;padding:1rem;margin:1rem 0}
button{font:inherit;padding:.6rem 1rem;border-radius:8px;border:1px solid var(--acc);background:var(--acc);color:var(--bg);cursor:pointer}
button.quiet{background:none;color:var(--acc)}button:disabled{opacity:.5;cursor:default}
input{font:inherit;padding:.5rem;border-radius:8px;border:1px solid var(--line);background:none;color:var(--fg);width:100%;box-sizing:border-box}
#err{color:var(--bad);min-height:1.5rem}
</style></head><body><main>
<h1 id="h">Hanbi passkey</h1>
<div id="body" class="mut">Loading…</div>
<p id="err" role="alert"></p>
</main>
<script nonce="NONCE">
const $ = (id) => document.getElementById(id);
const dec = (s) => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
const enc = (b) => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
function el(tag, text, cls){const e=document.createElement(tag); if(text!==undefined)e.textContent=text; if(cls)e.className=cls; return e;}
async function post(path, body){
  const r = await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  const j = await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(j.error || 'That did not work.');
  return j;
}
function fail(e){ $('err').textContent = (e && e.name==='NotAllowedError') ? 'The passkey was cancelled or timed out. Try again.' : (e.message || String(e)); }
async function run(button, work){
  $('err').textContent=''; button.disabled=true;
  try{ await work(); await show(); }catch(e){ fail(e); button.disabled=false; }
}
async function register(label){
  const b = await post('/api/register/begin',{label});
  const cred = await navigator.credentials.create({publicKey:{
    challenge: dec(b.challenge), rp:{id:b.rp_id,name:b.rp_name},
    user:{id:new TextEncoder().encode('pazuzu-'+(label||'passkey')),name:label||'passkey',displayName:label||'passkey'},
    pubKeyCredParams:[{type:'public-key',alg:-7}], attestation:'none', timeout:120000,
    excludeCredentials:b.exclude.map(id=>({type:'public-key',id:dec(id)})),
    authenticatorSelection:{residentKey:'preferred',userVerification:'required'}}});
  await post('/api/register/finish',{label,attestation:enc(cred.response.attestationObject),client:enc(cred.response.clientDataJSON)});
}
async function approve(purpose){
  const b = await post('/api/approve/begin',{purpose});
  const cred = await navigator.credentials.get({publicKey:{
    challenge: dec(b.challenge), rpId:b.rp_id, timeout:120000, userVerification:'required',
    allowCredentials:b.allow.map(id=>({type:'public-key',id:dec(id)}))}});
  await post('/api/approve/finish',{purpose,id:enc(cred.rawId),client:enc(cred.response.clientDataJSON),
    auth:enc(cred.response.authenticatorData),sig:enc(cred.response.signature)});
}
function labelBox(){ const i=el('input'); i.id='label'; i.maxLength=40; i.placeholder='Name this passkey, for example "my laptop"'; return i; }
async function show(){
  const s = await (await fetch('/api/state')).json();
  const body = $('body'); body.className=''; body.replaceChildren();
  if(s.approved){
    $('h').textContent='Approved';
    body.append(el('p','You can close this tab. The change will go ahead.'));
    return;
  }
  if(s.passkeys.length===0){
    $('h').textContent='Register your passkey';
    body.append(el('p','This passkey approves every change to your firewall. Looking never needs it.'));
    body.append(el('p','If you lose it, you reset the firewall and set up again. There is no back door.','mut'));
    const box = labelBox(); const btn = el('button','Create passkey');
    btn.onclick = () => run(btn, () => register(box.value));
    body.append(box, el('p'), btn); return;
  }
  if(s.pending){
    $('h').textContent='Approve this change';
    const card = el('div',undefined,'card'); const list = el('ul');
    s.pending.lines.forEach(t => list.append(el('li',t)));
    card.append(list, el('p','Plan digest: '+s.pending.digest,'mut'));
    const btn = el('button','Approve with passkey');
    btn.onclick = () => run(btn, () => approve('plan'));
    body.append(card, btn); return;
  }
  $('h').textContent='Your passkey is set up';
  const ul = el('ul'); s.passkeys.forEach(n => ul.append(el('li',n))); body.append(ul);
  if(s.passkeys.length<5){
    const box = labelBox(); const btn = el('button',s.can_add?'Add this passkey':'Add another passkey','quiet');
    btn.onclick = () => run(btn, async () => { if(!s.can_add){ await approve('add'); } await register(box.value); });
    body.append(el('p','Adding one needs a passkey you already have to approve it first.','mut'), box, el('p'), btn);
  }
}
show().catch(fail);
</script></body></html>
"""


# --- the server ------------------------------------------------------------------

def make_handler(service: Service, port_getter: Callable[[], int]):
    class Handler(BaseHTTPRequestHandler):
        server_version = "HanbiPasskey"
        sys_version = ""

        def log_message(self, fmt, *args):
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

        def _send(self, code: int, body: bytes, ctype: str, nonce: str = "") -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            script = f"script-src 'nonce-{nonce}'" if nonce else "script-src 'none'"
            style = f"style-src 'nonce-{nonce}'" if nonce else "style-src 'none'"
            self.send_header(
                "Content-Security-Policy",
                f"default-src 'none'; {script}; {style}; connect-src 'self'; "
                "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(body)

        def _json(self, code: int, payload) -> None:
            self._send(code, json.dumps(payload).encode("utf-8"),
                       "application/json; charset=utf-8")

        def _own_host(self) -> str:
            return f"localhost:{port_getter()}"

        def _host_ok(self) -> bool:
            if (self.headers.get("Host") or "").strip().lower() == self._own_host():
                return True
            self._json(421, {"error": f"open http://{self._own_host()}/ "
                                      "(passkeys only work on the name localhost)"})
            return False

        def do_GET(self) -> None:  # noqa: N802
            if not self._host_ok():
                return
            if self.path in ("/", "/index.html"):
                nonce = secrets.token_urlsafe(16)
                self._send(200, PAGE.replace("NONCE", nonce).encode("utf-8"),
                           "text/html; charset=utf-8", nonce)
            elif self.path == "/api/state":
                self._json(200, service.state())
            else:
                self._json(404, {"error": "not found"})

        ROUTES = {
            "/api/register/begin": lambda s, d: s.register_begin(),
            "/api/register/finish": lambda s, d: s.register_finish(
                d.get("label"), d["attestation"], d["client"]),
            "/api/approve/begin": lambda s, d: s.approve_begin(d.get("purpose")),
            "/api/approve/finish": lambda s, d: s.approve_finish(
                d.get("purpose"), d["id"], d["client"], d["auth"], d["sig"]),
        }

        def do_POST(self) -> None:  # noqa: N802
            if not self._host_ok():
                return
            if self.headers.get("Origin") != f"http://{self._own_host()}":
                self._json(403, {"error": "this request did not come from the page"})
                return
            if (self.headers.get("Content-Type") or "").split(";")[0].strip() \
                    != "application/json":
                self._json(415, {"error": "JSON only"})
                return
            route = self.ROUTES.get(self.path)
            if route is None:
                self._json(404, {"error": "not found"})
                return
            try:
                size = int(self.headers.get("Content-Length") or "")
            except ValueError:
                self._json(411, {"error": "length needed"})
                return
            if not 0 < size <= MAX_BODY:
                self._json(413, {"error": "request too large"})
                return
            try:
                data = json.loads(self.rfile.read(size).decode("utf-8"))
                if not isinstance(data, dict):
                    raise ValueError
                self._json(200, route(service, data))
            except pk.PasskeyError as exc:
                self._json(400, {"error": str(exc)})
            except (ValueError, KeyError, TypeError, UnicodeDecodeError):
                self._json(400, {"error": "that request was not understood"})
            except OSError:
                self._json(500, {"error": "could not save the passkey file"})

        def _refuse(self) -> None:
            self.close_connection = True
            self._json(405, {"error": "not allowed"})

        do_PUT = do_DELETE = do_PATCH = _refuse  # noqa: N815

    return Handler


class QuietServer(ThreadingHTTPServer):
    """A local page server that does not print a traceback when the browser drops a connection on its own (a closed
    tab, a reload mid-answer, a request the page gave up on). On Windows that shows as ConnectionAbortedError and was
    printed as a wall of noise in the window the person runs the setup from. Anything else is still reported."""

    DROPPED = (ConnectionAbortedError, ConnectionResetError, BrokenPipeError)

    def handle_error(self, request, client_address):
        import sys as _sys
        if isinstance(_sys.exc_info()[1], self.DROPPED):
            return
        super().handle_error(request, client_address)


def make_server(service: Service, port: int = DEFAULT_PORT) -> ThreadingHTTPServer:
    holder: dict[str, ThreadingHTTPServer] = {}
    server = QuietServer(
        ("127.0.0.1", port), make_handler(service, lambda: holder["s"].server_address[1]))
    holder["s"] = server
    return server


def origin_for(port: int) -> str:
    return f"http://localhost:{port}"


def serve_until(mode: str, creds_dir: Path, port: int = DEFAULT_PORT,
                pending: Pending | None = None, timeout: float = 300,
                open_browser: bool = True, say=print) -> bool:
    """Run the page until the job is done or time runs out. True when done."""

    svc = Service(Path(creds_dir) / pk.CREDENTIALS_FILE, origin_for(port), pending)
    server = make_server(svc, port)
    real_port = server.server_address[1]
    svc.origin = origin_for(real_port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    url = origin_for(real_port) + "/"
    say(f"Open {url} in your browser. Waiting for your passkey...")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:        # no browser to open: the printed address still works
            pass
    event = svc.approved if mode == "approve" else svc.registered
    try:
        return event.wait(timeout)
    finally:
        time.sleep(0.3)          # let the page fetch its final state
        server.shutdown()
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="passkey_server")
    parser.add_argument("mode", choices=["register", "approve"])
    parser.add_argument("--digest")
    parser.add_argument("--line", action="append", default=[],
                        help="a sentence saying what the change does (repeatable)")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--dir", default=str(Path.home() / ".pazuzu"))
    parser.add_argument("--timeout", type=float, default=300)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args(argv)
    if not pk.HAVE_CRYPTO:
        print("Passkeys need the 'cryptography' package: pip install cryptography")
        return 2
    pending = None
    if args.mode == "approve":
        if not args.digest:
            print("approve needs --digest")
            return 2
        pending = Pending(args.digest, tuple(args.line) or ("(no description given)",))
    try:
        done = serve_until(args.mode, Path(args.dir), args.port, pending,
                           args.timeout, not args.no_browser)
    except (OSError, pk.PasskeyError) as exc:
        print(f"Could not start: {exc}")
        return 1
    print("Done." if done else "Timed out: nothing was approved.")
    return 0 if done else 1


if __name__ == "__main__":
    raise SystemExit(main())
