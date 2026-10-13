# doubletap

**Automated Ruby on Rails remote code execution** — a pure-Python implementation of the
*doubletap* chain: an Action View file-content disclosure leading to a predictable
development-mode `secret_key_base`, which is used to forge an `ActiveStorage` disk-service
key that deserializes into a Ruby `Marshal` gadget and executes a command.

```
CVE-2019-5418  (Action View file content disclosure)
        │
        ▼
   secret_key_base   ──►  CVE-2019-5420  (dev-mode key → ActiveStorage Marshal deserialization)
        │
        ▼
   Marshal gadget    ──►  CVE-2026-41316  (ERB#def_module @_init guard bypass)
        │
        ▼
   Remote code execution
```

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Platform](https://img.shields.io/badge/platform-linux-informational.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)

> **For authorized security testing only.** Use this only against systems you own or have
> explicit written permission to test (pentest engagements, CTF/competition ranges, your
> own lab). Unauthorized access to computer systems is illegal. You are responsible for
> complying with all applicable laws. See [Disclaimer](#disclaimer).

---

## Why another doubletap?

`mpgn/Rails-doubletap-RCE` is the original proof of concept, and `exploit/multi/http/rails_double_tap`
is the Metasploit module. Both were written for **Ruby ≤ 2.6** and depend on booting a local
Rails 5 app to borrow ActiveSupport's serialization. Against a modern target they break:

* **`ERB#result` is guarded.** Ruby 2.7 added an `@_init` check to `ERB#result`/`#run`
  that refuses `Marshal`-reconstructed ERB objects, so the classic gadget raises
  `ArgumentError: not initialized`.
* **They rely on the credential files.** The Metasploit module also guesses the application
  name with `"dir".capitalize`, which does not produce the Ruby module name (`my-app` →
  `My-app`, not `MyApp`), and expects an HTTP 200 that a successful hit does not return.

This tool reimplements the whole chain in Python (no Ruby runtime, no bundled Rails app),
defaults to a gadget that survives the `@_init` guard, and automates recon so that only the
target and the command are needed.

## Supported versions

The chain has three independent requirements; all must hold on the target.

| Component | Vulnerable range | Fixed in |
| --- | --- | --- |
| Dev-mode `secret_key_base` (CVE-2019-5420) | Rails **< 5.2.2.1**, **< 6.0.0.beta3**, running in **development/test**, with ActiveStorage present | 5.2.2.1 / 6.0.0.beta3 |
| Action View file disclosure (CVE-2019-5418) | Action View **< 6.0.0.beta3, < 5.2.2.1, < 5.1.6.2, < 5.0.7.2, < 4.2.11.1** *and* a controller that calls `render file:` with no explicit format | same |
| Marshal gadget | Ruby **≤ 2.6** for `--classic`; Ruby **≥ 2.5** (incl. 2.7 / 3.x) with an unpatched `erb` for the default gadget | `erb` 4.0.3.1 / 4.0.4.1 / 6.0.1.1 / 6.0.4 |

Additional notes:

* CVE-2019-5420 requires Rails **5.2+** (ActiveStorage). Rails **≤ 5.1** has no
  `/rails/active_storage/disk` route and is **not** exploitable through this chain.
* The `@_init` guard in `ERB#result` / `ERB#run` landed in **Ruby 2.7.0**.
* The `ERB#def_module` guard (CVE-2026-41316) is what the default gadget bypasses; once
  patched in `erb`, both gadgets are dead.
* The real determinant on the gadget side is the loaded **`erb` version**, not the Ruby
  version — an app pinning an old `erb` in its `Gemfile.lock` stays exploitable.

### Verified vs. expected

**Verified working — runtime-tested against a real target:**

| Field | Value |
| --- | --- |
| Rails | **5.2.2** |
| Ruby | **2.7.8** |
| Environment | development |
| Gadget | default (`ERB#def_module`) |
| Key source | dev-mode `MD5("<AppClass>::Application")` |
| Output mode | web-root (`public/`) exfil |
| Platform | Linux x86_64 |
| Result | command execution as the app user (was `root` in our test) |

**Expected to work — derived from upstream code/advisories and unit-tested in isolation, but
not run end-to-end by us. Verify before relying on it:**

* `--classic` (`ERB#result`) on Ruby ≤ 2.6.
* The `CVE-2019-5418` file-disclosure path (reading `credentials.yml.enc` + `master.key`) and
  reflective output capture.
* Non-development targets (see [When it's not development mode](#when-its-not-development-mode)).
* Other platforms / OSes.

**Not supported:** Rails ≥ 5.2.2.1 or ≥ 6.0.0.beta3 (key no longer predictable), Rails ≤ 5.1
(no ActiveStorage disk route), and any target whose `erb` is patched for CVE-2026-41316.

## When it's not development mode

In production the `secret_key_base` is no longer `MD5(app name)`, so the dev-key path cannot
work. The tool can still succeed **only** if it can recover the real key:

* a `CVE-2019-5418` `render file:` sink must exist, **and**
* `config/credentials.yml.enc` **and** `config/master.key` must both be readable through it
  (if the master key is injected as `RAILS_MASTER_KEY` and no `master.key` file is deployed,
  this fails), **and**
* the `/rails/active_storage/disk/...` route must be present.

If those hold, the tool discloses and decrypts the credentials, verifies the key with the
signature oracle, and proceeds exactly as in development. Otherwise it exits with
`could not determine secret_key_base`.

## When auto-recon fails

Recon reads the development info pages (`/rails/info/properties`, `/rails/info/routes`).
Those are absent or disabled in production, or when `consider_all_requests_local = false`.
If recon comes back empty, supply whatever it could not discover:

| Symptom | Override |
| --- | --- |
| No file-disclosure sink discovered | `--resource /path` (point at a `render file:` route) |
| App root / app class name unknown | `--dev-md5 APPCLASS` (development targets) |
| Key unknown entirely | `--secret-key-base <hex>` |
| Old target (Ruby ≤ 2.6) | `--classic` |
| Traffic routed through Burp | `--proxy http://127.0.0.1:8080` |

## Using it as a library

`doubletap.py` is importable; the primitives are usable on their own for custom work:

```python
import doubletap as dt

# Build and sign your own payload (default = ERB#def_module gadget)
marshal = dt.build_erb_gadget_marshal("system('id')")
token   = dt.active_storage_token(secret_key_base, marshal)

# Read an arbitrary file through a CVE-2019-5418 sink
http = dt.DoubleTap("http://target:3000")
data = http.accept_read("/some/render-file-route", "etc/passwd")

# Decrypt Rails credentials (Rails EncryptedFile format, AES-128-GCM)
yaml = dt.decrypt_credentials(enc_blob, master_key_hex)
```

## Features

* Pure Python: no Ruby, no `ActiveSupport`, no booting a demo Rails app.
* Full re-implementation of the Ruby-side primitives:
  * a minimal `Marshal.dump` writer (byte-compatible object graph),
  * AES-128-GCM decryption of `credentials.yml.enc` (Rails `EncryptedFile` format),
  * `PBKDF2-HMAC-SHA1` key derivation and `HMAC-SHA1` hex signing,
  * the `Messages::Metadata` JSON wrapper used by `MessageVerifier#generate`.
* **Automatic recon:** reads `/rails/info/properties` and `/rails/info/routes`.
* **Automatic sink discovery** for the `CVE-2019-5418` file-disclosure stage.
* **Automatic `secret_key_base` derivation**, verified with a `404`-oracle, from either the
  disclosed credentials or the development-mode `MD5("<AppClass>::Application")` fallback.
* **Two gadgets:** `ERB#def_module` (default, modern Ruby) and `ERB#result` (`--classic`).
* **Command output returned** in-band — via the file-disclosure sink, or by writing to
  `public/` and fetching it over HTTP. Commands are base64-transported so quoting is safe.
* Self-cleaning: temporary files are removed after use.

## Requirements

* Python 3.8+
* [`requests`](https://pypi.org/project/requests/)
* [`cryptography`](https://pypi.org/project/cryptography/) — only needed to decrypt
  `credentials.yml.enc` when a file-disclosure sink is present.

```bash
pip install -r requirements.txt
```

## Usage

Only the target and the command are required:

```bash
python3 doubletap.py -t http://target:3000 -c 'id'
```

Example:

```
$ python3 doubletap.py -t http://rails.local:3000 -c 'id; hostname'

Rails exploit CVE-2019-5418 + CVE-2019-5420 = RCE
target: http://rails.local:3000

[*] target: Rails 5.2.2 / Ruby 2.7.8 / env development / root /app
[*] routes: 6 discovered
[*] no CVE-2019-5418 render-file sink found (using dev-key + web-root path)
    MD5('MyApp::Application') -> 0f1e2d3c4b5a69788796a5b4c3d2e1f0  [verified]
[+] dev-mode secret_key_base = MD5('MyApp::Application') OK

[*] gadget: ERB#def_module (CVE-2026-41316)
[*] command: id; hostname

[*] mode: web-root exfil (write to public/, fetch over HTTP)
---- command output ----
uid=0(root) gid=0(root) groups=0(root)
rails.local
------------------------
```

### Options

| Flag | Description |
| --- | --- |
| `-t`, `--target` | Target base URL, e.g. `http://host:3000`. **Required.** |
| `-c`, `--command` | Command to run on the target (default: `id`). |
| `--secret-key-base` | Skip derivation and use this `secret_key_base`. |
| `--dev-md5 APPCLASS` | Force `MD5("APPCLASS::Application")` as the dev key. |
| `--resource PATH` | Force the render-file sink route. |
| `--proxy URL` | Route requests through a proxy (e.g. Burp). |
| `--classic` | Use the original `ERB#result` gadget (Ruby ≤ 2.6 targets). |
| `--no-cleanup` | Keep the exfiltration file on the target. |
| `--check-only` | Run recon only; do not exploit. |
| `--version` | Print version and exit. |

## How it works

1. **Recon.** Reads the development info pages to learn the Rails/Ruby version, environment,
   application root, and route table.
2. **Sink discovery.** Probes application routes for a `render file:` controller that leaks
   files through a crafted `Accept:` header (`CVE-2019-5418`). If one exists it is used both
   to read files and to retrieve command output.
3. **`secret_key_base`.**
   * If a sink exists, disclose `config/credentials.yml.enc` + `config/master.key` and decrypt
     them (AES-128-GCM), then verify.
   * Otherwise, in development mode the key is `MD5("<AppClass>::Application")`; candidate
     class names are derived from the session cookie and the app-root directory and each is
     verified with a signature oracle (`404` = rejected, anything else = accepted).
4. **Gadget.** A signed `ActiveStorage` `blob_key` is forged. Its value marshals an
   `ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy` that dispatches into an
   `ERB` object. `ERB#def_module` is used by default because it evaluates the template source
   without the `@_init` guard, and `@src` begins with `end\n` to break out of the generated
   method wrapper (`CVE-2026-41316`).
5. **Execute + capture.** The `GET /rails/active_storage/disk/<signed_key>/x` request triggers
   deserialization and command execution; output is read back through the disclosure sink or
   from `public/`.

## Mitigations

The chain depends on several independent weaknesses — fixing any one of them breaks it.

* **Upgrade Rails.** `CVE-2019-5418` is fixed in Action View `5.2.2.1`, `5.1.6.2`, `5.0.7.2`,
  `4.2.11.1`, `6.0.0.beta3`. `CVE-2019-5420` is fixed in Rails `5.2.2.1` / `6.0.0.beta3`
  (development keys are generated and persisted instead of derived from the app name).
* **Upgrade ERB.** `CVE-2026-41316` is fixed in `erb` `4.0.3.1`, `4.0.4.1`, `6.0.1.1`, `6.0.4`.
* **Never run development/test mode in production.** The predictable `secret_key_base` and
  the verbose `/rails/info/*` pages are development-only footguns.
* **Set `secret_key_base` explicitly** (env/credentials) even in development.
* **Disable `/rails/info` in shared environments** (`config.consider_all_requests_local = false`
  and do not ship the dev info routes).
* **Remove `render file:` on attacker-influenced paths** and pin an explicit format.
* Treat any `Marshal.load` of untrusted data as dangerous — these gadget chains are generic.

## Disclaimer

This software is provided for **authorized security testing, research, and education only**.
It is a proof-of-concept intended to help defenders understand and reproduce these
vulnerabilities, and to verify patches.

* Do **not** use it against systems you do not own or lack explicit written authorization to test.
* Unauthorized use against systems may violate the Computer Fraud and Abuse Act and equivalent
  laws in your jurisdiction.
* The authors and contributors accept **no liability** for misuse or for any damage caused.

By using this software you agree that you are solely responsible for your actions and that you
will use it only in a lawful, authorized manner.

## Credits

* **mpgn** — original `Rails-doubletap-RCE` proof of concept.
* **John Hawthorn** — discovery of `CVE-2019-5418`.
* **ooooooo_q** — discovery of `CVE-2019-5420`.
* **TristanInSec** — discovery of the `CVE-2026-41316` ERB `@_init` guard bypass.
* **sinn3r** — Metasploit `rails_double_tap` module (reference).

## References

* CVE-2019-5418 — Action View File Content Disclosure — <https://github.com/mpgn/CVE-2019-5418>
* CVE-2019-5420 — Rails dev-mode `secret_key_base` / ActiveStorage deserialization —
  <https://hackerone.com/reports/473888>
* CVE-2026-41316 — ERB `@_init` deserialization guard bypass —
  <https://github.com/ruby/erb/security/advisories/GHSA-q339-8rmv-2mhv>
* Original PoC — <https://github.com/mpgn/Rails-doubletap-RCE>
* Zero Day Initiative write-up —
  <https://www.zerodayinitiative.com/blog/2019/6/20/remote-code-execution-via-ruby-on-rails-active-storage-insecure-deserialization>

## License

MIT — see [LICENSE](LICENSE).
