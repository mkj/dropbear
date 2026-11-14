"""
Regression test for the DROPBEAR_RSA_SHA1=0 server assert.

A server built with DROPBEAR_RSA_SHA1=0 (the default) used to abort its
connection child process when a client authenticated with an RSA key using the
legacy "ssh-rsa" (SHA-1) signature algorithm: signature_type_from_name()
returned DROPBEAR_SIGNKEY_RSA (0) instead of DROPBEAR_SIGNATURE_NONE, the guard
in svr_auth_pubkey() passed, and rsa_pad_em() hit assert(0). See commit
"signkey: fix assert when DROPBEAR_RSA_SHA1=0".

asyncssh is used to force the legacy ssh-rsa signature algorithm, mimicking
clients that ignore server-sig-algs (e.g. Renci.SshNet, which triggered the
original report). The SSH "none" auth method is monkey-patched to be skipped,
matching Renci.SshNet's behavior of going straight to public-key auth, otherwise
servers with blank passwords would be authenticated before pubkey is attempted.

The crash only happens once the server accepts the public key and starts
verifying the signature, so the RSA key must be authorized on the target server.

This test is meant to be run interactively against a specific server. It is
skipped unless an authorized RSA private key is provided with --rsakey.

Against a specified server IP:

    pytest test_rsa_sha1.py --remote 192.168.1.49 --user root \\
        --rsakey ~/.ssh/id_rsa

Against a locally built server (the ./dropbear fixture), using an RSA key that
is present in the current user's ~/.ssh/authorized_keys:

    pytest test_rsa_sha1.py --hostkey fakekey --rsakey ~/.ssh/id_rsa

A fixed server answers with SSH_MSG_USERAUTH_FAILURE (PermissionDenied) when
ssh-rsa is disabled, or authenticates normally when ssh-rsa is enabled. A
vulnerable server drops the connection mid-authentication, which fails the test.
"""
from test_dropbear import *

import asyncssh
import asyncssh.connection as _conn
import asyncssh.rsa as _rsa
import asyncio

# Skip SSH "none" auth — go directly to publickey. asyncssh hardcodes "none"
# as the first auth attempt; servers with blank passwords accept it before
# pubkey is ever tried. Renci.SshNet (the client from the original report)
# doesn't send "none" either.
_orig_conn_init = _conn.SSHConnection.__init__
def _no_none_init(self, *args, **kwargs):
    _orig_conn_init(self, *args, **kwargs)
    if getattr(self, '_auth_methods', None) == [b'none']:
        self._auth_methods = [b'publickey']
_conn.SSHConnection.__init__ = _no_none_init

# Modern cryptography backends reject SHA-1 for RSA signing. The server bug
# crashes in rsa_pad_em() before verifying the signature, so the hash used
# for signing is irrelevant — fall back to SHA-256 when SHA-1 is blocked.
_orig_sign_ssh = _rsa.RSAKey.sign_ssh
def _sign_ssh_sha1_fallback(self, data, sig_algorithm):
    try:
        return _orig_sign_ssh(self, data, sig_algorithm)
    except Exception:
        return _orig_sign_ssh(self, data, b'rsa-sha2-256')
_rsa.RSAKey.sign_ssh = _sign_ssh_sha1_fallback


def connect_kwargs(addr, port, username, rsakey, sig_algs):
    kwargs = dict(
        host=addr,
        port=port,
        client_keys=[rsakey],
        agent_path=None,
        signature_algs=sig_algs,
        known_hosts=None,
    )
    if username:
        kwargs["username"] = username
    return kwargs


async def run(addr, port, username, rsakey):
    # Verify the key works with default (rsa-sha2-*) algorithms first.
    try:
        async with asyncssh.connect(
                **connect_kwargs(addr, port, username, rsakey, ())):
            pass
    except asyncssh.PermissionDenied:
        pytest.skip(f"key {rsakey} is not authorized for user "
                    f"'{username or ''}' on {addr}:{port}; cannot exercise "
                    "the ssh-rsa signature verification path")

    # Force the legacy ssh-rsa (SHA-1) signature algorithm. Also override
    # _choose_signature_alg to ignore the server's server-sig-algs extension,
    # matching Renci.SshNet which sends ssh-rsa regardless of what the server
    # advertises.
    orig = _conn.SSHClientConnection._choose_signature_alg
    def _ignore_server_sig_algs(self, keypair):
        return keypair.sig_algorithms[-1] in self._sig_algs
    _conn.SSHClientConnection._choose_signature_alg = _ignore_server_sig_algs
    try:
        async with asyncssh.connect(
                **connect_kwargs(addr, port, username, rsakey, ["ssh-rsa"])):
            pass
    except asyncssh.PermissionDenied:
        # ssh-rsa rejected cleanly (DROPBEAR_RSA_SHA1=0, fixed server).
        pass
    except (asyncssh.ConnectionLost, asyncssh.DisconnectError,
            ConnectionError) as e:
        pytest.fail("Server dropped the connection during ssh-rsa "
                    "authentication - likely the DROPBEAR_RSA_SHA1=0 "
                    f"assert crash: {e!r}")
    finally:
        _conn.SSHClientConnection._choose_signature_alg = orig


def test_rsa_sha1_no_crash(request, dropbear):
    opt = request.config.option
    if not opt.rsakey:
        pytest.skip("--rsakey with an authorized RSA private key is required")
    host = opt.remote or LOCALADDR
    port = int(opt.port)
    asyncio.run(run(host, port, opt.user, opt.rsakey))
