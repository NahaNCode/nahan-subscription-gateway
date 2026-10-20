#!/usr/bin/env python3
"""Fail-closed Docker installer. No dependency installation or DNS access."""
import argparse
import contextlib
import datetime
import fcntl
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import urllib.request

UID = 65532
FILES = ("compose.yaml", "compose.proxy.yaml")


def run(args, capture=False):
    result = subprocess.run(args, check=False, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, text=True, timeout=240)
    if result.returncode:
        raise ValueError("command failed: " + " ".join(args[:2]))
    return result.stdout if capture else ""


def atomic(path, data, mode=0o600):
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".install-")
    try:
        with os.fdopen(fd, "wb") as out:
            os.fchmod(out.fileno(), mode)
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def fetch(url):
    # No environment proxies, redirects, credentials or insecure TLS.
    parsed = urllib.request.urlparse(url) if False else None
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError("release URL must be an HTTPS URL without credentials/query/fragment")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            # GitHub release downloads redirect to an asset CDN. Only a fixed
            # HTTPS GitHub asset domain is allowed; no arbitrary redirect hosts.
            target = urlparse(newurl)
            if target.scheme != "https" or target.hostname != "release-assets.githubusercontent.com" or target.username:
                raise ValueError("release redirect rejected")
            return super().redirect_request(req, fp, code, msg, headers, newurl)

    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(url, timeout=30) as response:
        body = response.read((1 << 20) + 1)
        if len(body) > 1 << 20:
            raise ValueError("release file too large")
        return body


def bundle(args):
    if args.bundle_dir:
        directory = Path(args.bundle_dir).resolve(strict=True)
        manifest_bytes = (directory / "manifest.json").read_bytes()
        get = lambda name: (directory / name).read_bytes()
    else:
        if not args.release_url or not re.fullmatch(r"[0-9a-f]{64}", args.manifest_sha256 or ""):
            raise ValueError("use --bundle-dir or --release-url and --manifest-sha256")
        from urllib.parse import urlparse
        parsed = urlparse(args.release_url)
        if parsed.hostname != "github.com" or not re.fullmatch(r"/[^/]+/[^/]+/releases/download/[^/]+", parsed.path):
            raise ValueError("release URL must identify a versioned public GitHub release")
        manifest_bytes = fetch(args.release_url + "/manifest.json")
        get = lambda name: fetch(args.release_url + "/" + name)
    if args.manifest_sha256 and hashlib.sha256(manifest_bytes).hexdigest() != args.manifest_sha256:
        raise ValueError("manifest pin mismatch")
    manifest = json.loads(manifest_bytes)
    if manifest.get("schemaVersion") != 1 or not re.fullmatch(r"[a-zA-Z0-9./_-]+@sha256:[0-9a-f]{64}", manifest.get("image", "")):
        raise ValueError("manifest requires schemaVersion 1 and digest-pinned image")
    files = {}
    for name in FILES:
        data = get(name)
        if hashlib.sha256(data).hexdigest() != manifest.get("files", {}).get(name):
            raise ValueError("bundle file hash mismatch")
        files[name] = data
    return manifest, files


def compose(root, *args):
    return run(["docker", "compose", "--project-name", "nahan-edge", "--env-file", str(root / ".env"),
                "-f", str(root / "compose.yaml"), *args], capture=True)


def docker_cert_sync(root, settings):
    cmd = ["docker", "run", "--rm", "--read-only", "--user", "65532:65532", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges:true", "--pids-limit", "64", "--memory", "256m", "--cpus", "1",
           "--log-driver", "none", "--mount", f"type=bind,src={root / 'config'},dst=/etc/nahan,readonly",
           "--mount", f"type=bind,src={root / 'state'},dst=/state"]
    if settings["behindProxy"]:
        cmd += ["--network", settings["proxyNetwork"]]
    run(cmd + [settings["image"], "-command", "cert-sync"])


def proxy_preflight(settings):
    proxy = json.loads(run(["docker", "inspect", settings["proxyContainer"]], capture=True))[0]
    if not proxy["State"]["Running"]:
        raise ValueError("proxy is not running")
    if settings["proxyNetwork"] not in proxy["NetworkSettings"]["Networks"]:
        raise ValueError("proxy is not on the requested network")
    directory = str(Path(settings["proxyCertDir"]).resolve(strict=True))
    if not any(m["Type"] in ("bind", "volume") and m["Destination"] == "/etc/nginx/certs" and
               str(Path(m["Source"]).resolve()) == directory for m in proxy["Mounts"]):
        raise ValueError("explicit cert directory does not match proxy /etc/nginx/certs bind mount")
    vhosts = [m["Source"] for m in proxy["Mounts"] if m["Destination"] == "/etc/nginx/vhost.d" and m["Type"] in ("bind", "volume")]
    if len(vhosts) != 1:
        raise ValueError("proxy requires a persistent per-host configuration directory")
    settings["proxyVhostDir"] = str(Path(vhosts[0]).resolve(strict=True))
    run(["docker", "exec", settings["proxyContainer"], "nginx", "-t"])


def export_proxy(root, settings):
    proxy_preflight(settings)
    directory = Path(settings["proxyCertDir"]).resolve(strict=True)
    source = root / "state" / "server.pem"
    # OpenSSL parses the managed source; never place secrets on the command line.
    cert = run(["openssl", "crl2pkcs7", "-nocrl", "-certfile", str(source)], capture=True)
    # Preserve the full certificate chain, not just the first leaf.
    full_chain = run(["openssl", "pkcs7", "-print_certs"], capture=True) if False else None
    pem = source.read_text()
    chain = re.findall(r"-----BEGIN CERTIFICATE-----\s.*?-----END CERTIFICATE-----", pem, re.S)
    if not chain or not cert:
        raise ValueError("managed certificate missing")
    key = run(["openssl", "pkey", "-in", str(source)], capture=True).encode()
    targets = [(directory / (settings["hostname"] + ".crt"), ("\n".join(chain) + "\n").encode(), 0o644),
               (directory / (settings["hostname"] + ".key"), key, 0o600)]
    previous = []
    for path, _, _ in targets:
        if path.is_symlink():
            raise ValueError("proxy certificate targets must not be symlinks")
        previous.append(path.read_bytes() if path.exists() else None)
    privacy = Path(settings["proxyVhostDir"]) / settings["hostname"]
    private_config = b"# Managed by NahaN subscription gateway\naccess_log off;\nerror_log /dev/null crit;\n"
    if privacy.is_symlink() or privacy.exists() and privacy.read_bytes() != private_config:
        raise ValueError("existing domain proxy configuration is not gateway-owned")
    old_privacy = privacy.read_bytes() if privacy.exists() else None
    # Host installer lock serializes exports; nginx only reads the pair on reload.
    try:
        for path, data, mode in targets:
            atomic(path, data, mode)
        atomic(privacy, private_config, 0o644)
        run(["docker", "exec", settings["proxyContainer"], "nginx", "-t"])
        run(["docker", "exec", settings["proxyContainer"], "nginx", "-s", "reload"])
    except Exception:
        if old_privacy is None:
            privacy.unlink(missing_ok=True)
        else:
            atomic(privacy, old_privacy, 0o644)
        for (path, _, mode), data in zip(targets, previous):
            if data is None:
                path.unlink(missing_ok=True)
            else:
                atomic(path, data, mode)
        raise


def install_timer(root):
    if not shutil.which("systemctl"):
        raise ValueError("systemd required for --install-timer")
    # Paths are restricted before constructing a unit. Secrets stay in files.
    units = Path("/etc/systemd/system")
    atomic(units / "nahan-edge-renew.service", (
        "[Unit]\nDescription=NahaN edge certificate renewal\nAfter=docker.service\n"
        "[Service]\nType=oneshot\nUMask=0077\nExecStart=/usr/bin/python3 " + str(root / "install.py") +
        " --renew --install-dir " + str(root) + "\n").encode(), 0o644)
    atomic(units / "nahan-edge-renew.timer", b"[Unit]\nDescription=NahaN edge renewal timer\n[Timer]\nOnBootSec=2min\nOnUnitActiveSec=5min\nRandomizedDelaySec=30\n[Install]\nWantedBy=timers.target\n", 0o644)
    run(["systemctl", "daemon-reload"])
    run(["systemctl", "enable", "--now", "nahan-edge-renew.timer"])


def backup(root):
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    dest = root / "backups" / stamp
    dest.mkdir(parents=True, mode=0o700)
    for name in ("config", "state", "compose.yaml", ".env", "identity.json", "install.py"):
        path = root / name
        if path.is_dir():
            shutil.copytree(path, dest / name)
        elif path.exists():
            shutil.copy2(path, dest / name)
    for stale in sorted((root / "backups").iterdir())[:-3]:
        if stale.is_dir() and not stale.is_symlink() and re.fullmatch(r"[0-9]{8}T[0-9]{12}Z", stale.name):
            shutil.rmtree(stale)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--bundle-dir")
    p.add_argument("--release-url")
    p.add_argument("--manifest-sha256")
    p.add_argument("--install-dir", required=True)
    p.add_argument("--config-file")
    p.add_argument("--enrollment-file")
    p.add_argument("--ca-file")
    p.add_argument("--edge-key-file")
    p.add_argument("--client-cert-file")
    p.add_argument("--client-key-file")
    p.add_argument("--bind-ip")
    p.add_argument("--behind-proxy", action="store_true")
    p.add_argument("--proxy-network", default="nginx-proxy")
    p.add_argument("--proxy-container")
    p.add_argument("--proxy-cert-dir")
    p.add_argument("--proxy-owner-consent", action="store_true")
    p.add_argument("--install-timer", action="store_true")
    p.add_argument("--renew", action="store_true")
    args = p.parse_args()
    enrollment_temp = None
    if args.enrollment_file:
        source = Path(args.enrollment_file)
        if source.is_symlink() or source.stat().st_mode & 0o077:
            raise ValueError("enrollment file must be protected with chmod 600")
        if source.stat().st_size > 131072:
            raise ValueError("enrollment too large")
        enrollment = json.loads(source.read_text())
        enrollment_temp = tempfile.TemporaryDirectory(prefix="nahan-enrollment-")
        temporary = Path(enrollment_temp.name)
        for name, data in (("config", json.dumps(enrollment["config"])), ("ca", enrollment["caPem"]), ("key", enrollment["key"])):
            atomic(temporary / name, data.encode())
        args.config_file, args.ca_file, args.edge_key_file = (str(temporary / name) for name in ("config", "ca", "key"))
    if os.geteuid() != 0:
        raise ValueError("run as root to prepare nonroot Docker mounts and protected backups")
    for command in ("docker", "openssl"):
        if not shutil.which(command):
            raise ValueError(command + " required; installer never installs dependencies")
    run(["docker", "info"])
    run(["docker", "compose", "version"])
    root = Path(args.install_dir).absolute()
    if not re.fullmatch(r"/[a-zA-Z0-9/_-]+", str(root)) or root == Path("/") or root.is_symlink():
        raise ValueError("install directory must be a plain absolute path without spaces or symlinks")
    if root.resolve() != root:
        raise ValueError("install path parents must not be symlinks")
    root.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(root, 0o700)
    with (root / ".lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        identity_file = root / "identity.json"
        old = json.loads(identity_file.read_text()) if identity_file.exists() else None
        if args.renew:
            if not old:
                raise ValueError("no installed identity")
            docker_cert_sync(root, old)
            if old["behindProxy"]:
                export_proxy(root, old)
            print("Certificate synchronized; proxy reloaded if configured.")
            return
        if not args.config_file or not args.ca_file:
            raise ValueError("--config-file and --ca-file required")
        config = json.loads(Path(args.config_file).read_text())
        host = config.get("hostname", "")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", host):
            raise ValueError("invalid hostname")
        if config.get("certificateSync") is not True:
            raise ValueError("installer requires managed certificateSync")
        settings = dict(hostname=host, behindProxy=args.behind_proxy, bindIP=args.bind_ip,
                        proxyNetwork=args.proxy_network if args.behind_proxy else None,
                        proxyContainer=args.proxy_container if args.behind_proxy else None,
                        proxyCertDir=str(Path(args.proxy_cert_dir).resolve()) if args.proxy_cert_dir else None)
        if args.behind_proxy:
            if args.bind_ip or not args.proxy_owner_consent or not args.proxy_container or not args.proxy_cert_dir:
                raise ValueError("proxy mode needs explicit owner consent, container, cert directory; no --bind-ip")
            if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]*", args.proxy_network):
                raise ValueError("invalid proxy network")
            proxy_preflight(settings)
        else:
            if not args.bind_ip or ipaddress.ip_address(args.bind_ip).is_unspecified:
                raise ValueError("--bind-ip must be a specific local IPv4 or IPv6 address")
        if old and any(settings[k] != old.get(k) for k in settings):
            raise ValueError("existing install has a different identity; refusing changes")
        if not old and any((root / name).exists() for name in ("config", "state", "compose.yaml", ".env")):
            raise ValueError("unmanaged installation files exist; refusing overwrite")
        # Never stop an owner of port 443. For an existing identity only the
        # exact managed compose container may already own the requested binding.
        if not args.behind_proxy:
            owned = False
            if old:
                ids = compose(root, "ps", "-q", "gateway").split()
                if ids:
                    container = json.loads(run(["docker", "inspect", ids[0]], capture=True))[0]
                    bindings = container["NetworkSettings"]["Ports"].get("8443/tcp") or []
                    owned = container["State"]["Running"] and any(x["HostIp"] == args.bind_ip and x["HostPort"] == "443" for x in bindings)
            if not owned:
                with socket.socket(socket.AF_INET6 if ":" in args.bind_ip else socket.AF_INET) as sock:
                    sock.bind((args.bind_ip, 443))
        manifest, files = bundle(args)
        settings["image"] = manifest["image"]
        if old:
            backup(root)
        cfg_dir, state = root / "config", root / "state"
        cfg_dir.mkdir(mode=0o700, exist_ok=True)
        state.mkdir(mode=0o700, exist_ok=True)
        os.chown(cfg_dir, UID, UID)
        os.chown(state, UID, UID)
        config.update(listen=":8080" if args.behind_proxy else ":8443", behindProxy=args.behind_proxy,
                      caFile="/etc/nahan/ca.pem", edgeKeyFile="/etc/nahan/edge-key",
                      certFile="/state/server.pem", keyFile="/state/server.pem")
        inputs = {"ca.pem": Path(args.ca_file).read_bytes()}
        if bool(args.client_cert_file) != bool(args.client_key_file):
            raise ValueError("both mTLS file arguments required")
        if args.client_cert_file:
            config.update(clientCertFile="/etc/nahan/client.pem", clientKeyFile="/etc/nahan/client-key.pem")
            inputs.update({"client.pem": Path(args.client_cert_file).read_bytes(), "client-key.pem": Path(args.client_key_file).read_bytes()})
        elif config.get("clientCertFile") or config.get("clientKeyFile"):
            raise ValueError("supply explicit mTLS source files")
        inputs["edge-key"] = Path(args.edge_key_file).read_bytes() if args.edge_key_file else getpass.getpass("Edge key: ").encode()
        inputs["config.json"] = (json.dumps(config, indent=2) + "\n").encode()
        for name, data in inputs.items():
            atomic(cfg_dir / name, data)
            os.chown(cfg_dir / name, UID, UID)
        atomic(root / "compose.yaml", files["compose.proxy.yaml" if args.behind_proxy else "compose.yaml"])
        bind = "[" + args.bind_ip + "]" if args.bind_ip and ":" in args.bind_ip else args.bind_ip
        env = f"GATEWAY_IMAGE={settings['image']}\nGATEWAY_HOSTNAME={host}\n"
        env += f"PROXY_NETWORK={args.proxy_network}\n" if args.behind_proxy else f"BIND_IP={bind}\n"
        atomic(root / ".env", env.encode())
        atomic(root / "install.py", Path(__file__).read_bytes())
        compose(root, "config", "--quiet")
        run(["docker", "pull", settings["image"]])
        docker_cert_sync(root, settings)
        if args.behind_proxy:
            export_proxy(root, settings)
        atomic(identity_file, (json.dumps(settings, indent=2) + "\n").encode())
        compose(root, "up", "-d", "--wait", "--wait-timeout", "30")
        if args.install_timer:
            install_timer(root)
        print("Gateway installed. Protected backups remain in the install directory.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, json.JSONDecodeError):
        # Third-party errors can contain private URLs or response contents.
        print("Installation/renewal failed closed; inspect inputs and Docker locally. No existing listener was stopped.", file=sys.stderr)
        sys.exit(1)
