"""Minimal HTTPS CONNECT egress proxy with public-IP validation and IP pinning.

Only CONNECT to TCP/443 is allowed. DNS is resolved once, every answer must be
public/global, and the upstream connection is opened to one of the exact IPs
returned by that resolution rather than resolving the hostname a second time.
"""
import asyncio
import ipaddress
import socket
from urllib.parse import urlsplit

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 3128
MAX_HEADER_BYTES = 16_384
CONNECT_TIMEOUT_SECONDS = 8
DNS_TIMEOUT_SECONDS = 5


def is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
        if getattr(address, "ipv4_mapped", None) is not None:
            address = address.ipv4_mapped
        return bool(address.is_global and not address.is_multicast and not address.is_unspecified)
    except ValueError:
        return False


def parse_authority(authority: str):
    if not authority or "@" in authority or any(c in authority for c in "\r\n\t /\\"):
        raise ValueError("invalid authority")
    try:
        parsed = urlsplit("//" + authority)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        raise ValueError("invalid authority") from None
    if not host or port != 443 or parsed.username is not None or parsed.password is not None:
        raise ValueError("only host:443 CONNECT is allowed")
    host = host.rstrip(".").lower()
    if host in {"localhost", "metadata.google.internal"} or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid", ".example")):
        raise ValueError("local or reserved hostname")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        host = host.encode("idna").decode("ascii")
        return host, port, None
    if not is_public_ip(str(literal)):
        raise ValueError("non-public IP")
    return str(literal), port, literal.version


async def resolve_public(host: str, port: int):
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        loop = asyncio.get_running_loop()
        records = await asyncio.wait_for(
            loop.getaddrinfo(host, port, type=socket.SOCK_STREAM),
            timeout=DNS_TIMEOUT_SECONDS,
        )
        addresses = []
        seen = set()
        for family, socktype, proto, canonname, sockaddr in records:
            ip_value = sockaddr[0]
            if ip_value in seen:
                continue
            seen.add(ip_value)
            if not is_public_ip(ip_value):
                raise ValueError("hostname resolved to a non-public address")
            addresses.append((family, ip_value))
        if not addresses:
            raise ValueError("hostname has no usable address")
        return addresses
    else:
        if not is_public_ip(str(literal)):
            raise ValueError("non-public IP")
        family = socket.AF_INET6 if literal.version == 6 else socket.AF_INET
        return [(family, str(literal))]


async def pump(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    try:
        while True:
            data = await reader.read(65_536)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass


async def handle_client(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter):
    upstream_writer = None
    peer = client_writer.get_extra_info("peername")
    try:
        header = await asyncio.wait_for(client_reader.readuntil(b"\r\n\r\n"), timeout=5)
        if len(header) > MAX_HEADER_BYTES:
            raise ValueError("headers too large")
        first_line = header.split(b"\r\n", 1)[0].decode("ascii", errors="strict")
        parts = first_line.split()
        if len(parts) != 3 or parts[0].upper() != "CONNECT" or not parts[2].startswith("HTTP/"):
            raise ValueError("only HTTPS CONNECT is allowed")
        host, port, _ = parse_authority(parts[1])
        addresses = await resolve_public(host, port)
        last_error = None
        upstream_reader = None
        for family, pinned_ip in addresses:
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(host=pinned_ip, port=port, family=family),
                    timeout=CONNECT_TIMEOUT_SECONDS,
                )
                break
            except (OSError, asyncio.TimeoutError) as exc:
                last_error = exc
        if upstream_writer is None:
            raise ConnectionError(type(last_error).__name__ if last_error else "connect failed")

        client_writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: QRSandboxEgress/0.1\r\n\r\n")
        await client_writer.drain()
        client_to_upstream = asyncio.create_task(pump(client_reader, upstream_writer))
        upstream_to_client = asyncio.create_task(pump(upstream_reader, client_writer))
        done, pending = await asyncio.wait(
            {client_to_upstream, upstream_to_client},
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
    except (ValueError, UnicodeError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError, OSError, ConnectionError) as exc:
        if not isinstance(exc, asyncio.IncompleteReadError):
            message = str(exc)[:100]
            print(f"blocked/rejected connection from {peer}: {type(exc).__name__}: {message}")
        try:
            client_writer.write(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            await client_writer.drain()
        except Exception:
            pass
    finally:
        if upstream_writer is not None:
            upstream_writer.close()
            try:
                await upstream_writer.wait_closed()
            except Exception:
                pass
        client_writer.close()
        try:
            await client_writer.wait_closed()
        except Exception:
            pass


async def main():
    server = await asyncio.start_server(handle_client, LISTEN_HOST, LISTEN_PORT, limit=MAX_HEADER_BYTES + 1)
    print(f"QRSandbox egress proxy listening on {LISTEN_HOST}:{LISTEN_PORT}; CONNECT :443 only")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    asyncio.run(main())
