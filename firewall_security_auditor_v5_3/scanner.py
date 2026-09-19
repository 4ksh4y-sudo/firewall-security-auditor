import socket
import time


def test_port(target, port, timeout=0.7):
    start = time.perf_counter()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((target, port))
        elapsed = (time.perf_counter() - start) * 1000
        return {
            "port": port,
            "status": "OPEN" if result == 0 else "CLOSED",
            "latency": elapsed
        }
    except socket.timeout:
        return {
            "port": port,
            "status": "TIMEOUT",
            "latency": (time.perf_counter() - start) * 1000
        }
    except OSError as exc:
        return {
            "port": port,
            "status": "ERROR",
            "latency": (time.perf_counter() - start) * 1000,
            "error": str(exc)
        }
    finally:
        sock.close()


def scan_ports(target, ports):
    return [test_port(target, port) for port in ports]
