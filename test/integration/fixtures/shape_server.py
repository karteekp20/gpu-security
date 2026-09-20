"""Response-shape fixtures for services that cannot run on a CPU-only host.

vLLM and Triton ship GPU-bound, multi-gigabyte images. Rather than pretend to
cover them, this replays the documented shapes of their health endpoints and
the test output labels them as fixtures. The real services in this compose
stack (Ray, Jupyter, MLflow, Ollama) are what actually validate the probes.

Also provides the negative-case servers: a service that correctly enforces
authentication, and one bound to loopback so it is reachable from nowhere.

Standard library only - this runs in python:3.11-alpine.
"""

import http.server
import socket
import socketserver
import sys
import threading

# Shapes taken from each project's documented health/info endpoints. Content
# is irrelevant to ray-guard (it never reads a body) but is included so the
# fixture is a faithful stand-in rather than a bare status code.
VLLM_MODELS = (
    b'{"object":"list","data":[{"id":"meta-llama/Llama-3-8B",'
    b'"object":"model","owned_by":"vllm","root":"meta-llama/Llama-3-8B"}]}'
)
TRITON_METRICS = (
    b"# HELP nv_inference_request_success Number of successful requests\n"
    b"# TYPE nv_inference_request_success counter\n"
    b'nv_inference_request_success{model="resnet50",version="1"} 0\n'
)


def handler_for(routes, fallback=404):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            path = self.path.split("?", 1)[0]
            if path in routes:
                status, body, headers = routes[path]
            elif fallback == 401:
                status, body, headers = 401, b"", {"WWW-Authenticate": 'Bearer realm="api"'}
            else:
                status, body, headers = fallback, b"", {}
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def log_message(self, *args):
            pass

    return Handler


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def serve_http(host, port, handler):
    Server((host, port), handler).serve_forever()


def serve_tcp(host, port):
    """A port that accepts and immediately closes - Triton's gRPC listener as
    far as a reachability-only probe can tell."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(16)
    while True:
        conn, _ = s.accept()
        conn.close()


def main():
    mode = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8000
    threads = []

    if mode == "vllm":
        json_hdr = {"Content-Type": "application/json"}
        routes = {"/v1/models": (200, VLLM_MODELS, json_hdr)}
        threads.append((("0.0.0.0", 8000), handler_for(routes)))

    elif mode == "triton":
        routes_http = {"/v2/health/ready": (200, b"", {})}
        routes_metrics = {"/metrics": (200, TRITON_METRICS, {"Content-Type": "text/plain"})}
        threads.append((("0.0.0.0", 8000), handler_for(routes_http)))
        threads.append((("0.0.0.0", 8002), handler_for(routes_metrics)))
        # Triton's gRPC port: reachable, speaks no HTTP.
        threading.Thread(target=serve_tcp, args=("0.0.0.0", 8001), daemon=True).start()

    elif mode == "secured":
        # Every path demands authentication. The service-exposure rule for
        # this port MUST NOT fire against it.
        threads.append((("0.0.0.0", port), handler_for({}, fallback=401)))

    elif mode == "loopback":
        # Correctly bound: reachable from inside the container only, so a scan
        # from outside must produce nothing at all for this host.
        threads.append((("127.0.0.1", port), handler_for({"/": (200, b"ok", {})})))

    else:
        raise SystemExit(f"unknown fixture mode: {mode}")

    workers = [
        threading.Thread(target=serve_http, args=(addr[0], addr[1], h), daemon=True)
        for addr, h in threads
    ]
    for w in workers:
        w.start()
    print(f"fixture {mode} ready", flush=True)
    for w in workers:
        w.join()


if __name__ == "__main__":
    main()
