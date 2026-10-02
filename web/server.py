"""
Legacy compatibility wrapper.
Redirects to backend.server.start_backend_server.
"""

from backend.server import start_backend_server, LabBackendHandler, start_backend_server as start_server

if __name__ == "__main__":
    start_backend_server()
