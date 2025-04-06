import http.server
import socketserver
import os

# Set the port you want to use
PORT = 8000

# Set directory to current directory
os.chdir(os.path.dirname(os.path.abspath(__file__)))

Handler = http.server.SimpleHTTPRequestHandler
Handler.extensions_map.update({
    '.js': 'application/javascript',
    '.css': 'text/css',
    '.csv': 'text/csv',
})

print(f"Starting server at http://localhost:{PORT}")
print(f"Press Ctrl+C to stop the server")

# Start the server
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    httpd.serve_forever()
