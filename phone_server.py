import http.server
import socketserver
import socket
import os
import sys

PORT = 8888

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=BASE_DIR, **kwargs)

    def do_GET(self):
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-type", "text/html; charset=utf-8")
            self.end_headers()
            
            html = f"""<!DOCTYPE html>
<html lang="az">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>DNS Shield Mobile Yüklə</title>
    <style>
        body {{
            background-color: #0B0F19;
            color: #F9FAFB;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            text-align: center;
            padding: 30px 20px;
            margin: 0;
        }}
        .card {{
            background: #111827;
            border: 1px solid #10B981;
            border-radius: 20px;
            padding: 30px 20px;
            max-width: 420px;
            margin: 0 auto;
            box-shadow: 0 10px 30px rgba(16, 185, 129, 0.15);
        }}
        h1 {{
            color: #10B981;
            font-size: 24px;
            margin-bottom: 5px;
        }}
        p {{
            color: #9CA3AF;
            font-size: 14px;
            line-height: 1.6;
        }}
        .badge {{
            display: inline-block;
            background: #162B28;
            color: #10B981;
            padding: 6px 14px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            margin-bottom: 20px;
        }}
        .btn {{
            display: block;
            background: #10B981;
            color: #0B0F19;
            text-decoration: none;
            padding: 16px;
            border-radius: 14px;
            font-weight: bold;
            font-size: 17px;
            margin-top: 25px;
            box-shadow: 0 4px 15px rgba(16, 185, 129, 0.4);
            transition: transform 0.2s;
        }}
        .btn:active {{
            transform: scale(0.98);
        }}
        .steps {{
            text-align: left;
            background: #1F2937;
            border-radius: 12px;
            padding: 15px;
            margin-top: 25px;
            font-size: 13px;
        }}
        .steps li {{
            margin-bottom: 8px;
            color: #D1D5DB;
        }}
    </style>
</head>
<body>
    <div class="card">
        <div class="badge">✓ RƏSMİ TELEFON VERSİYASI</div>
        <h1>🛡️ DNS Shield Mobile</h1>
        <p>Telefonunuzda DNS çöküşlərini və internet donmalarını avtomatik aradan qaldıran mobil sentinel.</p>
        
        <a href="/DNS_Shield_Mobile.apk" download class="btn">📥 APK YÜKLƏ (6.5 MB)</a>
        
        <div class="steps">
            <strong style="color:#06B6D4">Quraşdırma (3 addımda):</strong>
            <ol>
                <li>Yuxarıdakı yaşıl <b>APK YÜKLƏ</b> düyməsinə basın.</li>
                <li>Yüklənən fayla toxunub <b>Yüklə (Install)</b> deyin.</li>
                <li>Tətbiqi açın — qoruma <b>avtomatik</b> başlayacaq!</li>
            </ol>
        </div>
    </div>
</body>
</html>"""
            self.wfile.write(html.encode('utf-8'))
            return
            
        return super().do_GET()

def start_server():
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        except Exception:
            pass
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    local_ip = get_local_ip()
    url = f"http://{local_ip}:{PORT}"
    
    print("\n" + "=" * 60)
    print("  [SHIELD] DNS SHIELD MOBILE - TELEFON DOWNLOAD SERVER")
    print("=" * 60)
    print(f"\n[+] Telefonunuzun brauzerinde bu linki acin:\n")
    print(f"      >>>  {url}  <<<\n")
    print("=" * 60)
    print("[*] Server aktivdir. Telefonda linki acib birbasa yukleyin.")
    print("[*] Dayandirmaq ucun Ctrl+C basin.\n")
    
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), CustomHandler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[*] Server dayandirildi.")

if __name__ == "__main__":
    start_server()
