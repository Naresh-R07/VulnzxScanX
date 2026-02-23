from flask import Flask, render_template, request, jsonify
import threading
from core.scanner import ScannerCore, SCAN_COMMANDS
import uuid

app = Flask(__name__)
scanner = ScannerCore()

# Store active scans and their results
# { "scan_id": { "target": "...", "type": "...", "output": [], "status": "running" } }
scans = {}

@app.route('/')
def index():
    return render_template('index.html', scan_types=SCAN_COMMANDS.keys())

@app.route('/start_scan', methods=['POST'])
def start_scan():
    data = request.json
    target = data.get('target')
    scan_type = data.get('type')
    rotate = data.get('rotate', False)

    if not target or not scan_type:
        return jsonify({"error": "Missing target or scan type"}), 400

    scan_id = str(uuid.uuid4())
    scans[scan_id] = {
        "target": target,
        "type": scan_type,
        "output": [],
        "status": "running"
    }

    def run_scan_thread(s_id, t, st, rot):
        if rot:
            scanner.rotate_ip()
        
        command = SCAN_COMMANDS[st](t)
        for line in scanner.run_scan(command, t):
            scans[s_id]["output"].append(line)
        
        scans[s_id]["status"] = "completed"

    thread = threading.Thread(target=run_scan_thread, args=(scan_id, target, scan_type, rotate))
    thread.daemon = True
    thread.start()

    return jsonify({"scan_id": scan_id})

@app.route('/scan_status/<scan_id>')
def scan_status(scan_id):
    if scan_id not in scans:
        return jsonify({"error": "Scan not found"}), 404
    
    return jsonify({
        "status": scans[scan_id]["status"],
        "output": scans[scan_id]["output"]
    })

@app.route('/stop_scan/<scan_id>', methods=['POST'])
def stop_scan(scan_id):
    if scan_id not in scans:
        return jsonify({"error": "Scan not found"}), 404
    
    scanner.stop_scan()
    scans[scan_id]["status"] = "stopped"
    return jsonify({"status": "stopped"})

if __name__ == '__main__':
    app.run(debug=True, port=5000)
