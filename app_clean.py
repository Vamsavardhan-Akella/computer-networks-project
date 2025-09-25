"""
Network Discovery MVP - Fixed Flask Backend with Better Error Handling
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import threading
import time
import traceback
from network_scanner import NetworkScanner
from datetime import datetime, timedelta
import requests
import queue

app = Flask(__name__)
app.config['SECRET_KEY'] = 'network-discovery-mvp-2025'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global variables
discovered_devices = {}
device_history = {}
scanning = False
scanner = None
scan_thread = None
auto_scan_enabled = False
auto_scan_interval = 60
auto_scan_thread = None
next_scan_time = None
bandwidth_thread = None
bandwidth_enabled = True
snmp_community = 'public'
snmp_interval = 10
bandwidth_state = {}  # ip -> { last_in, last_out, last_ts, rate_in_bps, rate_out_bps }

@app.route('/')
def dashboard():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/devices')
def api_devices():
    """Return current discovered devices as JSON."""
    return jsonify({
        'devices': discovered_devices,
        'timestamp': time.time()
    })

@app.route('/api/history')
def api_history():
    return jsonify(device_history)

@app.route('/api/export.json')
def api_export_json():
    return jsonify({'devices': discovered_devices, 'history': device_history, 'exported_at': time.time()})

@app.route('/api/export.csv')
def api_export_csv():
    import csv
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['ip','hostname','type','status','mac','vendor','os','ports','last_seen'])
    for ip, dev in (discovered_devices or {}).items():
        ports = ';'.join([f"{p.get('proto','tcp')}/{p.get('port')}:{p.get('name') or ''}" for p in (dev.get('open_ports') or [])])
        writer.writerow([
            dev.get('ip'), dev.get('hostname'), dev.get('type'), dev.get('status'),
            dev.get('mac_address'), dev.get('vendor'), dev.get('os'), ports, dev.get('last_seen')
        ])
    output.seek(0)
    from flask import Response
    return Response(output.read(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename="devices.csv"'})

@socketio.on('speed_test')
def handle_speed_test():
    try:
        s = NetworkScanner(progress_callback=progress_callback)
        result = s.speed_test()
        emit('speed_test_result', result)
    except Exception as e:
        emit('status', {'message': f'Speed test error: {e}'})

# --- Pi-hole / Router blacklist integration (basic) ---
PIHOLE_URL = None  # e.g., 'http://pi.hole/admin/api.php'
PIHOLE_TOKEN = None  # optional auth token

@app.route('/api/blacklist', methods=['GET', 'POST', 'DELETE'])
def api_blacklist():
    """Proxy minimal blacklist ops to Pi-hole if configured. Body: { domain }"""
    if not PIHOLE_URL:
        return jsonify({'ok': False, 'message': 'Pi-hole not configured'}), 400
    try:
        if request.method == 'GET':
            r = requests.get(f"{PIHOLE_URL}?list=black&auth={PIHOLE_TOKEN or ''}", timeout=5)
            return jsonify({'ok': True, 'data': r.json()})
        data = request.get_json(silent=True) or {}
        domain = data.get('domain')
        if not domain:
            return jsonify({'ok': False, 'message': 'domain required'}), 400
        if request.method == 'POST':
            r = requests.get(f"{PIHOLE_URL}?list=black&add={domain}&auth={PIHOLE_TOKEN or ''}", timeout=5)
            return jsonify({'ok': True, 'result': r.text})
        if request.method == 'DELETE':
            r = requests.get(f"{PIHOLE_URL}?list=black&sub={domain}&auth={PIHOLE_TOKEN or ''}", timeout=5)
            return jsonify({'ok': True, 'result': r.text})
    except Exception as e:
        return jsonify({'ok': False, 'message': str(e)}), 500

@app.route('/api/blacklist/logs')
def api_blacklist_logs():
    if not PIHOLE_URL:
        return jsonify({'ok': False, 'message': 'Pi-hole not configured'}), 400
    try:
        r = requests.get(f"{PIHOLE_URL}?getAllQueries&auth={PIHOLE_TOKEN or ''}", timeout=5)
        return jsonify({'ok': True, 'data': r.json()})
    except Exception as e:
        return jsonify({'ok': False, 'message': str(e)}), 500

@socketio.on('connect')
def handle_connect():
    """Client connected to WebSocket"""
    print('Client connected')
    emit('status', {'message': 'Connected to Network Discovery MVP'})
    
@socketio.on('disconnect')
def handle_disconnect():
    """Client disconnected"""
    print('Client disconnected')

@socketio.on('start_scan')
def handle_start_scan():
    """Start network discovery scan"""
    global scanning, scan_thread
    
    print("Received start_scan request")
    
    if scanning:
        emit('status', {'message': 'Scan already in progress'})
        return
    
    # Check if previous thread is still running
    if scan_thread and scan_thread.is_alive():
        emit('status', {'message': 'Previous scan still finishing, please wait...'})
        return
    
    try:
        scanning = True
        scan_thread = threading.Thread(target=network_scan_worker)
        scan_thread.daemon = True
        scan_thread.start()
        emit('status', {'message': 'Initializing network scan...'})
        print("Scan thread started successfully")
    except Exception as e:
        scanning = False
        error_msg = f'Failed to start scan: {str(e)}'
        emit('status', {'message': error_msg})
        print(f"Error starting scan thread: {e}")
        traceback.print_exc()

@socketio.on('stop_scan')
def handle_stop_scan():
    """Stop current scan"""
    global scanning, scanner
    if scanning and scanner:
        scanner.stop_scan()  # Assuming NetworkScanner has this method
        emit('status', {'message': 'Stopping scan...'})

def progress_callback(message):
    """Callback function for scanner progress updates"""
    print(f"Progress: {message}")
    try:
        socketio.emit('status', {'message': message})
    except Exception as e:
        print(f"Error emitting progress: {e}")

def network_scan_worker():
    """Background worker for network scanning"""
    global scanning, discovered_devices, scanner
    
    print("Network scan worker started")
    
    try:
        # Send initial status
        socketio.emit('status', {'message': 'Initializing scanner...'})
        
        # Initialize scanner with progress callback
        scanner = NetworkScanner(progress_callback=progress_callback)
        print("Scanner initialized")
        
        socketio.emit('status', {'message': 'Starting network discovery...'})
        
        # Perform full network scan
        print("Calling full_scan()...")
        devices_found, network_range = scanner.full_scan()
        print(f"full_scan() returned: {len(devices_found) if devices_found else 0} devices")
        
        # Update global devices and emit to frontend
        prev_ips = set(discovered_devices.keys())
        discovered_devices = devices_found or {}
        now_ts = time.time()
        # Update device history and annotate vulnerabilities
        for ip, dev in discovered_devices.items():
            if ip not in device_history:
                device_history[ip] = {
                    'first_seen': now_ts,
                    'last_seen': now_ts,
                    'last_details': dev
                }
            else:
                device_history[ip]['last_seen'] = now_ts
                device_history[ip]['last_details'] = dev
            try:
                dev['vulnerabilities'] = NetworkScanner.detect_vulnerabilities(dev)
            except Exception:
                pass
        
        socketio.emit('devices_update', {
            'devices': discovered_devices,
            'timestamp': time.time(),
            'network_range': network_range or "Unknown"
        })

        # Emit notifications for joins/leaves
        current_ips = set(discovered_devices.keys())
        joined = sorted(list(current_ips - prev_ips))
        left = sorted(list(prev_ips - current_ips))
        if joined:
            socketio.emit('notification', {'type': 'join', 'ips': joined})
        if left:
            socketio.emit('notification', {'type': 'leave', 'ips': left})
        
        # Send completion message
        count = len(discovered_devices)
        
        if discovered_devices:
            scan_methods = set(device.get('scan_method', 'unknown') for device in discovered_devices.values())
            method_str = ', '.join(scan_methods) if scan_methods else 'unknown'
            completion_msg = f'✅ Scan complete: {count} device{"s" if count != 1 else ""} found using {method_str}'
        else:
            completion_msg = '⚠️ Scan complete: No devices found'
        
        socketio.emit('status', {'message': completion_msg})
        print(f"Scan completed: {count} devices found on {network_range}")
        
        # Print device summary
        if discovered_devices:
            print("Discovered devices:")
            for ip, device in discovered_devices.items():
                mac_info = f" [{device.get('mac_address', 'No MAC')}]" if device.get('mac_address') else ""
                device_type = device.get('type', 'Unknown')
                hostname = device.get('hostname', 'Unknown')
                print(f"  📱 {ip}: {hostname} ({device_type}){mac_info}")
        else:
            print("  No devices found. Possible reasons:")
            print("    - Network configuration blocking ping/scans")
            print("    - Firewall settings blocking responses")  
            print("    - Running on isolated network")
            print("    - Need administrator/root privileges for advanced scanning")
            print("    - NetworkScanner module may have issues")
        
    except ImportError as e:
        error_msg = f'❌ Import error: {str(e)} - Check if network_scanner module exists'
        socketio.emit('status', {'message': error_msg})
        print(f"Import error in scan worker: {e}")
        
    except AttributeError as e:
        error_msg = f'❌ Scanner method error: {str(e)} - Check NetworkScanner.full_scan() method'
        socketio.emit('status', {'message': error_msg})
        print(f"AttributeError in scan worker: {e}")
        
    except Exception as e:
        error_msg = f'❌ Scan error: {str(e)}'
        socketio.emit('status', {'message': error_msg})
        print(f"Unexpected error in scan worker: {e}")
        traceback.print_exc()
    
    finally:
        scanning = False
        scanner = None
        print("Scan worker finished")

@socketio.on('toggle_auto_scan')
def handle_toggle_auto_scan(data):
    """Enable/disable auto-scan with a given interval (seconds)."""
    global auto_scan_enabled, auto_scan_interval, auto_scan_thread, next_scan_time
    try:
        enabled = bool(data.get('enabled', False))
        interval = int(data.get('interval', 60))
        interval = max(30, min(3600, interval))

        auto_scan_interval = interval
        auto_scan_enabled = enabled

        if auto_scan_enabled:
            if not auto_scan_thread or not auto_scan_thread.is_alive():
                auto_scan_thread = threading.Thread(target=auto_scan_worker, daemon=True)
                auto_scan_thread.start()
            # schedule next scan
            next_scan_time = time.time() + auto_scan_interval
        else:
            next_scan_time = None

        emit_auto_scan_status()
    except Exception as e:
        print(f"Error toggling auto-scan: {e}")

def emit_auto_scan_status():
    """Emit current auto-scan status to all clients."""
    socketio.emit('auto_scan_status', {
        'enabled': auto_scan_enabled,
        'interval': auto_scan_interval,
        'next_scan': next_scan_time
    })

def auto_scan_worker():
    """Background worker that triggers scans at a fixed interval when enabled."""
    global auto_scan_enabled, next_scan_time
    print("Auto-scan worker started")
    while True:
        try:
            if not auto_scan_enabled:
                time.sleep(1)
                continue

            now = time.time()
            if next_scan_time is None or now >= next_scan_time:
                # only start a scan if not already scanning
                if not scanning:
                    socketio.emit('status', {'message': 'Auto-scan trigger starting...'})
                    # kick off scan
                    try:
                        # reuse the same path as manual scan
                        threading.Thread(target=network_scan_worker, daemon=True).start()
                    except Exception as e:
                        print(f"Auto-scan failed to start scan: {e}")
                # schedule next
                next_scan_time = now + auto_scan_interval
                emit_auto_scan_status()
            else:
                # periodically update countdown to clients
                emit_auto_scan_status()
                time.sleep(1)
        except Exception as e:
            print(f"Auto-scan worker error: {e}")
            time.sleep(2)

def bandwidth_poll_worker():
    """Poll devices via SNMP to estimate bandwidth in/out."""
    global bandwidth_enabled, bandwidth_state
    try:
        from pysnmp.hlapi import SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity, getCmd
    except Exception as e:
        print(f"Bandwidth monitor disabled: pysnmp not available ({e})")
        return
    print("Bandwidth monitor worker started")
    while True:
        try:
            if not bandwidth_enabled or not discovered_devices:
                time.sleep(2)
                continue
            for ip, dev in list(discovered_devices.items()):
                # Try first interface (ifIndex 1) for MVP
                in_oid = ObjectIdentity('1.3.6.1.2.1.2.2.1.10.1')  # ifInOctets.1
                out_oid = ObjectIdentity('1.3.6.1.2.1.2.2.1.16.1') # ifOutOctets.1
                try:
                    errorIndication, errorStatus, errorIndex, varBinds = next(getCmd(
                        SnmpEngine(),
                        CommunityData(snmp_community, mpModel=0),
                        UdpTransportTarget((ip, 161), timeout=1.0, retries=0),
                        ContextData(),
                        ObjectType(in_oid), ObjectType(out_oid)
                    ))
                    if errorIndication or errorStatus:
                        continue
                    vals = [int(vb[1]) for vb in varBinds]
                    now_ts = time.time()
                    prev = bandwidth_state.get(ip)
                    if prev:
                        dt = max(1e-3, now_ts - prev['last_ts'])
                        in_delta = (vals[0] - prev['last_in']) & 0xFFFFFFFF
                        out_delta = (vals[1] - prev['last_out']) & 0xFFFFFFFF
                        rate_in_bps = int((in_delta * 8) / dt)
                        rate_out_bps = int((out_delta * 8) / dt)
                        bandwidth_state[ip] = {
                            'last_in': vals[0], 'last_out': vals[1], 'last_ts': now_ts,
                            'rate_in_bps': rate_in_bps, 'rate_out_bps': rate_out_bps,
                        }
                    else:
                        bandwidth_state[ip] = {
                            'last_in': vals[0], 'last_out': vals[1], 'last_ts': now_ts,
                            'rate_in_bps': 0, 'rate_out_bps': 0,
                        }
                except Exception:
                    continue
            # emit snapshot
            try:
                socketio.emit('bandwidth_update', bandwidth_state)
            except Exception:
                pass
            time.sleep(snmp_interval)
        except Exception as e:
            print(f"Bandwidth worker error: {e}")
            time.sleep(2)

@socketio.on('get_devices')
def handle_get_devices():
    """Send current device list to client"""
    emit('devices_update', {
        'devices': discovered_devices,
        'timestamp': time.time(),
        'network_range': 'Current'
    })

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """HTTP-triggered scan supporting multi-subnet. Body: { "targets": ["10.0.0.0/24", ...] }"""
    global scanning, scan_thread
    if scanning:
        return jsonify({'ok': False, 'message': 'Scan already in progress'}), 409
    data = request.get_json(silent=True) or {}
    targets = data.get('targets')
    def run():
        global scanner, discovered_devices
        try:
            socketio.emit('status', {'message': 'Starting custom scan...'})
            scanner = NetworkScanner(progress_callback=progress_callback)
            devices_found, _ = scanner.full_scan(network_range=targets)
            discovered_devices = devices_found or {}
            socketio.emit('devices_update', {
                'devices': discovered_devices,
                'timestamp': time.time(),
                'network_range': targets or 'Custom'
            })
            socketio.emit('status', {'message': f'Scan complete: {len(discovered_devices)} devices found'})
        finally:
            pass
    scanning = True
    scan_thread = threading.Thread(target=run, daemon=True)
    scan_thread.start()
    return jsonify({'ok': True})

if __name__ == '__main__':
    print("🚀 Starting Network Discovery MVP with Real Scanning")
    print("📡 Dashboard will be available at: http://localhost:5000")
    
    # Check dependencies
    try:
        import nmap
        print("✅ python-nmap available - will use nmap for advanced scanning")
    except ImportError:
        print("⚠️  python-nmap not found - will use ping-based scanning only")
        print("   For better results, install with: pip install python-nmap")
        print("   Note: nmap binary also needs to be installed on your system")
    
    # Test NetworkScanner import
    try:
        from network_scanner import NetworkScanner
        print("✅ NetworkScanner module imported successfully")
        
        # Test instantiation
        test_scanner = NetworkScanner()
        print("✅ NetworkScanner instantiated successfully")
        
        # Check for required methods
        if hasattr(test_scanner, 'full_scan'):
            print("✅ full_scan method found")
        else:
            print("❌ full_scan method NOT found - this will cause errors!")
            
    except ImportError as e:
        print(f"❌ Failed to import NetworkScanner: {e}")
        print("   Make sure network_scanner.py exists in the same directory")
    except Exception as e:
        print(f"❌ Error testing NetworkScanner: {e}")
    
    print("\n📋 Network Discovery Features:")
    print("   🔍 Auto-detects your local network range")
    print("   🏠 Identifies device types (router, computer, mobile, etc.)")
    print("   📊 Real-time visualization with interactive network graph")
    print("   ⚡ Parallel scanning for faster results")
    
    print("\n🔄 Starting server...")
    try:
        # Start bandwidth thread
        try:
            bandwidth_thread = threading.Thread(target=bandwidth_poll_worker, daemon=True)
            bandwidth_thread.start()
        except Exception as e:
            print(f"Bandwidth thread failed to start: {e}")
        socketio.run(app, debug=True, host='127.0.0.1', port=5000, allow_unsafe_werkzeug=True)
    except Exception as e:
        print(f"❌ Error starting server: {e}")
        input("Press Enter to exit...")