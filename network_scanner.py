"""
Network Scanner Utility Module
Separate module for network scanning functionality
"""

import socket
import subprocess
import platform
import time
from concurrent.futures import ThreadPoolExecutor
import re

try:
    import nmap
    HAS_NMAP = True
except ImportError:
    HAS_NMAP = False

class NetworkScanner:
    def __init__(self, progress_callback=None):
        self.progress_callback = progress_callback
        self._stop = False
        self._mac_vendor_cache = {}
        
    def _emit_progress(self, message):
        """Emit progress message if callback is provided"""
        if self.progress_callback:
            self.progress_callback(message)

    def stop_scan(self):
        """Signal any ongoing scan to stop gracefully."""
        self._stop = True
    
    def get_local_network_range(self):
        """Auto-detect the local network range"""
        try:
            # Method 1: Get local IP through socket connection
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            
            # Assume /24 network for simplicity
            ip_parts = local_ip.split('.')
            network_base = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            return network_base, local_ip
            
        except Exception as e:
            print(f"Error detecting network: {e}")
            # Try alternative method
            try:
                hostname = socket.gethostname()
                local_ip = socket.gethostbyname(hostname)
                ip_parts = local_ip.split('.')
                network_base = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                return network_base, local_ip
            except Exception:
                # Final fallback
                return "192.168.1.0/24", "192.168.1.100"
    
    def ping_host(self, ip, timeout=3):
        """Ping a single host to check if it's alive"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', '1', '-w', '1000', ip]
            else:
                cmd = ['ping', '-c', '1', '-W', '1', ip]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return result.returncode == 0
        except Exception:
            return False
    
    def get_hostname(self, ip):
        """Try to get hostname for an IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            # Try nslookup as backup
            try:
                if platform.system().lower() == 'windows':
                    result = subprocess.run(['nslookup', ip], capture_output=True, text=True, timeout=2)
                else:
                    result = subprocess.run(['dig', '+short', '-x', ip], capture_output=True, text=True, timeout=2)
                
                if result.returncode == 0 and result.stdout.strip():
                    hostname = result.stdout.strip().split('\n')[-1].rstrip('.')
                    if hostname and hostname != ip:
                        return hostname
            except Exception:
                pass
            return None
    
    def _lookup_mac_vendor(self, mac_address):
        """Lookup MAC vendor from OUI prefix. Lightweight local map with cache."""
        if not mac_address:
            return None
        mac_upper = mac_address.upper().replace('-', ':')
        prefix = ':'.join(mac_upper.split(':')[:3])
        if prefix in self._mac_vendor_cache:
            return self._mac_vendor_cache[prefix]
        # Minimal embedded OUI map (extend as needed)
        oui_map = {
            '00:1C:B3': 'Apple',
            'F0:99:BF': 'Apple',
            '3C:5A:B4': 'Apple',
            '00:1A:79': 'Cisco',
            '00:1B:54': 'Cisco',
            '00:0C:29': 'VMware',
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            'BC:92:6B': 'TP-Link',
            'E0:3F:49': 'Huawei',
            'F8:1A:67': 'Samsung',
            'D4:6A:6A': 'Xiaomi',
            'AC:3F:A4': 'Google',
            'B8:27:EB': 'Raspberry Pi',
        }
        vendor = oui_map.get(prefix)
        self._mac_vendor_cache[prefix] = vendor
        return vendor

    def _parse_arp_table(self):
        """Try to read ARP table to discover IP->MAC mappings without ping responses."""
        entries = {}
        try:
            if platform.system().lower() == 'windows':
                result = subprocess.run(['arp', '-a'], capture_output=True, text=True, timeout=3)
                for line in result.stdout.splitlines():
                    #   10.0.0.1           00-11-22-33-44-55     dynamic
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})", line)
                    if m:
                        ip = m.group(1)
                        mac = m.group(2).replace('-', ':').lower()
                        entries[ip] = mac
            else:
                result = subprocess.run(['ip', 'neigh', 'show'], capture_output=True, text=True, timeout=3)
                for line in result.stdout.splitlines():
                    # 10.0.0.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+).*lladdr\s+([0-9a-fA-F:]{17})", line)
                    if m:
                        entries[m.group(1)] = m.group(2).lower()
        except Exception:
            pass
        return entries

    def guess_device_type(self, ip, hostname, mac_address=None):
        """Enhanced device type detection with mobile hotspot and better pattern recognition"""
        hostname_lower = (hostname or '').lower()
        ip_parts = ip.split('.')
        last_octet = int(ip_parts[-1])

        # Extract network info for hotspot detection
        network_prefix = '.'.join(ip_parts[:3])

        # Mobile Hotspot Detection (Enhanced)
        hotspot_patterns = [
            ('192.168.43', 'android_hotspot'),
            ('192.168.137', 'windows_hotspot'),
            ('172.20.10', 'iphone_hotspot'),
            ('10.34.167', 'mobile_hotspot'),
            ('10.0.0', 'mobile_hotspot'),
            ('10.0.1', 'mobile_hotspot'),
        ]

        for pattern, hotspot_type in hotspot_patterns:
            if network_prefix == pattern:
                if last_octet > 100 and last_octet not in (1, 254):
                    if not hostname or hostname.startswith('device-') or hostname == f'device-{last_octet}':
                        return 'mobile_hotspot'
                elif last_octet in (1, 254):
                    return 'hotspot_gateway'

        # Router/Gateway Detection (Enhanced)
        gateway_ips = [1, 254, 100, 101]
        if last_octet in gateway_ips and network_prefix != '10.34.167':
            return 'router'

        # Hostname-based detection (Enhanced)
        device_patterns = {
            'router': [
                'router', 'gateway', 'modem', 'dlink', 'netgear', 'linksys',
                'tplink', 'asus', 'fritz', 'speedport', 'livebox', 'bbox'
            ],
            'mobile': [
                'iphone', 'android', 'mobile', 'samsung', 'huawei', 'xiaomi',
                'pixel', 'oneplus', 'oppo', 'vivo', 'realme', 'nokia'
            ],
            'mobile_hotspot': [
                'hotspot', 'tethering', 'androidap', 'androidhotspot',
                'myhotspot', 'mobilehotspot'
            ],
            'computer': [
                'laptop', 'desktop', 'pc', 'computer', 'macbook', 'imac',
                'windows', 'ubuntu', 'linux', 'workstation'
            ],
            'printer': [
                'printer', 'canon', 'hp', 'epson', 'brother', 'print',
                'laser', 'inkjet', 'mfc', 'dcp'
            ],
            'media': [
                'tv', 'smart', 'roku', 'chromecast', 'firestick', 'appletv',
                'shield', 'xbox', 'playstation', 'ps4', 'ps5'
            ],
            'iot': [
                'alexa', 'echo', 'nest', 'ring', 'philips', 'hue', 'smart',
                'sensor', 'camera', 'doorbell', 'thermostat'
            ],
            'nas': [
                'nas', 'synology', 'qnap', 'drobo', 'storage', 'fileserver'
            ]
        }

        for device_type, keywords in device_patterns.items():
            if any(keyword in hostname_lower for keyword in keywords):
                return device_type

        # MAC Address OUI Detection (Enhanced)
        if mac_address:
            mac_upper = mac_address.upper().replace(':', '').replace('-', '')
            oui_patterns = {
                'mobile': [
                    '001B63', '001EC2', '0023DF', '002436', '002500',
                    '08F4AB', '3C0754', '40A93F', '64200C', '8C7C92',
                    '001D25', '002556', '0025BC', '40B395',
                    'F8A45F', 'BC4760', 'DC2B2A',
                ],
                'virtual': [
                    '005056', '000C29', '001C14',
                    '080027', '0A0027',
                    '001C42',
                ],
                'router': [
                    '001346', '0013F7', '00166C', '0018E7',
                    '001D7E', '002129', '00224D', '0024A5',
                    '000FB5', '0017C4', '001E2A', '0024B2',
                ],
                'printer': [
                    '000423', '0004E6', '001120', '001279',
                    '00000B', '008087', '00A0B0', '00C0EE',
                    '000393', '008007', '00C04F',
                ]
            }

            for device_type, oui_list in oui_patterns.items():
                if any(mac_upper.startswith(oui) for oui in oui_list):
                    return device_type

        if network_prefix == '10.34.167':
            if not hostname or hostname.startswith('device-'):
                if last_octet > 100:
                    return 'mobile_hotspot'

        if hostname and hostname.startswith('device-'):
            if 100 < last_octet < 200:
                return 'mobile_hotspot'
        elif last_octet < 50:
            return 'computer'
        elif last_octet > 200:
            return 'iot'

        if hostname and any(pattern in hostname_lower for pattern in ['laptop-', 'desktop-', 'pc-']):
            return 'computer'

        return 'unknown'
    def scan_with_nmap(self, network_range):
        """Use nmap for comprehensive network scanning"""
        if not HAS_NMAP:
            return {}
        
        devices = {}
        
        try:
            nm = nmap.PortScanner()
            
            self._emit_progress(f'Running nmap scan on {network_range}...')
            
            # Combined discovery with fast ports, service detection and OS guess
            # -T4 fast timing, -F fast ports, -sV service detect, -O OS (may require admin), -Pn skip host discovery
            scan_result = nm.scan(hosts=network_range, arguments='-T4 -F -sV -O -Pn')
            
            host_count = 0
            for host in nm.all_hosts():
                if self._stop:
                    self._emit_progress('Scan stopped by user')
                    break
                if nm[host].state() == 'up':
                    host_count += 1
                    hostname = None
                    
                    # Get hostname from nmap results
                    if 'hostnames' in nm[host] and nm[host]['hostnames']:
                        hostname = nm[host]['hostnames'][0]['name']
                    
                    # Fallback hostname lookup
                    if not hostname or hostname == '':
                        hostname = self.get_hostname(host)
                    
                    # Get MAC address if available (requires root/admin)
                    mac_address = None
                    if 'addresses' in nm[host]:
                        mac_address = nm[host]['addresses'].get('mac')

                    # OS fingerprinting (best guess)
                    os_name = None
                    try:
                        if 'osmatch' in nm[host] and nm[host]['osmatch']:
                            os_name = nm[host]['osmatch'][0].get('name')
                    except Exception:
                        os_name = None

                    # Open ports and services
                    open_ports = []
                    services = []
                    try:
                        for proto in ('tcp', 'udp'):
                            if proto in nm[host]:
                                for port, pdata in nm[host][proto].items():
                                    if pdata.get('state') == 'open':
                                        open_ports.append({'port': port, 'proto': proto, 'name': pdata.get('name'), 'product': pdata.get('product')})
                                        if pdata.get('name'):
                                            services.append(pdata.get('name'))
                    except Exception:
                        pass
                    
                    device_type = self.guess_device_type(host, hostname, mac_address)
                    vendor = self._lookup_mac_vendor(mac_address)
                    
                    devices[host] = {
                        'ip': host,
                        'hostname': hostname or f'device-{host.split(".")[-1]}',
                        'status': 'up',
                        'type': device_type,
                        'mac_address': mac_address,
                        'vendor': vendor,
                        'os': os_name,
                        'open_ports': open_ports,
                        'services': sorted(list(set(services))) if services else [],
                        'last_seen': time.time(),
                        'scan_method': 'nmap'
                    }
                    
                    self._emit_progress(f'Found {host_count} devices so far...')
            
            self._emit_progress(f'nmap scan complete - found {len(devices)} devices')
            
        except Exception as e:
            print(f"nmap scan error: {e}")
            self._emit_progress(f'nmap failed: {str(e)} - falling back to ping scan')
            return {}
        
        return devices
    
    def scan_with_ping(self, network_range):
        """Fallback ping-based network scanning"""
        devices = {}
        
        # Extract base network (assuming /24)
        base_ip = network_range.split('/')[0].rsplit('.', 1)[0]
        
        self._emit_progress(f'Starting ping scan of {network_range}...')
        
        def scan_ip(ip_suffix):
            if self._stop:
                return {}
            ip = f"{base_ip}.{ip_suffix}"
            if self.ping_host(ip, timeout=2):
                hostname = self.get_hostname(ip)
                device_type = self.guess_device_type(ip, hostname)
                # try to enrich via ARP
                arp_map = arp_cache
                mac = arp_map.get(ip)
                vendor = self._lookup_mac_vendor(mac) if mac else None
                
                return {
                    ip: {
                        'ip': ip,
                        'hostname': hostname or f'device-{ip_suffix}',
                        'status': 'up',
                        'type': device_type,
                        'mac_address': mac,
                        'vendor': vendor,
                        'last_seen': time.time(),
                        'scan_method': 'ping'
                    }
                }
            return {}
        
        # Use ThreadPoolExecutor for parallel pinging
        arp_cache = self._parse_arp_table()
        with ThreadPoolExecutor(max_workers=30) as executor:
            # Scan common IP range (1-254)
            futures = [executor.submit(scan_ip, i) for i in range(1, 255)]
            
            completed = 0
            for future in futures:
                try:
                    result = future.result(timeout=5)
                    devices.update(result)
                    
                    completed += 1
                    if completed % 25 == 0:
                        self._emit_progress(f'Ping scan progress: {completed}/254 IPs checked, {len(devices)} devices found')
                        
                except Exception:
                    completed += 1
                    continue
                if self._stop:
                    self._emit_progress('Ping scan stopped by user')
                    break
        
        self._emit_progress(f'Ping scan complete - found {len(devices)} devices')
        return devices
    
    def full_scan(self, network_range=None):
        """Perform a full network scan using best available method.
        network_range: string CIDR or list of CIDRs for multi-subnet scanning.
        """
        # reset stop flag at start of a full run
        self._stop = False
        if not network_range:
            network_range, local_ip = self.get_local_network_range()
            self._emit_progress(f'Auto-detected network: {network_range}')
        targets = network_range if isinstance(network_range, list) else [network_range]
        
        devices = {}
        for target in targets:
            if self._stop:
                break
            # Try nmap first (more accurate), fallback to ping
            sub_devices = {}
            if HAS_NMAP:
                sub_devices = self.scan_with_nmap(target)
            if not sub_devices and not self._stop:
                self._emit_progress(f'Trying ping-based scanning on {target}...')
                sub_devices = self.scan_with_ping(target)
            devices.update(sub_devices)
        return devices, (targets if len(targets) > 1 else targets[0])

    @staticmethod
    def detect_vulnerabilities(device):
        """Basic checks for risky open ports."""
        vulns = []
        ports = device.get('open_ports') or []
        port_set = {p['port'] for p in ports}
        if 23 in port_set:
            vulns.append('Telnet (23) open')
        if 21 in port_set:
            vulns.append('FTP (21) open')
        if 2323 in port_set:
            vulns.append('Alternate Telnet (2323) open')
        if 3389 in port_set:
            vulns.append('RDP (3389) open')
        if 445 in port_set and 139 in port_set:
            vulns.append('SMB (139/445) open')
        return vulns

    def speed_test(self):
        """Very simple latency test to gateway candidate and to 8.8.8.8."""
        _, local_ip = self.get_local_network_range()
        base = '.'.join(local_ip.split('.')[:3])
        gateway = f"{base}.1"
        targets = {'gateway': gateway, 'internet': '8.8.8.8'}
        results = {}
        for name, ip in targets.items():
            t0 = time.time()
            ok = self.ping_host(ip, timeout=3)
            latency_ms = int((time.time() - t0) * 1000)
            results[name] = {'ip': ip, 'ok': ok, 'latency_ms': latency_ms}
        return results