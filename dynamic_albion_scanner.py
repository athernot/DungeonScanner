#!/usr/bin/env python3
"""
Dynamic Albion Port Scanner
Mendeteksi port dinamis yang digunakan Albion dan test semua interface
"""

import sys
import time
import socket
import psutil
import threading
from scapy.all import *
from scapy.layers.inet import IP, UDP
from collections import defaultdict

class DynamicAlbionScanner:
    def __init__(self):
        self.albion_ports = set()
        self.server_ips = set()
        self.captured_packets = []
        self.active_capture = False
        
    def get_albion_network_info(self):
        """Extract network info from running Albion processes"""
        print("=== ANALYZING ALBION PROCESS NETWORK CONNECTIONS ===")
        
        albion_processes = []
        all_connections = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                if proc.info['name'] and any(keyword in proc.info['name'].lower() 
                                           for keyword in ['albion', 'unity']):
                    albion_processes.append(proc)
                    print(f"🎮 Process: {proc.info['name']} (PID: {proc.info['pid']})")
                    
                    try:
                        connections = proc.net_connections()
                        for conn in connections:
                            if conn.type == socket.SOCK_DGRAM:  # UDP only
                                all_connections.append(conn)
                                
                                # Extract local ports
                                if conn.laddr:
                                    self.albion_ports.add(conn.laddr.port)
                                    print(f"  🔌 Local UDP: {conn.laddr.ip}:{conn.laddr.port}")
                                
                                # Extract remote servers
                                if conn.raddr:
                                    self.server_ips.add(conn.raddr.ip)
                                    self.albion_ports.add(conn.raddr.port)
                                    print(f"  🌐 Remote UDP: {conn.raddr.ip}:{conn.raddr.port}")
                                    
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        print("  ⚠️  Need admin privileges for connection details")
                        
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        print(f"\n📊 Discovered Albion Network Info:")
        print(f"   Ports: {sorted(self.albion_ports)}")
        print(f"   Server IPs: {sorted(self.server_ips)}")
        
        return len(all_connections) > 0
    
    def create_dynamic_filter(self):
        """Create BPF filter based on discovered ports and IPs"""
        filters = []
        
        # Add port-based filters
        if self.albion_ports:
            port_filters = [f"udp port {port}" for port in self.albion_ports]
            filters.extend(port_filters)
        
        # Add IP-based filters  
        if self.server_ips:
            ip_filters = [f"host {ip}" for ip in self.server_ips]
            filters.extend(ip_filters)
        
        # Fallback to common Photon ports
        fallback_ports = [5055, 5056, 5057, 5058, 7777, 27015]
        fallback_filters = [f"udp port {port}" for port in fallback_ports]
        filters.extend(fallback_filters)
        
        # Combine with OR
        if filters:
            return " or ".join(f"({f})" for f in filters)
        else:
            return "udp"  # Capture all UDP as last resort
    
    def packet_handler_factory(self, interface_name):
        """Create packet handler for specific interface"""
        def packet_handler(packet):
            if packet.haslayer(UDP) and packet.haslayer(IP):
                udp = packet[UDP]
                ip = packet[IP]
                
                timestamp = time.strftime("%H:%M:%S.%f")[:-3]
                
                # Check if this looks like Albion traffic
                is_albion = False
                
                # Check by port
                if (udp.sport in self.albion_ports or udp.dport in self.albion_ports):
                    is_albion = True
                    reason = f"Known Port {udp.sport}/{udp.dport}"
                
                # Check by IP
                elif (ip.src in self.server_ips or ip.dst in self.server_ips):
                    is_albion = True
                    reason = f"Known Server IP {ip.src}/{ip.dst}"
                
                # Check by payload characteristics (Photon packets usually start with specific bytes)
                elif len(udp.payload) > 0:
                    payload = bytes(udp.payload)
                    # Photon packets often start with 0xF3 or other specific markers
                    if len(payload) > 2 and payload[0] in [0xF3, 0xF0, 0xF1, 0xF2]:
                        is_albion = True
                        reason = f"Photon-like payload (0x{payload[0]:02x})"
                
                if is_albion:
                    direction = "→" if ip.dst in self.server_ips or udp.dport in self.albion_ports else "←"
                    
                    print(f"[{timestamp}] 🎯 {interface_name}")
                    print(f"  {direction} {ip.src}:{udp.sport} → {ip.dst}:{udp.dport}")
                    print(f"  Size: {len(packet)} bytes, Payload: {len(udp.payload)} bytes")
                    print(f"  Reason: {reason}")
                    
                    # Show payload preview
                    if len(udp.payload) > 0:
                        payload_preview = bytes(udp.payload)[:16]
                        hex_preview = ' '.join(f'{b:02x}' for b in payload_preview)
                        print(f"  Hex: {hex_preview}...")
                    
                    print("-" * 50)
                    
                    self.captured_packets.append({
                        'interface': interface_name,
                        'packet': packet,
                        'timestamp': time.time(),
                        'reason': reason
                    })
                    
                    return True
                
        return packet_handler
    
    def test_interface_comprehensive(self, interface_index, interface_name, duration=20):
        """Test single interface with comprehensive filtering"""
        print(f"\n🔍 Testing Interface {interface_index}: {interface_name}")
        
        # Create dynamic filter
        bpf_filter = self.create_dynamic_filter()
        print(f"📡 Filter: {bpf_filter[:100]}...")
        
        packet_handler = self.packet_handler_factory(f"Interface-{interface_index}")
        
        try:
            print(f"⏱️  Capturing for {duration} seconds...")
            print("🚨 DO ACTIVE GAMEPLAY NOW! (move, attack, open chests, etc.)")
            print()
            
            start_time = time.time()
            packets = sniff(
                iface=interface_name,
                filter=bpf_filter,
                prn=packet_handler,
                timeout=duration,
                store=1
            )
            
            # Count Albion-relevant packets
            albion_count = len([p for p in self.captured_packets 
                             if p['interface'] == f"Interface-{interface_index}"
                             and p['timestamp'] > start_time])
            
            print(f"\n📊 Interface {interface_index} Results:")
            print(f"   Total packets: {len(packets)}")
            print(f"   Albion packets: {albion_count}")
            
            if albion_count > 0:
                print("✅ SUCCESS: Albion traffic detected!")
                return True
            else:
                print("❌ No Albion traffic detected")
                return False
                
        except Exception as e:
            print(f"❌ Error on interface {interface_index}: {e}")
            return False
    
    def run_comprehensive_scan(self):
        """Run comprehensive scan of all interfaces"""
        print("🚀 DYNAMIC ALBION ONLINE SCANNER")
        print("=" * 60)
        
        # Step 1: Get network info from Albion processes
        if not self.get_albion_network_info():
            print("⚠️  No Albion network connections found, using fallback detection")
        
        print("\n" + "=" * 60)
        
        # Step 2: Test all interfaces
        print("=== TESTING ALL INTERFACES ===")
        
        interfaces = get_if_list()
        successful_interfaces = []
        
        for i, interface in enumerate(interfaces):
            if i >= 8:  # Limit to first 8 interfaces to avoid too much testing
                break
                
            try:
                success = self.test_interface_comprehensive(i, interface, duration=15)
                if success:
                    successful_interfaces.append((i, interface))
            except KeyboardInterrupt:
                print("\n⏹️  Scan interrupted by user")
                break
            except Exception as e:
                print(f"❌ Failed to test interface {i}: {e}")
        
        # Step 3: Results
        print("\n" + "=" * 60)
        print("=== FINAL RESULTS ===")
        
        if successful_interfaces:
            print("✅ SUCCESS! Albion Online packets detected on:")
            for i, interface in successful_interfaces:
                print(f"  🎯 Interface {i}: {interface}")
            
            # Generate working code
            best_interface = successful_interfaces[0][1]
            print(f"\n🔧 WORKING CONFIGURATION FOUND:")
            print(f"   Interface: '{best_interface}'")
            print(f"   Detected ports: {sorted(self.albion_ports)}")
            print(f"   Server IPs: {sorted(self.server_ips)}")
            
            self.generate_working_scanner(best_interface)
            
        else:
            print("❌ NO ALBION TRAFFIC DETECTED ON ANY INTERFACE!")
            print("\n🔧 ADVANCED TROUBLESHOOTING:")
            print("1. Try running with different timing (Albion might not send packets constantly)")
            print("2. Check if Albion is actually connected to server (not just main menu)")
            print("3. Try disabling all firewalls temporarily") 
            print("4. Check if using VPN that redirects traffic")
            print("5. Try running Wireshark manually to see ANY traffic")
            
        print(f"\n📊 Total packets captured: {len(self.captured_packets)}")
        
    def generate_working_scanner(self, working_interface):
        """Generate a working scanner configuration"""
        print("\n" + "=" * 60)
        print("=== GENERATING WORKING SCANNER ===")
        
        config = {
            'interface': working_interface,
            'ports': list(self.albion_ports),
            'server_ips': list(self.server_ips),
            'filter': self.create_dynamic_filter()
        }
        
        print("✅ Working configuration created!")
        print("This can now be used for the next phase: Photon Protocol parsing")
        
        return config

def main():
    print("Dynamic Albion Online Network Scanner")
    print("Requirements: pip install scapy psutil")
    print("Run as Administrator for best results\n")
    
    scanner = DynamicAlbionScanner()
    scanner.run_comprehensive_scan()

if __name__ == "__main__":
    main()