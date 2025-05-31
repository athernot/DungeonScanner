#!/usr/bin/env python3
"""
Ultimate Network Debugger
Diagnosa masalah packet capture yang sangat mendalam
"""

import sys
import time
import socket
import psutil
import subprocess
import os
from scapy.all import *
from scapy.layers.inet import IP, UDP

class UltimateNetworkDebugger:
    def __init__(self):
        self.findings = []
        
    def log_finding(self, category, message):
        """Log a finding for later reporting"""
        self.findings.append(f"{category}: {message}")
        print(f"🔍 {category}: {message}")
    
    def check_admin_privileges(self):
        """Check if running with admin privileges"""
        print("=== CHECKING ADMIN PRIVILEGES ===")
        try:
            is_admin = os.getuid() == 0  # Unix
        except AttributeError:
            # Windows
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        
        if is_admin:
            self.log_finding("ADMIN", "✅ Running with admin privileges")
        else:
            self.log_finding("ADMIN", "❌ NOT running with admin privileges - THIS IS LIKELY THE PROBLEM!")
            print("🔧 SOLUTION: Restart Command Prompt as Administrator")
            print("   Right-click Command Prompt → 'Run as Administrator'")
        
        return is_admin
    
    def check_npcap_installation(self):
        """Check Npcap installation and configuration"""
        print("\n=== CHECKING NPCAP INSTALLATION ===")
        
        try:
            # Check if npcap service is running
            services = []
            for proc in psutil.process_iter(['name']):
                if 'npcap' in proc.info['name'].lower():
                    services.append(proc.info['name'])
            
            if services:
                self.log_finding("NPCAP", f"✅ Npcap processes running: {services}")
            else:
                self.log_finding("NPCAP", "⚠️ No Npcap processes detected")
            
            # Check npcap directory
            npcap_paths = [
                r"C:\Windows\System32\Npcap",
                r"C:\Windows\SysWOW64\Npcap"
            ]
            
            for path in npcap_paths:
                if os.path.exists(path):
                    files = os.listdir(path)
                    self.log_finding("NPCAP", f"✅ Npcap found at {path}: {len(files)} files")
                    break
            else:
                self.log_finding("NPCAP", "❌ Npcap installation directory not found!")
                print("🔧 SOLUTION: Download and install Npcap from https://npcap.com/")
                
        except Exception as e:
            self.log_finding("NPCAP", f"Error checking Npcap: {e}")
    
    def test_raw_scapy_capture(self):
        """Test most basic scapy capture possible"""
        print("\n=== TESTING RAW SCAPY CAPTURE ===")
        
        try:
            print("📡 Testing basic ANY traffic capture for 5 seconds...")
            
            packet_count = 0
            def simple_counter(pkt):
                nonlocal packet_count
                packet_count += 1
                if packet_count <= 3:
                    print(f"  Packet {packet_count}: {pkt.summary()}")
            
            # Capture ANY traffic, no filter
            packets = sniff(prn=simple_counter, timeout=5, store=0)
            
            if packet_count > 0:
                self.log_finding("CAPTURE", f"✅ Basic capture works: {packet_count} packets")
            else:
                self.log_finding("CAPTURE", "❌ NO packets captured at all - major problem!")
                
        except Exception as e:
            self.log_finding("CAPTURE", f"❌ Basic capture failed: {e}")
    
    def test_interface_by_interface_any_udp(self):
        """Test each interface for ANY UDP traffic"""
        print("\n=== TESTING EACH INTERFACE FOR ANY UDP ===")
        
        interfaces = get_if_list()
        working_interfaces = []
        
        for i, iface in enumerate(interfaces[:8]):  # Test first 8
            print(f"\n📡 Testing interface {i}: {iface[:50]}...")
            
            try:
                packet_count = 0
                def udp_counter(pkt):
                    nonlocal packet_count
                    if pkt.haslayer(UDP):
                        packet_count += 1
                        if packet_count <= 2:
                            udp = pkt[UDP]
                            ip = pkt[IP] if pkt.haslayer(IP) else None
                            if ip:
                                print(f"  UDP: {ip.src}:{udp.sport} → {ip.dst}:{udp.dport}")
                
                # Capture any UDP for 3 seconds
                sniff(iface=iface, filter="udp", prn=udp_counter, timeout=3, store=0)
                
                if packet_count > 0:
                    self.log_finding("INTERFACE", f"✅ Interface {i} has UDP traffic: {packet_count} packets")
                    working_interfaces.append((i, iface))
                else:
                    self.log_finding("INTERFACE", f"❌ Interface {i} no UDP traffic")
                    
            except Exception as e:
                self.log_finding("INTERFACE", f"❌ Interface {i} error: {e}")
        
        return working_interfaces
    
    def test_windows_firewall_status(self):
        """Check Windows Firewall status"""
        print("\n=== CHECKING WINDOWS FIREWALL ===")
        
        try:
            # Check firewall status
            result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'], 
                                  capture_output=True, text=True, shell=True)
            
            if result.returncode == 0:
                output = result.stdout
                if "ON" in output:
                    self.log_finding("FIREWALL", "⚠️ Windows Firewall is ON - may block packet capture")
                    print("🔧 Try temporarily: netsh advfirewall set allprofiles state off")
                else:
                    self.log_finding("FIREWALL", "✅ Windows Firewall appears to be OFF")
            else:
                self.log_finding("FIREWALL", "Could not check firewall status")
                
        except Exception as e:
            self.log_finding("FIREWALL", f"Error checking firewall: {e}")
    
    def check_albion_server_connectivity(self):
        """Check if Albion is actually connected to servers"""
        print("\n=== CHECKING ALBION SERVER CONNECTIVITY ===")
        
        # Get all Albion connections again, but more detailed
        for proc in psutil.process_iter(['pid', 'name']):
            if 'albion' in proc.info['name'].lower():
                try:
                    connections = proc.net_connections()
                    active_connections = [c for c in connections if c.status == 'ESTABLISHED' and c.raddr]
                    
                    print(f"🎮 {proc.info['name']} (PID {proc.info['pid']}):")
                    
                    if active_connections:
                        for conn in active_connections:
                            self.log_finding("CONNECTIVITY", 
                                           f"✅ Active connection: {conn.laddr} → {conn.raddr}")
                    else:
                        self.log_finding("CONNECTIVITY", 
                                       f"⚠️ {proc.info['name']} has no active server connections!")
                        print("  🔧 Make sure you're actually in-game, not main menu")
                        
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    self.log_finding("CONNECTIVITY", f"Cannot access {proc.info['name']} connections")
    
    def test_manual_packet_creation(self):
        """Test if we can create and send packets manually"""
        print("\n=== TESTING MANUAL PACKET CREATION ===")
        
        try:
            # Create a simple UDP packet
            test_packet = IP(dst="8.8.8.8")/UDP(dport=53)/Raw(b"test")
            
            # Check if we can at least create packets
            self.log_finding("PACKET_CREATE", "✅ Can create packets with Scapy")
            
            # Try to see if we can capture our own packet
            print("📡 Testing self-capture...")
            
            def capture_own_packet(pkt):
                if pkt.haslayer(UDP) and pkt.haslayer(Raw):
                    if b"test" in bytes(pkt[Raw]):
                        print("  ✅ Captured our own test packet!")
                        return True
            
            # Start capture in background
            import threading
            capture_thread = threading.Thread(
                target=lambda: sniff(filter="udp and dst host 8.8.8.8", 
                                   prn=capture_own_packet, timeout=3, store=0)
            )
            capture_thread.start()
            
            time.sleep(0.5)
            
            # Send test packet
            send(test_packet, verbose=0)
            
            capture_thread.join()
            
        except Exception as e:
            self.log_finding("PACKET_CREATE", f"❌ Cannot create/send packets: {e}")
    
    def perform_wireshark_recommendation(self):
        """Provide Wireshark testing recommendation"""
        print("\n=== WIRESHARK VERIFICATION RECOMMENDATION ===")
        
        print("🔧 MANUAL VERIFICATION STEPS:")
        print("1. Download and install Wireshark")
        print("2. Run Wireshark as Administrator")
        print("3. Select your main network interface")
        print("4. Apply filter: udp")
        print("5. Start capture")
        print("6. Do ANY internet activity (browse web, etc.)")
        print("7. Check if ANY UDP packets appear")
        print()
        print("If NO UDP packets in Wireshark either:")
        print("  → Network capture is completely blocked on your system")
        print("  → Need to fix Npcap/WinPcap installation")
        print("  → Administrative privileges issue")
        print("  → Deep security software interference")
    
    def generate_system_report(self):
        """Generate comprehensive system report"""
        print("\n" + "=" * 60)
        print("=== COMPREHENSIVE SYSTEM REPORT ===")
        
        print("\n📋 FINDINGS SUMMARY:")
        for finding in self.findings:
            print(f"  {finding}")
        
        print(f"\n🖥️  System: {sys.platform}")
        print(f"📦 Python: {sys.version}")
        print(f"🔗 Scapy: {scapy.__version__ if hasattr(scapy, '__version__') else 'Unknown'}")
        
        # Check if this is likely the common Windows UAC issue
        admin_issues = [f for f in self.findings if "NOT running with admin" in f]
        no_packets = [f for f in self.findings if "NO packets captured" in f]
        
        if admin_issues and no_packets:
            print("\n🎯 LIKELY ROOT CAUSE: ADMIN PRIVILEGES")
            print("=" * 40)
            print("✅ SOLUTION: Run as Administrator")
            print("1. Close this program")
            print("2. Right-click Command Prompt")
            print("3. Select 'Run as Administrator'")
            print("4. Navigate back to your folder")
            print("5. Run the script again")
            print("This should solve the packet capture issue!")
        
        elif no_packets:
            print("\n🎯 LIKELY ROOT CAUSE: NPCAP/CAPTURE ISSUE")
            print("=" * 40)
            print("✅ SOLUTIONS TO TRY:")
            print("1. Reinstall Npcap from https://npcap.com/")
            print("2. Temporarily disable all antivirus/firewall")
            print("3. Try running on different network (mobile hotspot)")
            print("4. Check with Wireshark first to confirm capture works")
    
    def run_ultimate_debug(self):
        """Run all diagnostic tests"""
        print("🚨 ULTIMATE ALBION NETWORK DEBUGGER")
        print("=" * 60)
        print("This will perform comprehensive diagnosis of packet capture issues")
        print()
        
        # Run all tests
        self.check_admin_privileges()
        self.check_npcap_installation()
        self.test_raw_scapy_capture()
        working_interfaces = self.test_interface_by_interface_any_udp()
        self.test_windows_firewall_status()
        self.check_albion_server_connectivity()
        self.test_manual_packet_creation()
        self.perform_wireshark_recommendation()
        self.generate_system_report()

def main():
    debugger = UltimateNetworkDebugger()
    debugger.run_ultimate_debug()

if __name__ == "__main__":
    main()