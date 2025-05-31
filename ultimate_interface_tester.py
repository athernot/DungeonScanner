#!/usr/bin/env python3
"""
Ultimate Interface Tester
Test ALL interfaces systematically to find working packet capture
"""

import sys
import time
import subprocess
import os
from scapy.all import *
from scapy.layers.inet import IP, UDP
from collections import defaultdict

class UltimateInterfaceTester:
    def __init__(self):
        self.client_ip = "192.168.143.243"
        self.test_results = {}
        self.working_interfaces = []
        
    def get_system_network_info(self):
        """Get comprehensive system network information"""
        print("=== SYSTEM NETWORK DIAGNOSTIC ===")
        
        try:
            # Get ipconfig info
            result = subprocess.run(['ipconfig', '/all'], capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                print("🌐 Windows Network Configuration:")
                
                # Parse ipconfig output for active adapters
                lines = result.stdout.split('\n')
                current_adapter = ""
                active_adapters = []
                
                for line in lines:
                    line = line.strip()
                    if "adapter" in line.lower() and ":" in line:
                        current_adapter = line
                    elif "IPv4 Address" in line and self.client_ip in line:
                        active_adapters.append(f"✅ {current_adapter} - {line}")
                    elif "IPv4 Address" in line and "192.168." in line:
                        active_adapters.append(f"⚠️  {current_adapter} - {line}")
                
                if active_adapters:
                    print("📍 Active Network Adapters:")
                    for adapter in active_adapters:
                        print(f"   {adapter}")
                else:
                    print("❌ No active network adapters found matching client IP")
            
        except Exception as e:
            print(f"⚠️  Could not get ipconfig info: {e}")
        
        # Get route info
        try:
            result = subprocess.run(['route', 'print'], capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                print(f"\n🛣️  Default Gateway Info:")
                lines = result.stdout.split('\n')
                for line in lines:
                    if "0.0.0.0" in line and "0.0.0.0" in line:
                        print(f"   {line.strip()}")
                        
        except Exception as e:
            print(f"⚠️  Could not get route info: {e}")
    
    def test_basic_scapy_function(self):
        """Test if Scapy basic functions work"""
        print(f"\n=== TESTING SCAPY BASIC FUNCTIONS ===")
        
        try:
            # Test 1: Can we get interface list?
            interfaces = get_if_list()
            print(f"✅ Scapy can get interface list: {len(interfaces)} interfaces")
            
            # Test 2: Can we get default interface?
            default_iface = conf.iface
            print(f"✅ Default interface: {default_iface}")
            
            # Test 3: Can we create a packet?
            test_packet = IP(dst="8.8.8.8")/UDP(dport=53)/Raw(b"test")
            print(f"✅ Can create packets: {test_packet.summary()}")
            
            return True
            
        except Exception as e:
            print(f"❌ Scapy basic function test failed: {e}")
            return False
    
    def test_single_interface_comprehensive(self, interface_idx, interface_name, duration=8):
        """Comprehensive test of single interface"""
        print(f"\n📡 TESTING INTERFACE {interface_idx}: {interface_name[:60]}...")
        
        test_result = {
            'interface': interface_name,
            'tests': {},
            'working': False,
            'packets_captured': 0,
            'errors': []
        }
        
        # Test 1: Basic packet capture (any traffic)
        try:
            print(f"   Test 1: Basic capture (any traffic)...")
            packet_count = 0
            
            def counter(pkt):
                nonlocal packet_count
                packet_count += 1
                return True
            
            packets = sniff(iface=interface_name, prn=counter, timeout=3, store=0)
            test_result['tests']['basic_capture'] = packet_count
            print(f"   ✅ Basic capture: {packet_count} packets")
            
        except Exception as e:
            test_result['errors'].append(f"Basic capture failed: {e}")
            print(f"   ❌ Basic capture failed: {e}")
        
        # Test 2: UDP traffic only
        try:
            print(f"   Test 2: UDP traffic...")
            udp_count = 0
            
            def udp_counter(pkt):
                nonlocal udp_count
                if pkt.haslayer(UDP):
                    udp_count += 1
                return True
            
            packets = sniff(iface=interface_name, filter="udp", prn=udp_counter, timeout=3, store=0)
            test_result['tests']['udp_capture'] = udp_count
            print(f"   ✅ UDP capture: {udp_count} packets")
            
        except Exception as e:
            test_result['errors'].append(f"UDP capture failed: {e}")
            print(f"   ❌ UDP capture failed: {e}")
        
        # Test 3: Client-specific traffic
        try:
            print(f"   Test 3: Client IP traffic...")
            client_count = 0
            server_ips = set()
            
            def client_counter(pkt):
                nonlocal client_count
                if pkt.haslayer(IP):
                    ip = pkt[IP]
                    if ip.src == self.client_ip or ip.dst == self.client_ip:
                        client_count += 1
                        if ip.src == self.client_ip:
                            server_ips.add(ip.dst)
                        else:
                            server_ips.add(ip.src)
                return True
            
            filter_str = f"host {self.client_ip}"
            packets = sniff(iface=interface_name, filter=filter_str, prn=client_counter, timeout=duration, store=0)
            test_result['tests']['client_traffic'] = client_count
            test_result['tests']['detected_servers'] = list(server_ips)
            print(f"   ✅ Client traffic: {client_count} packets")
            if server_ips:
                print(f"   🌐 Servers detected: {', '.join(list(server_ips)[:3])}")
            
        except Exception as e:
            test_result['errors'].append(f"Client traffic capture failed: {e}")
            print(f"   ❌ Client traffic failed: {e}")
        
        # Determine if interface is working
        total_packets = sum([test_result['tests'].get(test, 0) for test in ['basic_capture', 'udp_capture', 'client_traffic']])
        test_result['packets_captured'] = total_packets
        test_result['working'] = total_packets > 0
        
        if test_result['working']:
            print(f"   ✅ INTERFACE {interface_idx} IS WORKING! ({total_packets} total packets)")
            self.working_interfaces.append((interface_idx, interface_name, test_result))
        else:
            print(f"   ❌ Interface {interface_idx} not working")
        
        self.test_results[interface_idx] = test_result
        return test_result['working']
    
    def run_comprehensive_interface_test(self):
        """Test all interfaces comprehensively"""
        print("🔍 ULTIMATE INTERFACE TESTER")
        print("=" * 80)
        
        # Step 1: System diagnostics
        self.get_system_network_info()
        
        # Step 2: Scapy basic tests
        if not self.test_basic_scapy_function():
            print("❌ Scapy basic functions failed - cannot proceed")
            return False
        
        # Step 3: Get all interfaces
        try:
            interfaces = get_if_list()
            print(f"\n📋 Found {len(interfaces)} network interfaces")
        except Exception as e:
            print(f"❌ Cannot get interface list: {e}")
            return False
        
        # Step 4: Test each interface
        print(f"\n🧪 TESTING ALL INTERFACES WITH ACTIVE GAMEPLAY...")
        print("🚨 PERFORM VERY ACTIVE GAMEPLAY DURING TESTS!")
        print("   - Move constantly 👟")
        print("   - Attack mobs ⚔️")
        print("   - Open/close inventory 🎒")
        print()
        
        for i, interface in enumerate(interfaces):
            if i >= 10:  # Limit to first 10 interfaces
                break
            self.test_single_interface_comprehensive(i, interface, duration=8)
            time.sleep(1)  # Brief pause between tests
        
        # Step 5: Results and recommendations
        print(f"\n📊 COMPREHENSIVE TEST RESULTS")
        print("=" * 50)
        
        if self.working_interfaces:
            print(f"✅ WORKING INTERFACES FOUND: {len(self.working_interfaces)}")
            
            for idx, name, result in self.working_interfaces:
                print(f"\n🎯 Interface {idx}: WORKING")
                print(f"   Name: {name[:60]}")
                print(f"   Basic packets: {result['tests'].get('basic_capture', 0)}")
                print(f"   UDP packets: {result['tests'].get('udp_capture', 0)}")
                print(f"   Client packets: {result['tests'].get('client_traffic', 0)}")
                
                servers = result['tests'].get('detected_servers', [])
                if servers:
                    print(f"   🌐 Servers: {', '.join(servers[:3])}")
            
            # Recommend best interface
            best_interface = max(self.working_interfaces, key=lambda x: x[2]['packets_captured'])
            best_idx, best_name, best_result = best_interface
            
            print(f"\n🏆 RECOMMENDED INTERFACE:")
            print(f"   Index: {best_idx}")
            print(f"   Name: {best_name}")
            print(f"   Total packets: {best_result['packets_captured']}")
            
            # Generate working configuration
            self.generate_working_config(best_idx, best_name, best_result)
            
            return True
            
        else:
            print("❌ NO WORKING INTERFACES FOUND!")
            print("\n🔧 TROUBLESHOOTING STEPS:")
            print("1. ✅ Check if game is actually running and connected")
            print("2. ✅ Try restarting the game")
            print("3. ✅ Disable all antivirus/firewall temporarily")
            print("4. ✅ Reinstall Npcap from https://npcap.com/")
            print("5. ✅ Try running on different network (mobile hotspot)")
            print("6. ✅ Check Windows network adapter settings")
            
            # Show error summary
            all_errors = []
            for result in self.test_results.values():
                all_errors.extend(result['errors'])
            
            if all_errors:
                print(f"\n📋 Common Errors Encountered:")
                error_counts = {}
                for error in all_errors:
                    error_type = error.split(':')[0]
                    error_counts[error_type] = error_counts.get(error_type, 0) + 1
                
                for error_type, count in error_counts.items():
                    print(f"   {error_type}: {count} interfaces")
            
            return False
    
    def generate_working_config(self, interface_idx, interface_name, result):
        """Generate working configuration for dungeon scanner"""
        print(f"\n🔧 GENERATING WORKING CONFIGURATION...")
        
        servers = result['tests'].get('detected_servers', [])
        
        config = {
            'interface_index': interface_idx,
            'interface_name': interface_name,
            'client_ip': self.client_ip,
            'detected_servers': servers,
            'capture_confirmed': True,
            'recommended_filter': f"udp and host {self.client_ip}",
            'test_results': result
        }
        
        try:
            import json
            with open('working_capture_config.json', 'w') as f:
                json.dump(config, f, indent=2)
            
            print(f"💾 Configuration saved to: working_capture_config.json")
            
        except Exception as e:
            print(f"⚠️  Could not save config: {e}")
        
        print(f"\n🎯 READY FOR DUNGEON SCANNER!")
        print("Use this configuration for packet capture in the main scanner")
        
        return config

def main():
    print("Ultimate Interface Tester")
    print("Comprehensive testing to find working packet capture interface")
    print()
    
    tester = UltimateInterfaceTester()
    success = tester.run_comprehensive_interface_test()
    
    if success:
        print("\n🎉 SUCCESS! Found working packet capture interface!")
        print("Ready to proceed with Albion dungeon scanner development!")
    else:
        print("\n❌ No working interfaces found")
        print("Check troubleshooting steps above")

if __name__ == "__main__":
    main()
