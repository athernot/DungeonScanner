#!/usr/bin/env python3
"""
Simple Traffic Sniffer
Simplified version yang menghindari psutil issues
"""

import sys
import time
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP
from collections import defaultdict, Counter

class SimpleTrafficSniffer:
    def __init__(self):
        # Interface yang sudah terbukti punya traffic
        self.target_interface = r"\Device\NPF_{6B3C185F-8A6A-48FA-89E8-F4E0E10196E0}"
        
        # Counters
        self.packet_count = 0
        self.udp_count = 0
        self.tcp_count = 0
        
        # Analysis
        self.port_counter = Counter()
        self.ip_counter = Counter()
        self.interesting_packets = []
        
    def packet_handler(self, packet):
        """Handle each packet"""
        self.packet_count += 1
        
        # Show progress
        if self.packet_count % 50 == 0:
            print(f"📦 Captured {self.packet_count} packets...")
        
        try:
            # Analyze packet
            if packet.haslayer(UDP):
                self.udp_count += 1
                self.analyze_udp_packet(packet)
                
            elif packet.haslayer(TCP):
                self.tcp_count += 1
                
            # Track IPs
            if packet.haslayer(IP):
                ip = packet[IP]
                self.ip_counter[ip.src] += 1
                self.ip_counter[ip.dst] += 1
                
        except Exception as e:
            # Ignore packet processing errors
            pass
    
    def analyze_udp_packet(self, packet):
        """Analyze UDP packets for gaming patterns"""
        try:
            udp = packet[UDP]
            ip = packet[IP]
            
            # Track ports
            self.port_counter[udp.sport] += 1
            self.port_counter[udp.dport] += 1
            
            # Look for gaming-like traffic
            payload = bytes(udp.payload) if udp.payload else b''
            
            # Gaming characteristics
            is_interesting = False
            reason = ""
            
            # Check 1: Common gaming ports
            gaming_ports = {5055, 5056, 5057, 5058, 7777, 27015}
            if udp.sport in gaming_ports or udp.dport in gaming_ports:
                is_interesting = True
                reason = f"Gaming port {udp.sport}/{udp.dport}"
            
            # Check 2: Payload size and content
            elif 10 <= len(payload) <= 1500:
                # Check for Photon-like signatures
                if len(payload) > 0:
                    first_byte = payload[0]
                    if first_byte in [0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9]:
                        is_interesting = True
                        reason = f"Photon signature 0x{first_byte:02x}"
                    
                    # High entropy might indicate game data
                    elif len(set(payload[:20])) > 10:  # Varied bytes
                        is_interesting = True
                        reason = "High entropy payload"
            
            # Check 3: Server-like IPs
            server_prefixes = ['5.', '23.', '34.', '52.', '54.', '185.', '188.']
            if any(ip.dst.startswith(prefix) for prefix in server_prefixes):
                is_interesting = True
                reason = f"Server-like IP {ip.dst}"
            
            # Check 4: Private to public communication
            private_prefixes = ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.']
            is_private_src = any(ip.src.startswith(prefix) for prefix in private_prefixes)
            is_public_dst = not any(ip.dst.startswith(prefix) for prefix in private_prefixes + ['127.'])
            
            if is_private_src and is_public_dst and len(payload) >= 20:
                is_interesting = True
                reason = f"Private→Public gaming-sized"
            
            if is_interesting:
                timestamp = time.strftime("%H:%M:%S")
                packet_info = {
                    'timestamp': timestamp,
                    'src': f"{ip.src}:{udp.sport}",
                    'dst': f"{ip.dst}:{udp.dport}",
                    'size': len(packet),
                    'payload_size': len(payload),
                    'reason': reason,
                    'hex_preview': payload[:16].hex() if len(payload) > 0 else ""
                }
                self.interesting_packets.append(packet_info)
                
                # Show real-time interesting packets
                print(f"[{timestamp}] 🎯 INTERESTING: {reason}")
                print(f"  📍 {ip.src}:{udp.sport} → {ip.dst}:{udp.dport}")
                print(f"  📦 Size: {len(packet)} bytes, Payload: {len(payload)} bytes")
                if len(payload) > 0:
                    print(f"  🔍 Hex: {payload[:16].hex()}")
                print("-" * 50)
                
        except Exception as e:
            # Ignore analysis errors
            pass
    
    def run_simple_capture(self, duration=45):
        """Run simple packet capture"""
        print("🔍 SIMPLE TRAFFIC SNIFFER")
        print("=" * 60)
        print(f"🎯 Interface: {self.target_interface}")
        print(f"⏱️  Duration: {duration} seconds")
        print("📡 Capturing ALL UDP traffic")
        print()
        print("🚨 PERFORM ACTIVE GAMEPLAY NOW!")
        print("   - Enter/exit dungeons 🏰")
        print("   - Move around constantly 👟")
        print("   - Attack mobs ⚔️")
        print("   - Open chests 📦")
        print("   - Use skills/spells ✨")
        print()
        
        try:
            start_time = time.time()
            
            # Capture with simple UDP filter
            print("🔄 Starting capture...")
            packets = sniff(
                iface=self.target_interface,
                filter="udp",  # Only UDP for simplicity
                prn=self.packet_handler,
                timeout=duration,
                store=0  # Don't store packets in memory
            )
            
            end_time = time.time()
            
            # Results
            print(f"\n📊 CAPTURE RESULTS")
            print("=" * 40)
            print(f"⏱️  Duration: {end_time - start_time:.1f} seconds")
            print(f"📦 Total packets: {self.packet_count}")
            print(f"📡 UDP packets: {self.udp_count}")
            print(f"🎯 Interesting packets: {len(self.interesting_packets)}")
            
            if self.packet_count == 0:
                print("\n❌ NO PACKETS CAPTURED!")
                print("🔧 FUNDAMENTAL CAPTURE ISSUE:")
                print("   1. Interface might be wrong")
                print("   2. Npcap might not be working")
                print("   3. No network activity at all")
                return False
            
            elif self.udp_count == 0:
                print("\n⚠️  NO UDP TRAFFIC!")
                print("   - TCP traffic exists but no UDP")
                print("   - Games usually use UDP for real-time data")
                return False
            
            elif len(self.interesting_packets) == 0:
                print("\n⚠️  NO GAMING-LIKE TRAFFIC DETECTED")
                print("   - UDP traffic exists but doesn't look like gaming")
                print("   - Albion might use different patterns")
                
                # Show top ports anyway
                print(f"\n📡 Top UDP ports detected:")
                for port, count in self.port_counter.most_common(10):
                    print(f"   Port {port}: {count} packets")
                
                return False
            
            else:
                print("\n✅ SUCCESS! INTERESTING TRAFFIC DETECTED!")
                print(f"🎉 Found {len(self.interesting_packets)} potentially relevant packets")
                
                # Show breakdown of interesting packets
                reason_counts = Counter(pkt['reason'] for pkt in self.interesting_packets)
                print(f"\n🔍 Breakdown by detection method:")
                for reason, count in reason_counts.items():
                    print(f"   {reason}: {count} packets")
                
                # Show some examples
                print(f"\n📋 Example interesting packets:")
                for i, pkt in enumerate(self.interesting_packets[:5]):
                    print(f"   {i+1}. [{pkt['timestamp']}] {pkt['src']} → {pkt['dst']}")
                    print(f"      {pkt['reason']}, {pkt['payload_size']} bytes")
                    if pkt['hex_preview']:
                        print(f"      Hex: {pkt['hex_preview']}")
                
                # Save results
                self.save_results()
                
                return True
                
        except Exception as e:
            print(f"\n❌ Capture error: {e}")
            print("🔧 Try checking interface or Npcap installation")
            return False
    
    def save_results(self):
        """Save capture results"""
        try:
            import json
            
            results = {
                'timestamp': time.time(),
                'interface': self.target_interface,
                'total_packets': self.packet_count,
                'udp_packets': self.udp_count,
                'interesting_packets_count': len(self.interesting_packets),
                'interesting_packets': self.interesting_packets,
                'top_ports': dict(self.port_counter.most_common(20)),
                'top_ips': dict(self.ip_counter.most_common(20))
            }
            
            with open('simple_capture_results.json', 'w') as f:
                json.dump(results, f, indent=2)
            
            print(f"\n💾 Results saved to: simple_capture_results.json")
            
        except Exception as e:
            print(f"⚠️  Could not save results: {e}")

def main():
    print("Simple Traffic Sniffer")
    print("Simplified approach to avoid psutil issues")
    print()
    
    sniffer = SimpleTrafficSniffer()
    success = sniffer.run_simple_capture(duration=45)
    
    if success:
        print("\n🎯 NEXT STEPS:")
        print("✅ We've detected interesting network traffic!")
        print("🔥 Ready to focus on Photon protocol parsing")
        print("📊 Review the captured patterns")
    else:
        print("\n🔧 TROUBLESHOOTING:")
        print("1. Try different interface if no packets captured")
        print("2. Check Npcap installation")
        print("3. Verify game is actively running and connected")
        print("4. Try manual Wireshark capture test")

if __name__ == "__main__":
    main()