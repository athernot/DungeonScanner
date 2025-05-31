#!/usr/bin/env python3
"""
Adaptive Albion Scanner
Dynamic detection dengan filtering yang fleksibel
"""

import sys
import time
import json
import psutil
from scapy.all import *
from scapy.layers.inet import IP, UDP
from collections import defaultdict

class AdaptiveAlbionScanner:
    def __init__(self):
        # Target interface yang sudah terbukti bekerja
        self.target_interface = r"\Device\NPF_{6B3C185F-8A6A-48FA-89E8-F4E0E10196E0}"
        
        # Dynamic data
        self.packets_captured = []
        self.albion_indicators = {
            'server_ips': set(),
            'client_ips': set(), 
            'photon_ports': {5055, 5056, 5057, 5058},  # Common Photon ports
            'dynamic_ports': set()
        }
        self.packet_stats = defaultdict(int)
        self.last_ip_scan = 0
        
    def get_current_albion_connections(self):
        """Get current Albion network connections"""
        print("🔍 Scanning current Albion connections...")
        
        current_connections = {
            'server_ips': set(),
            'client_ips': set(),
            'ports': set()
        }
        
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if 'albion' in proc.info['name'].lower():
                    connections = proc.net_connections()
                    for conn in connections:
                        if conn.type == socket.SOCK_DGRAM and conn.raddr:  # UDP with remote address
                            current_connections['server_ips'].add(conn.raddr.ip)
                            current_connections['client_ips'].add(conn.laddr.ip)
                            current_connections['ports'].add(conn.raddr.port)
                            current_connections['ports'].add(conn.laddr.port)
                            
                            print(f"  📡 Connection: {conn.laddr.ip}:{conn.laddr.port} ↔ {conn.raddr.ip}:{conn.raddr.port}")
                            
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
        
        return current_connections
    
    def create_adaptive_filter(self):
        """Create adaptive filter based on current connections and common patterns"""
        # Get current connections
        current = self.get_current_albion_connections()
        
        # Update our indicators
        self.albion_indicators['server_ips'].update(current['server_ips'])
        self.albion_indicators['client_ips'].update(current['client_ips'])
        self.albion_indicators['dynamic_ports'].update(current['ports'])
        
        # Build filter components
        filters = []
        
        # Add known server IPs
        if current['server_ips']:
            ip_filters = [f"host {ip}" for ip in current['server_ips']]
            filters.extend(ip_filters)
            print(f"📍 Using server IPs: {current['server_ips']}")
        
        # Add common Photon ports
        port_filters = [f"port {port}" for port in self.albion_indicators['photon_ports']]
        filters.extend(port_filters)
        
        # Fallback: capture all UDP traffic (we'll filter in handler)
        if not filters:
            return "udp"
        
        # Combine with OR
        return " or ".join(f"({f})" for f in filters)
    
    def is_potential_albion_packet(self, packet):
        """Determine if packet is potentially from Albion"""
        if not (packet.haslayer(UDP) and packet.haslayer(IP)):
            return False, "Not UDP"
            
        udp = packet[UDP]
        ip = packet[IP]
        
        # Check 1: Known server IPs
        if ip.src in self.albion_indicators['server_ips'] or ip.dst in self.albion_indicators['server_ips']:
            return True, f"Known server IP ({ip.src}/{ip.dst})"
        
        # Check 2: Known client IPs
        if ip.src in self.albion_indicators['client_ips'] or ip.dst in self.albion_indicators['client_ips']:
            return True, f"Known client IP ({ip.src}/{ip.dst})"
        
        # Check 3: Common Photon ports
        if udp.sport in self.albion_indicators['photon_ports'] or udp.dport in self.albion_indicators['photon_ports']:
            return True, f"Photon port ({udp.sport}/{udp.dport})"
        
        # Check 4: Dynamic ports from connections
        if udp.sport in self.albion_indicators['dynamic_ports'] or udp.dport in self.albion_indicators['dynamic_ports']:
            return True, f"Dynamic port ({udp.sport}/{udp.dport})"
        
        # Check 5: Payload analysis for Photon signatures
        if len(udp.payload) > 0:
            payload = bytes(udp.payload)
            # Photon packet signatures
            if len(payload) > 0 and payload[0] in [0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9]:
                return True, f"Photon signature (0x{payload[0]:02x})"
        
        # Check 6: Private IP ranges communicating on gaming ports
        private_ranges = ['192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.']
        is_private_src = any(ip.src.startswith(range_) for range_ in private_ranges)
        is_private_dst = any(ip.dst.startswith(range_) for range_ in private_ranges)
        
        if (is_private_src or is_private_dst) and (1000 <= udp.sport <= 65535 or 1000 <= udp.dport <= 65535):
            # Check payload size patterns (Photon packets are usually > 10 bytes)
            if len(udp.payload) >= 10:
                return True, f"Private IP gaming traffic"
        
        return False, "No Albion indicators"
    
    def analyze_photon_packet(self, packet):
        """Enhanced Photon packet analysis"""
        udp = packet[UDP]
        payload = bytes(udp.payload)
        
        if len(payload) == 0:
            return None
            
        # Photon packet signatures
        photon_types = {
            0xF0: "Unreliable",
            0xF1: "UnreliableFragment", 
            0xF2: "ReliableFragment",
            0xF3: "Reliable",
            0xF4: "Acknowledge",
            0xF5: "Connect",
            0xF6: "Disconnect",
            0xF7: "DisconnectAck",
            0xF8: "Ping",
            0xF9: "Pong"
        }
        
        first_byte = payload[0]
        packet_type = photon_types.get(first_byte, f"Unknown(0x{first_byte:02x})")
        
        analysis = {
            'type': packet_type,
            'size': len(payload),
            'hex_preview': payload[:20].hex(),
            'is_reliable': first_byte == 0xF3
        }
        
        # If reliable packet, try to extract more info
        if analysis['is_reliable'] and len(payload) > 10:
            analysis['game_data'] = self.extract_game_data(payload)
        
        return analysis
    
    def extract_game_data(self, payload):
        """Extract potential game data from reliable Photon packets"""
        game_data = {}
        
        try:
            # Look for OpCode patterns (common Albion OpCodes)
            common_opcodes = {
                18: "Move",
                20: "CastStart", 
                28: "ChangeCluster",
                26: "InventoryMoveItem"
            }
            
            # Search for opcode patterns in first 20 bytes
            for i in range(min(20, len(payload) - 1)):
                value = (payload[i] << 8) | payload[i + 1]  # Big endian 16-bit
                if value in common_opcodes:
                    game_data['possible_opcode'] = f"{common_opcodes[value]} ({value})"
                    break
            
            # Look for string patterns (item names, etc.)
            strings = []
            i = 0
            while i < len(payload) - 3:
                if payload[i] > 0 and payload[i] < 100:  # Possible string length
                    str_len = payload[i]
                    if i + str_len + 1 < len(payload):
                        try:
                            text = payload[i+1:i+1+str_len].decode('utf-8')
                            if text.isprintable() and len(text) >= 3:
                                strings.append(text)
                                i += str_len + 1
                                continue
                        except:
                            pass
                i += 1
            
            if strings:
                game_data['strings'] = strings[:3]  # First 3 strings
                
        except Exception:
            pass
            
        return game_data
    
    def packet_handler(self, packet):
        """Enhanced packet handler with adaptive detection"""
        is_albion, reason = self.is_potential_albion_packet(packet)
        
        if is_albion:
            udp = packet[UDP]
            ip = packet[IP]
            timestamp = time.strftime("%H:%M:%S.%f")[:-3]
            
            # Determine direction
            direction = "UNKNOWN"
            if ip.dst in self.albion_indicators['server_ips']:
                direction = "→ SERVER"
            elif ip.src in self.albion_indicators['server_ips']:
                direction = "← SERVER"
            elif any(ip.dst.startswith(r) for r in ['5.', '23.', '34.', '52.', '54.']):  # Common server IP ranges
                direction = "→ SERVER?"
            elif any(ip.src.startswith(r) for r in ['5.', '23.', '34.', '52.', '54.']):
                direction = "← SERVER?"
            
            print(f"[{timestamp}] 🎯 POTENTIAL ALBION PACKET {direction}")
            print(f"  📍 {ip.src}:{udp.sport} → {ip.dst}:{udp.dport}")
            print(f"  📦 Size: {len(packet)} bytes, Payload: {len(udp.payload)} bytes")
            print(f"  🔍 Reason: {reason}")
            
            # Analyze Photon content
            photon_info = self.analyze_photon_packet(packet)
            if photon_info:
                print(f"  🔥 Photon: {photon_info['type']}")
                print(f"  📊 Hex: {photon_info['hex_preview']}")
                
                if 'game_data' in photon_info and photon_info['game_data']:
                    for key, value in photon_info['game_data'].items():
                        print(f"  🎮 {key}: {value}")
            
            print("-" * 70)
            
            # Update our indicators
            self.albion_indicators['server_ips'].add(ip.src)
            self.albion_indicators['server_ips'].add(ip.dst)
            self.albion_indicators['dynamic_ports'].add(udp.sport)
            self.albion_indicators['dynamic_ports'].add(udp.dport)
            
            # Store packet
            self.packets_captured.append({
                'timestamp': time.time(),
                'direction': direction,
                'reason': reason,
                'packet': packet,
                'photon_info': photon_info
            })
            
            self.packet_stats[direction] += 1
    
    def run_adaptive_scan(self, duration=60):
        """Run adaptive scan with dynamic filtering"""
        print("🔄 ADAPTIVE ALBION SCANNER")
        print("=" * 70)
        print(f"🎯 Interface: {self.target_interface}")
        print(f"⏱️  Duration: {duration} seconds")
        print()
        
        # Create adaptive filter
        bpf_filter = self.create_adaptive_filter()
        print(f"📡 Initial Filter: {bpf_filter[:100]}...")
        print()
        print("🚨 PERFORM ACTIVE GAMEPLAY NOW!")
        print("   - Enter/exit dungeons 🏰")
        print("   - Move around actively 👟")
        print("   - Attack mobs ⚔️")
        print("   - Open chests 📦")
        print("   - Change floors 🔄")
        print("   - Open/close inventory 🎒")
        print()
        
        try:
            start_time = time.time()
            
            # Start capture with adaptive filtering
            packets = sniff(
                iface=self.target_interface,
                filter=bpf_filter,
                prn=self.packet_handler,
                timeout=duration,
                store=1
            )
            
            end_time = time.time()
            
            # Results
            print("\n" + "=" * 70)
            print("=== ADAPTIVE SCAN RESULTS ===")
            print(f"⏱️  Duration: {end_time - start_time:.1f} seconds")
            print(f"📦 Total packets captured: {len(packets)}")
            print(f"🎯 Potential Albion packets: {len(self.packets_captured)}")
            
            if self.packet_stats:
                print("\n📊 Traffic Breakdown:")
                for direction, count in self.packet_stats.items():
                    print(f"   {direction}: {count} packets")
            
            if self.albion_indicators['server_ips']:
                server_ips = [ip for ip in self.albion_indicators['server_ips'] if not any(ip.startswith(r) for r in ['192.168.', '10.', '172.'])]
                if server_ips:
                    print(f"\n🌐 Server IPs detected: {', '.join(server_ips)}")
            
            if self.albion_indicators['dynamic_ports']:
                common_ports = self.albion_indicators['dynamic_ports'] & {5055, 5056, 5057, 5058}
                if common_ports:
                    print(f"🔌 Photon ports confirmed: {', '.join(map(str, sorted(common_ports)))}")
            
            if len(self.packets_captured) > 0:
                print("\n✅ SUCCESS! Potential Albion traffic detected!")
                print("🎉 Ready for advanced Photon protocol analysis!")
                
                # Save data
                self.save_capture_data()
                return True
            else:
                print("\n⚠️  No potential Albion traffic detected")
                print("🔧 Possible issues:")
                print("   - Game may be idle/not sending packets")
                print("   - May need to try during more active gameplay")
                print("   - Connection might be using different interface")
                return False
                
        except Exception as e:
            print(f"\n❌ Capture error: {e}")
            return False
    
    def save_capture_data(self):
        """Save captured data for analysis"""
        try:
            summary = {
                'timestamp': time.time(),
                'interface': self.target_interface,
                'packets_captured': len(self.packets_captured),
                'server_ips': list(self.albion_indicators['server_ips']),
                'dynamic_ports': list(self.albion_indicators['dynamic_ports']),
                'packet_stats': dict(self.packet_stats)
            }
            
            with open('adaptive_capture_summary.json', 'w') as f:
                json.dump(summary, f, indent=2)
            
            print(f"💾 Data saved to: adaptive_capture_summary.json")
            
        except Exception as e:
            print(f"⚠️  Could not save data: {e}")

def main():
    scanner = AdaptiveAlbionScanner()
    success = scanner.run_adaptive_scan(duration=60)
    
    if success:
        print("\n🎯 BREAKTHROUGH ACHIEVED!")
        print("Ready to proceed with Photon Protocol parsing and game event detection!")
    else:
        print("\n🔧 Continue troubleshooting or try with more active gameplay")

if __name__ == "__main__":
    main()