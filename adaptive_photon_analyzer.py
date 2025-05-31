#!/usr/bin/env python3
"""
Adaptive Photon Analyzer
Auto-detect current Albion servers and analyze all potential Photon traffic
"""

import sys
import time
import json
import struct
from scapy.all import *
from scapy.layers.inet import IP, UDP
from collections import defaultdict, Counter

class AdaptivePhotonAnalyzer:
    def __init__(self):
        # Working interface
        self.target_interface = r"\Device\NPF_{6B3C185F-8A6A-48FA-89E8-F4E0E10196E0}"
        
        # Dynamic detection
        self.client_ip = "192.168.143.243"  # From previous detection
        self.detected_servers = set()
        self.gaming_ports = {5055, 5056, 5057, 5058, 7777}
        
        # Photon detection (more permissive)
        self.photon_signatures = set(range(0xF0, 0xFA))  # F0-F9
        
        # Potential Albion OpCodes
        self.albion_opcodes = {
            18: "Move", 20: "CastStart", 28: "ChangeCluster", 26: "InventoryMoveItem",
            21: "CastCancel", 22: "CastTimeUpdate", 23: "CastHit", 24: "CastHits",
            25: "CastFinish", 27: "NewCharacter", 29: "LeaveCluster"
        }
        
        # Data storage
        self.all_udp_packets = []
        self.potential_photon = []
        self.game_events = []
        self.server_stats = Counter()
        self.packet_stats = Counter()
        
    def is_potential_photon(self, payload):
        """Check if payload could be Photon packet"""
        if len(payload) == 0:
            return False, "Empty payload"
            
        first_byte = payload[0]
        
        # Check 1: Known Photon signatures
        if first_byte in self.photon_signatures:
            return True, f"Photon signature 0x{first_byte:02x}"
        
        # Check 2: High entropy gaming-like data
        if len(payload) >= 20:
            unique_bytes = len(set(payload[:20]))
            if unique_bytes >= 12:  # High variety of bytes
                return True, "High entropy data"
        
        # Check 3: Binary data with some structure
        if len(payload) >= 10:
            # Look for potential structured binary data
            null_count = payload.count(0)
            if null_count < len(payload) * 0.3:  # Less than 30% nulls
                return True, "Structured binary data"
        
        return False, "No Photon indicators"
    
    def analyze_potential_game_packet(self, payload):
        """Analyze packet for game content"""
        analysis = {
            'size': len(payload),
            'hex_preview': payload[:24].hex(),
            'first_bytes': [f"0x{b:02x}" for b in payload[:8]]
        }
        
        # Look for OpCodes
        opcodes_found = []
        for i in range(min(32, len(payload) - 1)):
            # Try different interpretations
            if i + 1 < len(payload):
                # 16-bit big endian
                be_val = (payload[i] << 8) | payload[i + 1]
                if be_val in self.albion_opcodes:
                    opcodes_found.append(f"{self.albion_opcodes[be_val]} ({be_val}) @ {i}")
                
                # 16-bit little endian  
                le_val = payload[i] | (payload[i + 1] << 8)
                if le_val in self.albion_opcodes and le_val != be_val:
                    opcodes_found.append(f"{self.albion_opcodes[le_val]} ({le_val}) @ {i}")
            
            # Single byte values
            if payload[i] in self.albion_opcodes:
                opcodes_found.append(f"{self.albion_opcodes[payload[i]]} ({payload[i]}) @ {i}")
        
        if opcodes_found:
            analysis['potential_opcodes'] = opcodes_found
        
        # Look for strings
        strings = []
        i = 0
        while i < len(payload) - 3:
            if 3 <= payload[i] <= 50:  # Potential string length
                str_len = payload[i]
                if i + str_len + 1 <= len(payload):
                    try:
                        text = payload[i+1:i+1+str_len].decode('utf-8', errors='ignore')
                        if len(text) >= 3 and text.isprintable():
                            if any(c.isalpha() for c in text):  # Contains letters
                                strings.append(f"'{text}' @ {i}")
                        i += str_len + 1
                        continue
                    except:
                        pass
            i += 1
        
        if strings:
            analysis['strings'] = strings[:5]
        
        # Look for coordinates (float patterns)
        coords = []
        for i in range(0, len(payload) - 3, 4):
            if i + 4 <= len(payload):
                try:
                    # Little endian float (more common)
                    le_float = struct.unpack('<f', payload[i:i+4])[0]
                    if -5000 < le_float < 5000 and abs(le_float) > 0.1:
                        if not (le_float == int(le_float) and abs(le_float) < 256):  # Skip obvious integers
                            coords.append(f"{le_float:.2f} @ {i}")
                except:
                    pass
        
        if coords:
            analysis['potential_coords'] = coords[:8]
        
        # Pattern analysis
        patterns = {}
        if len(payload) >= 4:
            # Look for repeated 4-byte patterns
            pattern_count = Counter()
            for i in range(len(payload) - 3):
                pattern = payload[i:i+4]
                pattern_count[pattern] += 1
            
            repeated = [p.hex() for p, c in pattern_count.items() if c > 1]
            if repeated:
                patterns['repeated_4byte'] = repeated[:3]
        
        if patterns:
            analysis['patterns'] = patterns
        
        return analysis
    
    def packet_handler(self, packet):
        """Handle all UDP packets and analyze for Albion content"""
        if not (packet.haslayer(UDP) and packet.haslayer(IP)):
            return
            
        udp = packet[UDP]
        ip = packet[IP]
        payload = bytes(udp.payload) if udp.payload else b''
        
        if len(payload) == 0:
            return
        
        self.all_udp_packets.append(packet)
        
        # Track servers communicating with our client
        if ip.src == self.client_ip:
            self.detected_servers.add(ip.dst)
            self.server_stats[ip.dst] += 1
        elif ip.dst == self.client_ip:
            self.detected_servers.add(ip.src)
            self.server_stats[ip.src] += 1
        
        # Check if this looks like gaming traffic
        is_gaming = False
        reason = ""
        
        # Gaming indicators
        if (udp.sport in self.gaming_ports or udp.dport in self.gaming_ports):
            is_gaming = True
            reason = f"Gaming port {udp.sport}/{udp.dport}"
        elif (ip.src == self.client_ip or ip.dst == self.client_ip) and len(payload) >= 20:
            is_gaming = True
            reason = "Client traffic with payload"
        
        if not is_gaming:
            return
        
        # Check if potentially Photon
        is_photon, photon_reason = self.is_potential_photon(payload)
        
        if is_photon:
            timestamp = time.strftime("%H:%M:%S.%f")[:-3]
            direction = "→" if ip.src == self.client_ip else "←"
            
            # Analyze packet content
            analysis = self.analyze_potential_game_packet(payload)
            
            packet_info = {
                'timestamp': timestamp,
                'direction': direction,
                'src': f"{ip.src}:{udp.sport}",
                'dst': f"{ip.dst}:{udp.dport}",
                'size': len(packet),
                'payload_size': len(payload),
                'detection_reason': f"{reason} + {photon_reason}",
                'analysis': analysis
            }
            
            self.potential_photon.append(packet_info)
            
            # Show interesting packets
            if ('potential_opcodes' in analysis or 
                'strings' in analysis or 
                'potential_coords' in analysis):
                
                print(f"[{timestamp}] 🎮 POTENTIAL GAME PACKET {direction}")
                print(f"  📍 {packet_info['src']} → {packet_info['dst']}")
                print(f"  🔍 Detection: {packet_info['detection_reason']}")
                print(f"  📦 Size: {analysis['size']} bytes")
                
                if 'potential_opcodes' in analysis:
                    opcodes = analysis['potential_opcodes'][:3]  # Show first 3
                    print(f"  🎯 OpCodes: {', '.join(opcodes)}")
                
                if 'strings' in analysis:
                    strings = analysis['strings'][:2]  # Show first 2
                    print(f"  📝 Strings: {', '.join(strings)}")
                
                if 'potential_coords' in analysis:
                    coords = analysis['potential_coords'][:3]  # Show first 3
                    print(f"  🗺️  Coords: {', '.join(coords)}")
                
                print(f"  🔍 Hex: {analysis['hex_preview']}...")
                print("-" * 70)
                
                self.game_events.append(packet_info)
            
            self.packet_stats[photon_reason] += 1
    
    def run_adaptive_analysis(self, duration=60):
        """Run adaptive Photon analysis"""
        print("🔄 ADAPTIVE PHOTON ANALYZER")
        print("=" * 70)
        print(f"🎯 Interface: {self.target_interface}")
        print(f"💻 Client IP: {self.client_ip}")
        print(f"⏱️  Duration: {duration} seconds")
        print("📡 Auto-detecting Albion servers...")
        print()
        print("🚨 PERFORM ACTIVE DUNGEON ACTIVITIES:")
        print("   - Move around constantly 👟")
        print("   - Attack mobs repeatedly ⚔️") 
        print("   - Open chests 📦")
        print("   - Use skills/spells ✨")
        print("   - Change equipment 🎒")
        print()
        
        try:
            start_time = time.time()
            
            # Broader filter - all UDP traffic to/from client
            bpf_filter = f"udp and (src host {self.client_ip} or dst host {self.client_ip})"
            
            print("🔄 Starting adaptive packet analysis...")
            packets = sniff(
                iface=self.target_interface,
                filter=bpf_filter,
                prn=self.packet_handler,
                timeout=duration,
                store=0
            )
            
            end_time = time.time()
            
            # Results
            print(f"\n📊 ADAPTIVE ANALYSIS RESULTS")
            print("=" * 50)
            print(f"⏱️  Duration: {end_time - start_time:.1f} seconds")
            print(f"📦 Total UDP packets: {len(self.all_udp_packets)}")
            print(f"🔥 Potential Photon packets: {len(self.potential_photon)}")
            print(f"🎮 Game event packets: {len(self.game_events)}")
            
            # Show detected servers
            if self.detected_servers:
                print(f"\n🌐 Detected Albion Servers:")
                for server in sorted(self.detected_servers):
                    count = self.server_stats[server]
                    print(f"   {server}: {count} packets")
            
            # Show packet type breakdown
            if self.packet_stats:
                print(f"\n📈 Detection Method Breakdown:")
                for method, count in self.packet_stats.most_common():
                    print(f"   {method}: {count} packets")
            
            if len(self.game_events) > 0:
                print(f"\n✅ SUCCESS! Detected {len(self.game_events)} potential game events!")
                
                # Analyze what we found
                opcodes_detected = set()
                strings_detected = set()
                
                for event in self.game_events:
                    analysis = event['analysis']
                    if 'potential_opcodes' in analysis:
                        for opcode in analysis['potential_opcodes']:
                            opcodes_detected.add(opcode.split('@')[0].strip())
                    if 'strings' in analysis:
                        for string in analysis['strings']:
                            strings_detected.add(string.split('@')[0].strip())
                
                if opcodes_detected:
                    print(f"\n🎯 Potential OpCodes found:")
                    for opcode in sorted(opcodes_detected):
                        print(f"   {opcode}")
                
                if strings_detected:
                    print(f"\n📝 Game strings found:")
                    for string in sorted(list(strings_detected)[:10]):
                        print(f"   {string}")
                
                print(f"\n🎉 READY FOR DUNGEON SCANNER IMPLEMENTATION!")
                
                self.save_analysis_results()
                return True
            else:
                print(f"\n⚠️  No game events detected")
                
                if len(self.potential_photon) > 0:
                    print("🔍 Found potential Photon packets but no obvious game events")
                    print("🔧 Try more varied gameplay activities")
                else:
                    print("🔍 No Photon-like packets detected")
                    print("🔧 Game might use different protocol or encryption")
                
                return False
                
        except Exception as e:
            print(f"\n❌ Analysis error: {e}")
            return False
    
    def save_analysis_results(self):
        """Save analysis results"""
        try:
            results = {
                'timestamp': time.time(),
                'total_udp_packets': len(self.all_udp_packets),
                'potential_photon_packets': len(self.potential_photon),
                'game_events': len(self.game_events),
                'detected_servers': list(self.detected_servers),
                'server_stats': dict(self.server_stats),
                'packet_stats': dict(self.packet_stats),
                'sample_game_events': self.game_events[:5]  # First 5 for analysis
            }
            
            with open('adaptive_photon_results.json', 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"\n💾 Results saved to: adaptive_photon_results.json")
            
        except Exception as e:
            print(f"⚠️  Could not save results: {e}")

def main():
    analyzer = AdaptivePhotonAnalyzer()
    success = analyzer.run_adaptive_analysis(duration=60)
    
    if success:
        print("\n🚀 BREAKTHROUGH ACHIEVED!")
        print("✅ Game protocol analysis successful!")
        print("🔥 Ready to build the final dungeon scanner!")
    else:
        print("\n🔧 Need more analysis or different approach")
        print("Consider checking saved results for patterns")

if __name__ == "__main__":
    main()
