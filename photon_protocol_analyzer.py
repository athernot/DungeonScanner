#!/usr/bin/env python3
"""
Photon Protocol Analyzer
Parse Photon Protocol16 packets untuk extract game events
"""

import sys
import time
import json
import struct
from scapy.all import *
from scapy.layers.inet import IP, UDP
from collections import defaultdict, Counter

class PhotonProtocolAnalyzer:
    def __init__(self):
        # Proven working configuration
        self.target_interface = r"\Device\NPF_{6B3C185F-8A6A-48FA-89E8-F4E0E10196E0}"
        self.albion_server = "157.240.13.51"
        self.client_ip = "192.168.143.243"
        
        # Photon Protocol signatures
        self.photon_msg_types = {
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
        
        # Potential Albion OpCodes (from research doc)
        self.albion_opcodes = {
            18: "Move",
            20: "CastStart", 
            28: "ChangeCluster",
            26: "InventoryMoveItem",
            # Add more as we discover
        }
        
        # Data collectors
        self.packets_analyzed = []
        self.photon_packets = []
        self.game_events = []
        self.stats = defaultdict(int)
        
    def parse_photon_header(self, payload):
        """Parse Photon packet header"""
        if len(payload) < 2:
            return None
            
        try:
            # First byte is message type
            msg_type = payload[0]
            
            # Check if it's a known Photon message type
            if msg_type not in self.photon_msg_types:
                return None
                
            photon_info = {
                'msg_type_code': msg_type,
                'msg_type': self.photon_msg_types[msg_type],
                'raw_payload': payload
            }
            
            # Parse based on message type
            if msg_type == 0xF3:  # Reliable - contains game data
                photon_info.update(self.parse_reliable_packet(payload))
            elif msg_type == 0xF8:  # Ping
                photon_info['ping_data'] = payload[1:].hex() if len(payload) > 1 else ""
            elif msg_type == 0xF9:  # Pong
                photon_info['pong_data'] = payload[1:].hex() if len(payload) > 1 else ""
                
            return photon_info
            
        except Exception as e:
            return None
    
    def parse_reliable_packet(self, payload):
        """Parse Reliable Photon packet (contains game commands/events)"""
        if len(payload) < 10:
            return {}
            
        try:
            # Reliable packets have more complex structure
            # [F3][Reliable Header][Game Data]
            
            info = {'contains_game_data': True}
            
            # Try to extract potential OpCodes and EventCodes
            # Look for 16-bit values in first part of payload that match known opcodes
            potential_opcodes = []
            
            for i in range(1, min(20, len(payload) - 1)):
                # Try both big-endian and little-endian 16-bit values
                be_value = struct.unpack('>H', payload[i:i+2])[0] if i + 1 < len(payload) else 0
                le_value = struct.unpack('<H', payload[i:i+2])[0] if i + 1 < len(payload) else 0
                
                if be_value in self.albion_opcodes:
                    potential_opcodes.append(f"{self.albion_opcodes[be_value]} ({be_value}, BE @ {i})")
                if le_value in self.albion_opcodes and le_value != be_value:
                    potential_opcodes.append(f"{self.albion_opcodes[le_value]} ({le_value}, LE @ {i})")
            
            if potential_opcodes:
                info['potential_opcodes'] = potential_opcodes
            
            # Look for string patterns (item names, etc.)
            strings = self.extract_strings(payload)
            if strings:
                info['strings'] = strings
            
            # Look for coordinate-like data (float values)
            coordinates = self.extract_coordinates(payload)
            if coordinates:
                info['potential_coordinates'] = coordinates
            
            # Analyze data patterns
            info['data_analysis'] = self.analyze_data_patterns(payload)
            
            return info
            
        except Exception as e:
            return {'parse_error': str(e)}
    
    def extract_strings(self, payload):
        """Extract potential string data from payload"""
        strings = []
        i = 0
        
        while i < len(payload) - 3:
            # Look for length-prefixed strings
            if payload[i] > 0 and payload[i] < 100:  # Reasonable string length
                str_len = payload[i]
                if i + str_len + 1 <= len(payload):
                    try:
                        text = payload[i+1:i+1+str_len].decode('utf-8', errors='ignore')
                        if len(text) >= 3 and text.isprintable():
                            # Filter out likely non-text data
                            if not all(ord(c) < 32 or ord(c) > 126 for c in text):
                                strings.append(f"'{text}' @ {i}")
                        i += str_len + 1
                    except:
                        i += 1
                else:
                    i += 1
            else:
                i += 1
        
        return strings[:5]  # Return first 5 strings
    
    def extract_coordinates(self, payload):
        """Extract potential coordinate data (floats)"""
        coordinates = []
        
        # Look for IEEE 754 float patterns
        for i in range(0, len(payload) - 3, 4):
            if i + 4 <= len(payload):
                try:
                    # Try both endianness
                    be_float = struct.unpack('>f', payload[i:i+4])[0]
                    le_float = struct.unpack('<f', payload[i:i+4])[0]
                    
                    # Check if values look like game coordinates
                    for float_val, endian in [(be_float, 'BE'), (le_float, 'LE')]:
                        if -10000 < float_val < 10000 and abs(float_val) > 0.01:
                            coordinates.append(f"{float_val:.2f} ({endian}) @ {i}")
                            
                except:
                    continue
        
        return coordinates[:10]  # Return first 10 potential coordinates
    
    def analyze_data_patterns(self, payload):
        """Analyze payload for interesting patterns"""
        analysis = {}
        
        # Entropy analysis
        if len(payload) > 0:
            unique_bytes = len(set(payload))
            entropy_ratio = unique_bytes / len(payload)
            analysis['entropy'] = f"{entropy_ratio:.2f} ({unique_bytes}/{len(payload)})"
        
        # Look for repeated patterns
        if len(payload) >= 8:
            pattern_counts = Counter()
            for i in range(len(payload) - 3):
                pattern = payload[i:i+4].hex()
                pattern_counts[pattern] += 1
            
            common_patterns = [p for p, c in pattern_counts.items() if c > 1]
            if common_patterns:
                analysis['repeated_patterns'] = common_patterns[:3]
        
        # Look for null-terminated regions
        null_regions = []
        in_null_region = False
        start = 0
        
        for i, byte in enumerate(payload):
            if byte == 0:
                if not in_null_region:
                    start = i
                    in_null_region = True
            else:
                if in_null_region and i - start > 2:  # At least 3 null bytes
                    null_regions.append(f"nulls[{start}:{i}]")
                in_null_region = False
        
        if null_regions:
            analysis['null_regions'] = null_regions[:3]
        
        return analysis
    
    def packet_handler(self, packet):
        """Main packet handler for Photon analysis"""
        if not (packet.haslayer(UDP) and packet.haslayer(IP)):
            return
            
        udp = packet[UDP]
        ip = packet[IP]
        
        # Filter for our known Albion traffic
        is_albion = False
        direction = ""
        
        if ((ip.src == self.client_ip and ip.dst == self.albion_server) or
            (ip.src == self.albion_server and ip.dst == self.client_ip)):
            is_albion = True
            direction = "→ SERVER" if ip.dst == self.albion_server else "← SERVER"
        
        if not is_albion:
            return
        
        payload = bytes(udp.payload) if udp.payload else b''
        if len(payload) == 0:
            return
        
        # Analyze as Photon packet
        photon_info = self.parse_photon_header(payload)
        
        if photon_info:
            timestamp = time.strftime("%H:%M:%S.%f")[:-3]
            
            packet_info = {
                'timestamp': timestamp,
                'direction': direction,
                'src': f"{ip.src}:{udp.sport}",
                'dst': f"{ip.dst}:{udp.dport}",
                'size': len(packet),
                'payload_size': len(payload),
                'photon_info': photon_info
            }
            
            self.packets_analyzed.append(packet_info)
            
            # Count stats
            self.stats[f"photon_{photon_info['msg_type']}"] += 1
            self.stats[f"direction_{direction}"] += 1
            
            # Show interesting packets real-time
            if (photon_info['msg_type'] == 'Reliable' and 
                photon_info.get('contains_game_data')):
                
                print(f"[{timestamp}] 🎮 GAME DATA {direction}")
                print(f"  📍 {ip.src}:{udp.sport} → {ip.dst}:{udp.dport}")
                print(f"  🔥 Photon: {photon_info['msg_type']}")
                print(f"  📦 Size: {len(payload)} bytes")
                
                # Show interesting findings
                if 'potential_opcodes' in photon_info:
                    print(f"  🎯 OpCodes: {', '.join(photon_info['potential_opcodes'])}")
                
                if 'strings' in photon_info:
                    print(f"  📝 Strings: {', '.join(photon_info['strings'])}")
                
                if 'potential_coordinates' in photon_info:
                    coords = photon_info['potential_coordinates'][:3]  # Show first 3
                    print(f"  🗺️  Coords: {', '.join(coords)}")
                
                # Show hex preview
                hex_preview = payload[:32].hex()
                print(f"  🔍 Hex: {hex_preview}...")
                print("-" * 70)
                
                # Store as potential game event
                self.game_events.append(packet_info)
    
    def run_photon_analysis(self, duration=60):
        """Run Photon protocol analysis"""
        print("🔥 PHOTON PROTOCOL ANALYZER")
        print("=" * 70)
        print(f"🎯 Interface: {self.target_interface}")
        print(f"🌐 Albion Server: {self.albion_server}")
        print(f"💻 Client IP: {self.client_ip}")
        print(f"⏱️  Duration: {duration} seconds")
        print()
        print("🚨 PERFORM DUNGEON ACTIVITIES:")
        print("   - Enter/exit dungeons 🏰")
        print("   - Attack mobs (look for Move/CastStart) ⚔️")
        print("   - Open chests (look for InventoryMove) 📦")
        print("   - Change floors (look for ChangeCluster) 🔄")
        print()
        
        try:
            start_time = time.time()
            
            # Create filter for our specific Albion traffic
            bpf_filter = f"udp and (host {self.albion_server})"
            
            print("🔄 Starting Photon packet analysis...")
            packets = sniff(
                iface=self.target_interface,
                filter=bpf_filter,
                prn=self.packet_handler,
                timeout=duration,
                store=0
            )
            
            end_time = time.time()
            
            # Results
            print(f"\n📊 PHOTON ANALYSIS RESULTS")
            print("=" * 50)
            print(f"⏱️  Duration: {end_time - start_time:.1f} seconds")
            print(f"📦 Total Photon packets: {len(self.packets_analyzed)}")
            print(f"🎮 Game data packets: {len(self.game_events)}")
            
            if self.stats:
                print(f"\n📈 Packet Type Breakdown:")
                for ptype, count in sorted(self.stats.items()):
                    print(f"   {ptype}: {count}")
            
            if len(self.game_events) > 0:
                print(f"\n✅ SUCCESS! Detected {len(self.game_events)} game events!")
                print("🎉 Ready for game event classification!")
                
                # Show summary of game events found
                opcodes_found = set()
                strings_found = set()
                
                for event in self.game_events:
                    photon = event['photon_info']
                    if 'potential_opcodes' in photon:
                        opcodes_found.update(photon['potential_opcodes'])
                    if 'strings' in photon:
                        for s in photon['strings']:
                            strings_found.add(s.split('@')[0].strip())  # Remove position info
                
                if opcodes_found:
                    print(f"\n🎯 Potential OpCodes detected:")
                    for opcode in sorted(opcodes_found):
                        print(f"   {opcode}")
                
                if strings_found:
                    print(f"\n📝 Game strings detected:")
                    for string in sorted(list(strings_found)[:10]):  # Show first 10
                        print(f"   {string}")
                
                self.save_analysis_results()
                return True
            else:
                print(f"\n⚠️  No game events detected in Photon packets")
                print("🔧 Try performing more active gameplay activities")
                return False
                
        except Exception as e:
            print(f"\n❌ Analysis error: {e}")
            return False
    
    def save_analysis_results(self):
        """Save analysis results"""
        try:
            results = {
                'timestamp': time.time(),
                'total_packets': len(self.packets_analyzed),
                'game_events': len(self.game_events),
                'stats': dict(self.stats),
                'sample_events': self.game_events[:10]  # Save first 10 for analysis
            }
            
            with open('photon_analysis_results.json', 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"\n💾 Analysis saved to: photon_analysis_results.json")
            
        except Exception as e:
            print(f"⚠️  Could not save results: {e}")

def main():
    analyzer = PhotonProtocolAnalyzer()
    success = analyzer.run_photon_analysis(duration=60)
    
    if success:
        print("\n🎯 MAJOR BREAKTHROUGH!")
        print("✅ Photon protocol parsing working!")
        print("🔥 Ready for game event classification and dungeon scanner!")
    else:
        print("\n🔧 Continue with more active gameplay or check packet patterns")

if __name__ == "__main__":
    main()
