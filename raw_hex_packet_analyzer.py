#!/usr/bin/env python3
"""
Raw Hex Packet Analyzer
Analyze actual packet content without protocol assumptions
"""

import sys
import time
import json
from scapy.all import *
from scapy.layers.inet import IP, UDP
from collections import defaultdict, Counter

class RawHexAnalyzer:
    def __init__(self):
        # Working configuration
        self.target_interface = r"\Device\NPF_{6B3C185F-8A6A-48FA-89E8-F4E0E10196E0}"
        self.client_ip = "192.168.143.243"
        
        # Data storage
        self.captured_packets = []
        self.hex_patterns = []
        self.server_traffic = {}
        self.packet_sizes = []
        
    def analyze_raw_packet(self, payload):
        """Analyze raw packet content without assumptions"""
        if len(payload) == 0:
            return None
            
        analysis = {
            'size': len(payload),
            'first_16_bytes': payload[:16].hex() if len(payload) >= 16 else payload.hex(),
            'full_hex': payload.hex(),
            'first_8_bytes_int': [f"0x{b:02x}" for b in payload[:8]],
            'last_8_bytes': payload[-8:].hex() if len(payload) >= 8 else "",
            'byte_patterns': {}
        }
        
        # Basic statistics
        analysis['unique_bytes'] = len(set(payload))
        analysis['entropy_ratio'] = len(set(payload)) / len(payload) if len(payload) > 0 else 0
        analysis['null_count'] = payload.count(0)
        analysis['ff_count'] = payload.count(0xFF)
        
        # Look for repeating patterns
        if len(payload) >= 4:
            patterns = Counter()
            for i in range(len(payload) - 3):
                pattern = payload[i:i+4].hex()
                patterns[pattern] += 1
            
            repeated = {p: c for p, c in patterns.items() if c > 1}
            if repeated:
                analysis['byte_patterns']['repeated_4byte'] = repeated
        
        # Look for potential text
        text_regions = []
        current_text = ""
        for i, byte in enumerate(payload):
            if 32 <= byte <= 126:  # Printable ASCII
                current_text += chr(byte)
            else:
                if len(current_text) >= 3:
                    text_regions.append(f"'{current_text}' @ {i-len(current_text)}")
                current_text = ""
        
        if len(current_text) >= 3:
            text_regions.append(f"'{current_text}' @ {len(payload)-len(current_text)}")
        
        if text_regions:
            analysis['text_regions'] = text_regions
        
        # Look for structured data patterns
        structure_hints = []
        
        # Check for length-prefixed data
        if len(payload) >= 4:
            for i in range(min(4, len(payload))):
                potential_len = payload[i]
                if 0 < potential_len < len(payload) - i:
                    structure_hints.append(f"Potential length field: {potential_len} @ {i}")
        
        # Check for common binary markers
        markers = {
            b'\x00\x00': 'null_pair',
            b'\xFF\xFF': 'max_pair', 
            b'\x01\x00': 'little_endian_1',
            b'\x00\x01': 'big_endian_1'
        }
        
        found_markers = []
        for marker, name in markers.items():
            if marker in payload:
                positions = [i for i in range(len(payload) - len(marker) + 1) 
                           if payload[i:i+len(marker)] == marker]
                found_markers.append(f"{name}: {positions[:3]}")  # First 3 positions
        
        if found_markers:
            structure_hints.extend(found_markers)
        
        if structure_hints:
            analysis['structure_hints'] = structure_hints
        
        return analysis
    
    def packet_handler(self, packet):
        """Handle all UDP packets for raw analysis"""
        if not (packet.haslayer(UDP) and packet.haslayer(IP)):
            return
            
        udp = packet[UDP]
        ip = packet[IP]
        payload = bytes(udp.payload) if udp.payload else b''
        
        # Only analyze traffic to/from our client
        if not (ip.src == self.client_ip or ip.dst == self.client_ip):
            return
        
        if len(payload) == 0:
            return
        
        timestamp = time.strftime("%H:%M:%S.%f")[:-3]
        direction = "→" if ip.src == self.client_ip else "←"
        
        # Determine server
        server_ip = ip.dst if ip.src == self.client_ip else ip.src
        server_port = udp.dport if ip.src == self.client_ip else udp.sport
        
        # Track server traffic
        server_key = f"{server_ip}:{server_port}"
        if server_key not in self.server_traffic:
            self.server_traffic[server_key] = []
        
        # Analyze packet content
        analysis = self.analyze_raw_packet(payload)
        
        packet_info = {
            'timestamp': timestamp,
            'direction': direction,
            'server': server_key,
            'src': f"{ip.src}:{udp.sport}",
            'dst': f"{ip.dst}:{udp.dport}",
            'size': len(packet),
            'payload_size': len(payload),
            'analysis': analysis
        }
        
        self.captured_packets.append(packet_info)
        self.server_traffic[server_key].append(packet_info)
        self.packet_sizes.append(len(payload))
        
        # Show ALL packets in real-time with full hex
        print(f"[{timestamp}] 📦 RAW PACKET {direction} {server_key}")
        print(f"  📍 {packet_info['src']} → {packet_info['dst']}")
        print(f"  📊 Size: {len(packet)} bytes, Payload: {len(payload)} bytes")
        print(f"  🔍 First 16 bytes: {analysis['first_16_bytes']}")
        
        if len(payload) > 16:
            print(f"  📄 Full hex ({len(payload)} bytes):")
            # Show hex in groups of 16 bytes for readability
            for i in range(0, len(payload), 16):
                chunk = payload[i:i+16]
                hex_str = ' '.join(f'{b:02x}' for b in chunk)
                ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                print(f"     {i:04x}: {hex_str:<48} |{ascii_str}|")
        
        # Show analysis results
        if analysis['entropy_ratio'] > 0.7:
            print(f"  🎲 High entropy: {analysis['entropy_ratio']:.2f}")
        
        if 'text_regions' in analysis:
            print(f"  📝 Text: {', '.join(analysis['text_regions'][:3])}")
        
        if 'structure_hints' in analysis:
            print(f"  🔧 Structure: {', '.join(analysis['structure_hints'][:3])}")
        
        print("-" * 80)
    
    def run_raw_analysis(self, duration=45):
        """Run raw packet analysis"""
        print("🔍 RAW HEX PACKET ANALYZER")
        print("=" * 80)
        print(f"🎯 Interface: {self.target_interface}")
        print(f"💻 Client IP: {self.client_ip}")
        print(f"⏱️  Duration: {duration} seconds")
        print("📡 Capturing ALL UDP traffic with FULL HEX DUMP")
        print()
        print("🚨 PERFORM VERY ACTIVE GAMEPLAY:")
        print("   - Move around constantly 👟")
        print("   - Attack mobs repeatedly ⚔️")
        print("   - Open chests multiple times 📦")
        print("   - Use skills/spells ✨")
        print("   - Interact with anything clickable 🖱️")
        print()
        
        try:
            start_time = time.time()
            
            # Broader filter for all client traffic
            bpf_filter = f"udp and (src host {self.client_ip} or dst host {self.client_ip})"
            
            print("🔄 Starting raw packet capture...")
            packets = sniff(
                iface=self.target_interface,
                filter=bpf_filter,
                prn=self.packet_handler,
                timeout=duration,
                store=0
            )
            
            end_time = time.time()
            
            # Results summary
            print(f"\n📊 RAW ANALYSIS RESULTS")
            print("=" * 60)
            print(f"⏱️  Duration: {end_time - start_time:.1f} seconds")
            print(f"📦 Total packets captured: {len(self.captured_packets)}")
            
            if len(self.captured_packets) == 0:
                print("❌ NO PACKETS CAPTURED!")
                print("🔧 Check if game is active and creating network traffic")
                return False
            
            # Server breakdown
            print(f"\n🌐 Server Communication:")
            for server, packets in self.server_traffic.items():
                print(f"   {server}: {len(packets)} packets")
            
            # Packet size analysis
            if self.packet_sizes:
                avg_size = sum(self.packet_sizes) / len(self.packet_sizes)
                print(f"\n📊 Payload Size Analysis:")
                print(f"   Average: {avg_size:.1f} bytes")
                print(f"   Range: {min(self.packet_sizes)} - {max(self.packet_sizes)} bytes")
                
                # Size distribution
                size_ranges = Counter()
                for size in self.packet_sizes:
                    if size <= 50:
                        size_ranges['Small (≤50)'] += 1
                    elif size <= 200:
                        size_ranges['Medium (51-200)'] += 1
                    elif size <= 500:
                        size_ranges['Large (201-500)'] += 1
                    else:
                        size_ranges['Very Large (>500)'] += 1
                
                for range_name, count in size_ranges.items():
                    print(f"   {range_name}: {count} packets")
            
            # Pattern analysis
            print(f"\n🔍 NEXT STEPS:")
            print("1. Review the hex dumps above for patterns")
            print("2. Look for repeated byte sequences") 
            print("3. Identify packet types by size/content")
            print("4. Manual analysis of packet structure")
            
            self.save_raw_results()
            return True
            
        except Exception as e:
            print(f"\n❌ Analysis error: {e}")
            return False
    
    def save_raw_results(self):
        """Save raw analysis results"""
        try:
            # Prepare data for JSON (exclude binary data)
            export_data = []
            for packet in self.captured_packets:
                export_packet = {
                    'timestamp': packet['timestamp'],
                    'direction': packet['direction'],
                    'server': packet['server'],
                    'src': packet['src'],
                    'dst': packet['dst'],
                    'payload_size': packet['payload_size'],
                    'hex_data': packet['analysis']['full_hex'],
                    'entropy': packet['analysis']['entropy_ratio'],
                    'text_regions': packet['analysis'].get('text_regions', []),
                    'structure_hints': packet['analysis'].get('structure_hints', [])
                }
                export_data.append(export_packet)
            
            results = {
                'timestamp': time.time(),
                'total_packets': len(self.captured_packets),
                'servers': list(self.server_traffic.keys()),
                'packet_size_stats': {
                    'average': sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0,
                    'min': min(self.packet_sizes) if self.packet_sizes else 0,
                    'max': max(self.packet_sizes) if self.packet_sizes else 0
                },
                'packets': export_data
            }
            
            with open('raw_hex_analysis.json', 'w') as f:
                json.dump(results, f, indent=2)
            
            print(f"\n💾 Raw data saved to: raw_hex_analysis.json")
            
        except Exception as e:
            print(f"⚠️  Could not save results: {e}")

def main():
    analyzer = RawHexAnalyzer()
    success = analyzer.run_raw_analysis(duration=45)
    
    if success:
        print("\n🔍 RAW ANALYSIS COMPLETE!")
        print("✅ Review the hex dumps to understand the actual protocol")
        print("🔧 Use this data to reverse engineer the packet structure")
    else:
        print("\n❌ No packets captured - check game connectivity")

if __name__ == "__main__":
    main()
