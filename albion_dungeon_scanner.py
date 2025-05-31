#!/usr/bin/env python3
"""
Albion Online Dungeon Scanner v1.0
Production dungeon scanner using proven working packet capture
"""

import sys
import time
import json
import struct
from scapy.all import *
from scapy.layers.inet import IP, UDP
from collections import defaultdict, Counter
from datetime import datetime

class AlbionDungeonScanner:
    def __init__(self):
        # Proven working configuration from testing
        self.interface = r"\Device\NPF_{6B3C185F-8A6A-48FA-89E8-F4E0E10196E0}"
        self.client_ip = "192.168.143.243"
        
        # Known Albion servers (from testing)
        self.albion_servers = {
            "13.35.238.120",
            "35.174.127.31", 
            "5.45.187.30"
        }
        
        # Game state tracking
        self.current_dungeon = {
            'in_dungeon': False,
            'dungeon_id': None,
            'floor': 0,
            'mobs': {},  # {mob_id: mob_info}
            'chests': {},  # {chest_id: chest_info}
            'player_position': {'x': 0, 'y': 0, 'z': 0}
        }
        
        # Event detection patterns
        self.mob_keywords = [
            b'MOB_', b'CREATURE_', b'MONSTER_', b'BEAST_', b'UNDEAD_',
            b'AVALONIAN_', b'BANDIT_', b'HERETIC_', b'KEEPER_'
        ]
        
        self.chest_keywords = [
            b'TREASURE_CHEST', b'CHEST_', b'LOOT_', b'SILVER_',
            b'AVALONIAN_CHEST', b'BOOK_CHEST', b'LEGENDARY_CHEST'
        ]
        
        self.item_keywords = [
            b'MAIN_', b'HEAD_', b'ARMOR_', b'SHOES_', b'BAG_',
            b'WEAPON_', b'OFFHAND_', b'CAPE_', b'MOUNT_', b'FOOD_'
        ]
        
        # Statistics
        self.stats = {
            'packets_analyzed': 0,
            'mobs_detected': 0,
            'chests_detected': 0,
            'items_detected': 0,
            'session_start': time.time()
        }
        
        # Detection results
        self.recent_detections = []
        
    def detect_dungeon_entry_exit(self, payload):
        """Detect when player enters/exits dungeons"""
        # Look for cluster change patterns
        cluster_patterns = [
            b'CLUSTER_', b'RANDOMDUNGEON_', b'SOLO_', b'GROUP_',
            b'AVALON_', b'CORRUPTED_', b'HELLGATE_'
        ]
        
        for pattern in cluster_patterns:
            if pattern in payload:
                # Potential dungeon change
                print(f"🏰 POTENTIAL DUNGEON EVENT: {pattern.decode('utf-8', 'ignore')}")
                self.current_dungeon['in_dungeon'] = True
                return True
        
        return False
    
    def detect_mob_spawn(self, payload):
        """Detect mob spawn events"""
        for keyword in self.mob_keywords:
            if keyword in payload:
                # Extract mob information
                mob_info = self.extract_entity_info(payload, keyword, 'MOB')
                if mob_info:
                    mob_id = mob_info.get('id', f"mob_{time.time()}")
                    self.current_dungeon['mobs'][mob_id] = mob_info
                    self.stats['mobs_detected'] += 1
                    
                    print(f"👹 MOB DETECTED: {mob_info['name']}")
                    if 'position' in mob_info:
                        pos = mob_info['position']
                        print(f"   📍 Position: ({pos['x']:.1f}, {pos['y']:.1f})")
                    
                    self.recent_detections.append({
                        'type': 'MOB',
                        'timestamp': datetime.now().strftime("%H:%M:%S"),
                        'info': mob_info
                    })
                    
                    return True
        return False
    
    def detect_chest_spawn(self, payload):
        """Detect chest spawn events"""
        for keyword in self.chest_keywords:
            if keyword in payload:
                # Extract chest information
                chest_info = self.extract_entity_info(payload, keyword, 'CHEST')
                if chest_info:
                    chest_id = chest_info.get('id', f"chest_{time.time()}")
                    self.current_dungeon['chests'][chest_id] = chest_info
                    self.stats['chests_detected'] += 1
                    
                    # Determine chest rarity
                    rarity = self.determine_chest_rarity(chest_info['name'])
                    chest_info['rarity'] = rarity
                    
                    print(f"📦 CHEST DETECTED: {chest_info['name']} ({rarity})")
                    if 'position' in chest_info:
                        pos = chest_info['position']
                        print(f"   📍 Position: ({pos['x']:.1f}, {pos['y']:.1f})")
                    
                    self.recent_detections.append({
                        'type': 'CHEST',
                        'timestamp': datetime.now().strftime("%H:%M:%S"),
                        'info': chest_info
                    })
                    
                    return True
        return False
    
    def determine_chest_rarity(self, chest_name):
        """Determine chest rarity from name"""
        name_lower = chest_name.lower()
        
        if 'legendary' in name_lower or 'gold' in name_lower:
            return '🏆 LEGENDARY'
        elif 'epic' in name_lower or 'purple' in name_lower:
            return '🟣 EPIC'
        elif 'rare' in name_lower or 'blue' in name_lower:
            return '🔵 RARE'
        elif 'uncommon' in name_lower or 'green' in name_lower:
            return '🟢 UNCOMMON'
        elif 'book' in name_lower:
            return '📚 BOOK'
        elif 'avalonian' in name_lower:
            return '⚪ AVALONIAN'
        else:
            return '⚪ STANDARD'
    
    def extract_entity_info(self, payload, keyword, entity_type):
        """Extract entity information from payload"""
        try:
            # Find keyword position
            keyword_pos = payload.find(keyword)
            if keyword_pos == -1:
                return None
            
            # Extract name (look for null-terminated string)
            name_start = keyword_pos
            name_end = name_start
            
            # Find end of string (null terminator or non-printable)
            while name_end < len(payload) and payload[name_end] != 0:
                if payload[name_end] < 32 or payload[name_end] > 126:
                    break
                name_end += 1
            
            if name_end > name_start:
                name = payload[name_start:name_end].decode('utf-8', 'ignore')
            else:
                name = keyword.decode('utf-8', 'ignore')
            
            # Look for position data (floats near the keyword)
            position = self.extract_position_near(payload, keyword_pos)
            
            entity_info = {
                'name': name,
                'type': entity_type,
                'detected_at': time.time()
            }
            
            if position:
                entity_info['position'] = position
            
            return entity_info
            
        except Exception as e:
            return None
    
    def extract_position_near(self, payload, keyword_pos):
        """Extract position coordinates near keyword"""
        try:
            # Look for float patterns in 100 bytes around keyword
            search_start = max(0, keyword_pos - 50)
            search_end = min(len(payload), keyword_pos + 50)
            search_region = payload[search_start:search_end]
            
            coordinates = []
            
            # Look for IEEE 754 floats
            for i in range(0, len(search_region) - 3, 4):
                if i + 4 <= len(search_region):
                    try:
                        # Try little endian (more common)
                        float_val = struct.unpack('<f', search_region[i:i+4])[0]
                        
                        # Check if looks like game coordinate
                        if -5000 < float_val < 5000 and abs(float_val) > 0.1:
                            # Avoid obvious integers or weird values
                            if not (float_val == int(float_val) and abs(float_val) < 100):
                                coordinates.append(float_val)
                    except:
                        continue
            
            # If we found 2+ coordinates, assume they are x, y (and possibly z)
            if len(coordinates) >= 2:
                position = {'x': coordinates[0], 'y': coordinates[1]}
                if len(coordinates) >= 3:
                    position['z'] = coordinates[2]
                return position
            
        except:
            pass
        
        return None
    
    def analyze_player_movement(self, payload):
        """Analyze player movement patterns"""
        # Look for movement-related data
        position = self.extract_position_near(payload, 0)
        if position:
            # Update player position
            old_pos = self.current_dungeon['player_position']
            new_pos = position
            
            # Calculate movement distance
            dx = new_pos['x'] - old_pos['x']
            dy = new_pos['y'] - old_pos['y']
            distance = (dx**2 + dy**2)**0.5
            
            # Only update if significant movement
            if distance > 1.0:
                self.current_dungeon['player_position'] = new_pos
                print(f"🚶 Player moved to ({new_pos['x']:.1f}, {new_pos['y']:.1f})")
                return True
        
        return False
    
    def packet_handler(self, packet):
        """Main packet handler for dungeon scanning"""
        if not (packet.haslayer(UDP) and packet.haslayer(IP)):
            return
        
        udp = packet[UDP]
        ip = packet[IP]
        payload = bytes(udp.payload) if udp.payload else b''
        
        if len(payload) == 0:
            return
        
        # Filter for Albion traffic
        is_albion = False
        
        # Check if communicating with known Albion servers
        if ip.src in self.albion_servers or ip.dst in self.albion_servers:
            is_albion = True
        # Check if client traffic on gaming ports
        elif ((ip.src == self.client_ip or ip.dst == self.client_ip) and 
              (5055 <= udp.sport <= 5058 or 5055 <= udp.dport <= 5058)):
            is_albion = True
        # Check for high entropy gaming data
        elif ((ip.src == self.client_ip or ip.dst == self.client_ip) and 
              len(payload) >= 20 and len(set(payload[:20])) >= 12):
            is_albion = True
        
        if not is_albion:
            return
        
        self.stats['packets_analyzed'] += 1
        
        # Analyze packet for game events
        detected_something = False
        
        # Check for dungeon entry/exit
        if self.detect_dungeon_entry_exit(payload):
            detected_something = True
        
        # Check for mob spawns
        if self.detect_mob_spawn(payload):
            detected_something = True
        
        # Check for chest spawns  
        if self.detect_chest_spawn(payload):
            detected_something = True
        
        # Check for player movement
        if self.analyze_player_movement(payload):
            detected_something = True
        
        # Show progress every 100 packets
        if self.stats['packets_analyzed'] % 100 == 0:
            print(f"📊 Analyzed {self.stats['packets_analyzed']} packets...")
    
    def display_current_status(self):
        """Display current dungeon status"""
        print(f"\n🎯 CURRENT DUNGEON STATUS")
        print("=" * 50)
        print(f"📍 In Dungeon: {'Yes' if self.current_dungeon['in_dungeon'] else 'No'}")
        print(f"👹 Active Mobs: {len(self.current_dungeon['mobs'])}")
        print(f"📦 Available Chests: {len(self.current_dungeon['chests'])}")
        
        pos = self.current_dungeon['player_position']
        print(f"🚶 Player Position: ({pos['x']:.1f}, {pos['y']:.1f})")
        
        # Show recent detections
        if self.recent_detections:
            print(f"\n🕐 Recent Detections (last 10):")
            for detection in self.recent_detections[-10:]:
                timestamp = detection['timestamp']
                entity_type = detection['type']
                name = detection['info']['name']
                print(f"   [{timestamp}] {entity_type}: {name}")
    
    def run_dungeon_scanner(self, duration=None):
        """Run the main dungeon scanner"""
        print("🎯 ALBION ONLINE DUNGEON SCANNER v1.0")
        print("=" * 60)
        print(f"🌐 Interface: {self.interface[-20:]}")
        print(f"💻 Client IP: {self.client_ip}")
        print(f"🖥️  Albion Servers: {len(self.albion_servers)} known servers")
        print(f"⏱️  Duration: {'Unlimited' if duration is None else f'{duration} seconds'}")
        print()
        print("🎮 SCANNER ACTIVE - Enter dungeons and explore!")
        print("   👹 Watching for mob spawns")
        print("   📦 Watching for chest spawns") 
        print("   🏰 Watching for dungeon events")
        print("   🚶 Tracking player movement")
        print()
        
        try:
            start_time = time.time()
            
            # Create filter for Albion traffic
            server_list = ' or '.join([f'host {server}' for server in self.albion_servers])
            bpf_filter = f"udp and (({server_list}) or host {self.client_ip})"
            
            print("🔄 Starting dungeon scan...")
            
            # Run scanner
            packets = sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=self.packet_handler,
                timeout=duration,
                store=0
            )
            
            end_time = time.time()
            
            # Final results
            print(f"\n📊 DUNGEON SCAN RESULTS")
            print("=" * 40)
            print(f"⏱️  Duration: {end_time - start_time:.1f} seconds")
            print(f"📦 Packets analyzed: {self.stats['packets_analyzed']}")
            print(f"👹 Mobs detected: {self.stats['mobs_detected']}")
            print(f"📦 Chests detected: {self.stats['chests_detected']}")
            
            # Display final status
            self.display_current_status()
            
            # Save results
            self.save_scan_results()
            
            return True
            
        except KeyboardInterrupt:
            print(f"\n⏹️  Scanner stopped by user")
            self.display_current_status()
            self.save_scan_results()
            return True
            
        except Exception as e:
            print(f"\n❌ Scanner error: {e}")
            return False
    
    def save_scan_results(self):
        """Save scan results to file"""
        try:
            results = {
                'timestamp': time.time(),
                'session_duration': time.time() - self.stats['session_start'],
                'stats': self.stats,
                'current_dungeon': self.current_dungeon,
                'recent_detections': self.recent_detections,
                'interface_used': self.interface,
                'servers_monitored': list(self.albion_servers)
            }
            
            filename = f"dungeon_scan_{int(time.time())}.json"
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"\n💾 Scan results saved to: {filename}")
            
        except Exception as e:
            print(f"⚠️  Could not save results: {e}")

def main():
    print("Albion Online Dungeon Scanner v1.0")
    print("Production scanner using proven packet capture")
    print()
    
    scanner = AlbionDungeonScanner()
    
    try:
        # Run unlimited duration (until Ctrl+C)
        success = scanner.run_dungeon_scanner()
        
        if success:
            print("\n✅ Dungeon scan completed successfully!")
        else:
            print("\n❌ Dungeon scan encountered errors")
            
    except KeyboardInterrupt:
        print("\n👋 Scanner stopped by user - goodbye!")

if __name__ == "__main__":
    main()
