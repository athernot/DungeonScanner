#!/usr/bin/env python3
"""
Enhanced Albion Online Dungeon Scanner v2.0
Advanced UI with live map and entity tracking
"""

import sys
import time
import json
import struct
import threading
from scapy.all import *
from scapy.layers.inet import IP, UDP
from collections import defaultdict, Counter
from datetime import datetime

class EnhancedDungeonScanner:
    def __init__(self):
        # Proven working configuration
        self.interface = r"\Device\NPF_{6B3C185F-8A6A-48FA-89E8-F4E0E10196E0}"
        self.client_ip = "192.168.143.243"
        self.albion_servers = {"13.35.238.120", "35.174.127.31", "5.45.187.30"}
        
        # Enhanced game state
        self.dungeon_state = {
            'in_dungeon': False,
            'dungeon_name': 'Unknown',
            'floor': 0,
            'entities': {},  # Combined mobs and chests
            'player_pos': {'x': 0, 'y': 0, 'z': 0},
            'last_update': time.time()
        }
        
        # Enhanced detection patterns
        self.entity_patterns = {
            'mobs': [
                b'MOB_KEEPER_', b'MOB_BANDIT_', b'MOB_UNDEAD_', b'MOB_AVALONIAN_',
                b'KEEPER_', b'CREATURE_', b'MONSTER_', b'BEAST_', b'HERETIC_',
                b'EARTHDAUGHTER_', b'ROCKSPIRIT_', b'THORNWEAVER_', b'DRYAD_'
            ],
            'chests': [
                b'TREASURE_CHEST', b'CHEST_RARE', b'CHEST_EPIC', b'CHEST_LEGENDARY',
                b'CHEST_AVALONIAN', b'BOOK_CHEST', b'SILVER_CHEST', b'GOLD_CHEST'
            ],
            'dungeon_types': [
                b'SOLO_', b'GROUP_', b'AVALONIAN_', b'CORRUPTED_', b'HELLGATE_',
                b'RANDOMDUNGEON_', b'CLUSTER_DUNGEON'
            ]
        }
        
        # Enhanced statistics
        self.stats = {
            'session_start': time.time(),
            'packets_analyzed': 0,
            'entities_detected': 0,
            'unique_mobs': set(),
            'unique_chests': set(),
            'detection_rate': 0,
            'avg_detection_time': 0
        }
        
        # Live tracking
        self.live_entities = []
        self.detection_history = []
        self.scanner_active = False
        
    def enhanced_entity_detection(self, payload):
        """Enhanced entity detection with better parsing"""
        detected_entities = []
        
        # Check for all entity types
        for entity_type, patterns in self.entity_patterns.items():
            for pattern in patterns:
                if pattern in payload:
                    entity_info = self.extract_enhanced_entity_info(payload, pattern, entity_type)
                    if entity_info:
                        detected_entities.append(entity_info)
        
        return detected_entities
    
    def extract_enhanced_entity_info(self, payload, pattern, entity_type):
        """Extract detailed entity information"""
        try:
            pattern_pos = payload.find(pattern)
            if pattern_pos == -1:
                return None
            
            # Extract full entity name (improved parsing)
            name_start = pattern_pos
            name_end = name_start
            
            # Find complete entity name
            while name_end < len(payload) and payload[name_end] != 0:
                if payload[name_end] < 32 or payload[name_end] > 126:
                    # Check if we have a reasonable name length
                    if name_end - name_start >= 3:
                        break
                name_end += 1
            
            entity_name = payload[name_start:name_end].decode('utf-8', 'ignore')
            
            # Extract position with better accuracy
            position = self.extract_precise_position(payload, pattern_pos)
            
            # Determine entity classification
            classification = self.classify_entity(entity_name, entity_type)
            
            # Generate unique ID
            entity_id = f"{entity_type}_{hash(entity_name + str(time.time()))}"
            
            entity_info = {
                'id': entity_id,
                'name': entity_name,
                'type': entity_type,
                'classification': classification,
                'detected_at': time.time(),
                'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3]
            }
            
            if position:
                entity_info['position'] = position
                entity_info['distance_from_player'] = self.calculate_distance(
                    position, self.dungeon_state['player_pos']
                )
            
            return entity_info
            
        except Exception as e:
            return None
    
    def classify_entity(self, name, entity_type):
        """Classify entities with enhanced details"""
        name_lower = name.lower()
        
        if entity_type == 'mobs':
            if 'boss' in name_lower or 'veteran' in name_lower:
                return '👑 BOSS'
            elif 'elite' in name_lower:
                return '⭐ ELITE'
            elif 'keeper' in name_lower:
                return '🛡️ KEEPER'
            elif 'avalonian' in name_lower:
                return '⚪ AVALONIAN'
            else:
                return '👹 REGULAR'
                
        elif entity_type == 'chests':
            if 'legendary' in name_lower or 'gold' in name_lower:
                return '🏆 LEGENDARY'
            elif 'epic' in name_lower or 'purple' in name_lower:
                return '🟣 EPIC'
            elif 'rare' in name_lower or 'blue' in name_lower:
                return '🔵 RARE'
            elif 'book' in name_lower:
                return '📚 BOOK'
            elif 'avalonian' in name_lower:
                return '⚪ AVALONIAN'
            else:
                return '🟢 STANDARD'
        
        return '❓ UNKNOWN'
    
    def extract_precise_position(self, payload, reference_pos):
        """Extract precise position coordinates"""
        try:
            # Search in expanded region around reference
            search_start = max(0, reference_pos - 100)
            search_end = min(len(payload), reference_pos + 100)
            search_region = payload[search_start:search_end]
            
            coordinates = []
            
            # Look for IEEE 754 float patterns
            for i in range(0, len(search_region) - 3, 1):  # More thorough search
                if i + 4 <= len(search_region):
                    try:
                        # Little endian float
                        float_val = struct.unpack('<f', search_region[i:i+4])[0]
                        
                        # Game coordinate validation
                        if -10000 < float_val < 10000 and abs(float_val) > 0.01:
                            # Avoid obvious non-coordinates
                            if not (abs(float_val) < 1 and float_val == int(float_val)):
                                coordinates.append(float_val)
                    except:
                        continue
            
            # Return most likely coordinate set
            if len(coordinates) >= 2:
                # Remove duplicates and select best candidates
                unique_coords = []
                for coord in coordinates:
                    if not any(abs(coord - existing) < 0.1 for existing in unique_coords):
                        unique_coords.append(coord)
                
                if len(unique_coords) >= 2:
                    position = {
                        'x': round(unique_coords[0], 2),
                        'y': round(unique_coords[1], 2)
                    }
                    if len(unique_coords) >= 3:
                        position['z'] = round(unique_coords[2], 2)
                    
                    return position
            
        except:
            pass
        
        return None
    
    def calculate_distance(self, pos1, pos2):
        """Calculate 3D distance between positions"""
        try:
            dx = pos1.get('x', 0) - pos2.get('x', 0)
            dy = pos1.get('y', 0) - pos2.get('y', 0)
            dz = pos1.get('z', 0) - pos2.get('z', 0)
            return round((dx**2 + dy**2 + dz**2)**0.5, 1)
        except:
            return 0
    
    def update_player_position(self, payload):
        """Update player position with enhanced tracking"""
        position = self.extract_precise_position(payload, 0)
        if position:
            old_pos = self.dungeon_state['player_pos']
            distance_moved = self.calculate_distance(position, old_pos)
            
            # Only update for significant movement
            if distance_moved > 0.5:
                self.dungeon_state['player_pos'] = position
                self.dungeon_state['last_update'] = time.time()
                return True
        return False
    
    def display_live_scanner_ui(self):
        """Display enhanced live scanner interface"""
        while self.scanner_active:
            # Clear screen for live updates
            import os
            os.system('cls' if os.name == 'nt' else 'clear')
            
            print("🎯 ENHANCED ALBION DUNGEON SCANNER v2.0")
            print("=" * 70)
            
            # Session info
            runtime = time.time() - self.stats['session_start']
            print(f"⏱️  Runtime: {runtime:.1f}s | 📦 Packets: {self.stats['packets_analyzed']}")
            print(f"🎮 Detection Rate: {self.stats['detection_rate']:.1f}/min")
            
            # Dungeon status
            print(f"\n🏰 DUNGEON STATUS")
            print("-" * 30)
            print(f"📍 In Dungeon: {'Yes' if self.dungeon_state['in_dungeon'] else 'No'}")
            print(f"🗺️  Dungeon: {self.dungeon_state['dungeon_name']}")
            print(f"🏢 Floor: {self.dungeon_state['floor']}")
            
            # Player position
            pos = self.dungeon_state['player_pos']
            print(f"🚶 Player: ({pos['x']:.1f}, {pos['y']:.1f}, {pos.get('z', 0):.1f})")
            
            # Live entities
            print(f"\n👁️ LIVE ENTITIES ({len(self.live_entities)})")
            print("-" * 30)
            
            for entity in self.live_entities[-10:]:  # Show last 10
                name = entity['name'][:30]  # Truncate long names
                classification = entity['classification']
                timestamp = entity['timestamp']
                
                if 'distance_from_player' in entity:
                    distance = entity['distance_from_player']
                    print(f"[{timestamp}] {classification} {name} ({distance}m)")
                else:
                    print(f"[{timestamp}] {classification} {name}")
            
            # Statistics
            print(f"\n📊 SESSION STATISTICS")
            print("-" * 30)
            print(f"👹 Unique Mobs: {len(self.stats['unique_mobs'])}")
            print(f"📦 Unique Chests: {len(self.stats['unique_chests'])}")
            print(f"🎯 Total Detections: {self.stats['entities_detected']}")
            
            print(f"\n🔄 Scanning... (Ctrl+C to stop)")
            
            time.sleep(2)  # Update every 2 seconds
    
    def enhanced_packet_handler(self, packet):
        """Enhanced packet handler with better detection"""
        if not (packet.haslayer(UDP) and packet.haslayer(IP)):
            return
        
        udp = packet[UDP]
        ip = packet[IP]
        payload = bytes(udp.payload) if udp.payload else b''
        
        if len(payload) == 0:
            return
        
        # Enhanced Albion traffic detection
        is_albion = (
            ip.src in self.albion_servers or ip.dst in self.albion_servers or
            ((ip.src == self.client_ip or ip.dst == self.client_ip) and 
             (5055 <= udp.sport <= 5058 or 5055 <= udp.dport <= 5058)) or
            ((ip.src == self.client_ip or ip.dst == self.client_ip) and 
             len(payload) >= 20 and len(set(payload[:20])) >= 10)
        )
        
        if not is_albion:
            return
        
        self.stats['packets_analyzed'] += 1
        
        # Enhanced entity detection
        detected_entities = self.enhanced_entity_detection(payload)
        
        for entity in detected_entities:
            self.live_entities.append(entity)
            self.detection_history.append(entity)
            self.stats['entities_detected'] += 1
            
            # Track unique entities
            if entity['type'] == 'mobs':
                self.stats['unique_mobs'].add(entity['name'])
            elif entity['type'] == 'chests':
                self.stats['unique_chests'].add(entity['name'])
            
            # Update detection rate
            runtime = time.time() - self.stats['session_start']
            self.stats['detection_rate'] = (self.stats['entities_detected'] / runtime) * 60
        
        # Update player position
        self.update_player_position(payload)
        
        # Detect dungeon state changes
        for pattern in self.entity_patterns['dungeon_types']:
            if pattern in payload:
                self.dungeon_state['in_dungeon'] = True
                self.dungeon_state['dungeon_name'] = pattern.decode('utf-8', 'ignore')
    
    def run_enhanced_scanner(self, duration=None):
        """Run enhanced scanner with live UI"""
        print("🚀 STARTING ENHANCED DUNGEON SCANNER v2.0")
        print("=" * 60)
        
        self.scanner_active = True
        
        # Start UI thread
        ui_thread = threading.Thread(target=self.display_live_scanner_ui, daemon=True)
        ui_thread.start()
        
        try:
            # Create enhanced filter
            server_filter = ' or '.join([f'host {server}' for server in self.albion_servers])
            bpf_filter = f"udp and (({server_filter}) or host {self.client_ip})"
            
            # Start packet capture
            packets = sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=self.enhanced_packet_handler,
                timeout=duration,
                store=0
            )
            
        except KeyboardInterrupt:
            print(f"\n⏹️  Enhanced scanner stopped by user")
        except Exception as e:
            print(f"\n❌ Enhanced scanner error: {e}")
        finally:
            self.scanner_active = False
            self.save_enhanced_results()
    
    def save_enhanced_results(self):
        """Save enhanced scan results"""
        try:
            results = {
                'scanner_version': '2.0',
                'timestamp': time.time(),
                'session_duration': time.time() - self.stats['session_start'],
                'stats': {
                    **self.stats,
                    'unique_mobs': list(self.stats['unique_mobs']),
                    'unique_chests': list(self.stats['unique_chests'])
                },
                'dungeon_state': self.dungeon_state,
                'live_entities': self.live_entities,
                'detection_history': self.detection_history,
                'interface_used': self.interface,
                'servers_monitored': list(self.albion_servers)
            }
            
            filename = f"enhanced_dungeon_scan_{int(time.time())}.json"
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"\n💾 Enhanced results saved to: {filename}")
            
        except Exception as e:
            print(f"⚠️  Could not save enhanced results: {e}")

def main():
    scanner = EnhancedDungeonScanner()
    scanner.run_enhanced_scanner()

if __name__ == "__main__":
    main()
