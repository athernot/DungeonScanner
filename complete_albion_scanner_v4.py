#!/usr/bin/env python3
"""
Complete Albion Online Dungeon Scanner Suite v4.0
- Advanced Deduplication with Fixed Normalization
- WebSocket Integration for Real-time Visualization
- Avalonian Multi-Floor Support
- OpCode Detection
- Advanced Analytics & Reporting
- Professional UI with Live Statistics
"""

import sys
import time
import json
import struct
import threading
import hashlib
import asyncio
import websockets
import sqlite3
from datetime import datetime, timedelta
from scapy.all import *
from scapy.layers.inet import IP, UDP
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class FloorEntity:
    """Enhanced entity representation"""
    entity_id: str
    name: str
    entity_type: str
    position: Tuple[float, float, float]
    floor_id: int
    detected_at: float
    classification: str
    faction: str = "Unknown"
    threat_level: str = "Unknown"
    tier: int = 0
    is_boss: bool = False
    is_shrine: bool = False
    loot_value: str = "Unknown"
    detection_count: int = 1
    last_seen: float = None

@dataclass
class DungeonFloor:
    """Enhanced floor representation"""
    floor_id: int
    floor_name: str
    floor_type: str
    entities: Dict[str, FloorEntity]
    entry_time: float
    exit_time: Optional[float] = None
    completed: bool = False
    shrine_activated: bool = False
    player_path: List[Tuple[float, float, float]] = None

class EnhancedDeduplicationManager:
    """Advanced deduplication with improved normalization"""
    
    def __init__(self):
        self.seen_entities = {}
        self.position_tracker = {}
        self.name_variations = {}
        self.entity_database = sqlite3.connect(':memory:')
        self._setup_database()
        
    def _setup_database(self):
        """Setup in-memory database for entity tracking"""
        cursor = self.entity_database.cursor()
        cursor.execute('''
            CREATE TABLE entities (
                hash TEXT PRIMARY KEY,
                name TEXT,
                normalized_name TEXT,
                type TEXT,
                position_x REAL,
                position_y REAL,
                position_z REAL,
                first_seen REAL,
                last_seen REAL,
                detection_count INTEGER,
                floor_id INTEGER
            )
        ''')
        self.entity_database.commit()
        
    def normalize_entity_name(self, name):
        """Enhanced normalize entity name with comprehensive pattern matching"""
        normalized = name.upper().strip()
        
        # Remove leading/trailing underscores
        normalized = normalized.strip('_')
        
        # Remove common prefixes in order of specificity
        prefixes_to_remove = [
            'HERETIC_SOLO_', 'HERETIC_GROUP_', 'AVALONIAN_SOLO_', 'AVALONIAN_GROUP_',
            'HERETIC_', 'AVALONIAN_', 'KEEPER_', 'MORGANA_',
            'SOLO_', 'GROUP_', 'MOB_', 'CREATURE_', 'MONSTER_'
        ]
        
        for prefix in prefixes_to_remove:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
                break
        
        # Normalize common suffixes
        suffix_replacements = {
            '_VETERAN': '_VET',
            '_BOSS': '_B',
            '_STANDARD': '_STD',
            '_UNCOMMON': '_UNC',
            '_COMMON': '_COM',
            '_RARE': '_R',
            '_EPIC': '_EP',
            '_LEGENDARY': '_LEG'
        }
        
        for old_suffix, new_suffix in suffix_replacements.items():
            normalized = normalized.replace(old_suffix, new_suffix)
        
        # Special handling for chest variations
        if 'CHEST' in normalized:
            # Normalize chest types to base form
            chest_types = ['_STD', '_UNC', '_COM', '_R', '_EP', '_LEG']
            base_name = 'CHEST'
            
            # Find the chest quality
            for chest_type in chest_types:
                if chest_type in normalized:
                    base_name += chest_type
                    break
            
            normalized = base_name
        
        return normalized
    
    def generate_entity_hash(self, entity_name, position, entity_type, floor_id=0):
        """Generate unique hash with floor consideration"""
        normalized_name = self.normalize_entity_name(entity_name)
        
        # For entities without position, use name + type + floor
        if not position:
            hash_string = f"{normalized_name}_{entity_type}_{floor_id}"
        else:
            # Round position for consistency
            pos_x = round(position.get('x', 0), 1)
            pos_y = round(position.get('y', 0), 1)
            pos_z = round(position.get('z', 0), 1)
            pos_string = f"{pos_x}_{pos_y}_{pos_z}"
            hash_string = f"{normalized_name}_{pos_string}_{entity_type}_{floor_id}"
        
        return hashlib.md5(hash_string.encode()).hexdigest()[:16]
    
    def is_duplicate(self, entity_name, position, entity_type, floor_id=0, tolerance=5.0):
        """Enhanced duplicate detection with multiple methods"""
        
        # Method 1: Exact hash match
        entity_hash = self.generate_entity_hash(entity_name, position, entity_type, floor_id)
        if entity_hash in self.seen_entities:
            return True, entity_hash, "exact_hash_match"
        
        # Method 2: Database lookup with normalization
        normalized_name = self.normalize_entity_name(entity_name)
        cursor = self.entity_database.cursor()
        
        if position:
            x, y, z = position.get('x', 0), position.get('y', 0), position.get('z', 0)
            cursor.execute('''
                SELECT hash FROM entities 
                WHERE normalized_name = ? 
                AND type = ? 
                AND floor_id = ?
                AND ABS(position_x - ?) < ? 
                AND ABS(position_y - ?) < ?
                AND ABS(position_z - ?) < ?
            ''', (normalized_name, entity_type, floor_id, x, tolerance, y, tolerance, z, tolerance))
        else:
            cursor.execute('''
                SELECT hash FROM entities 
                WHERE normalized_name = ? 
                AND type = ? 
                AND floor_id = ?
                AND position_x IS NULL
            ''', (normalized_name, entity_type, floor_id))
        
        result = cursor.fetchone()
        if result:
            return True, result[0], "database_match"
        
        return False, entity_hash, "new_entity"
    
    def add_entity(self, entity_name, position, entity_type, floor_id=0):
        """Add entity to tracking system with database storage"""
        entity_hash = self.generate_entity_hash(entity_name, position, entity_type, floor_id)
        normalized_name = self.normalize_entity_name(entity_name)
        current_time = time.time()
        
        # Store in memory
        self.seen_entities[entity_hash] = {
            'detected_name': entity_name,
            'normalized_name': normalized_name,
            'type': entity_type,
            'position': position,
            'floor_id': floor_id,
            'first_seen': current_time,
            'last_seen': current_time,
            'detection_count': 1
        }
        
        # Store in database
        cursor = self.entity_database.cursor()
        pos_x = position.get('x') if position else None
        pos_y = position.get('y') if position else None
        pos_z = position.get('z') if position else None
        
        cursor.execute('''
            INSERT INTO entities 
            (hash, name, normalized_name, type, position_x, position_y, position_z, 
             first_seen, last_seen, detection_count, floor_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (entity_hash, entity_name, normalized_name, entity_type, 
              pos_x, pos_y, pos_z, current_time, current_time, 1, floor_id))
        
        self.entity_database.commit()
        return entity_hash
    
    def update_entity(self, entity_hash):
        """Update existing entity"""
        current_time = time.time()
        
        if entity_hash in self.seen_entities:
            self.seen_entities[entity_hash]['last_seen'] = current_time
            self.seen_entities[entity_hash]['detection_count'] += 1
            
            # Update database
            cursor = self.entity_database.cursor()
            cursor.execute('''
                UPDATE entities 
                SET last_seen = ?, detection_count = detection_count + 1
                WHERE hash = ?
            ''', (current_time, entity_hash))
            self.entity_database.commit()

class AvalonianDungeonTracker:
    """Enhanced multi-floor Avalonian dungeon tracking"""
    
    def __init__(self):
        self.floors: Dict[int, DungeonFloor] = {}
        self.current_floor_id: int = 0
        self.dungeon_session_id: str = f"avalonian_{int(time.time())}"
        self.total_floors_discovered: int = 0
        self.floor_transition_history: List[Dict] = []
        
        # Avalonian-specific patterns
        self.avalonian_patterns = {
            'floor_transitions': [
                b'FLOOR_TRANSITION', b'AVALONIAN_FLOOR_', b'LEVEL_CHANGE',
                b'TELEPORT_FLOOR', b'DUNGEON_LEVEL_', b'CLUSTER_AVALONIAN'
            ],
            'shrines': [
                b'SHRINE_COMBAT', b'SHRINE_FAME', b'SHRINE_LOOT', 
                b'SHRINE_SILVER', b'AVALONIAN_SHRINE', b'SHRINE_ENERGY'
            ],
            'avalonian_mobs': [
                b'AVALONIAN_KNIGHT', b'AVALONIAN_MAGE', b'AVALONIAN_ARCHER',
                b'AVALONIAN_CONSTRUCT', b'AVALONIAN_GUARDIAN', b'AVALONIAN_CHAMPION'
            ],
            'avalonian_bosses': [
                b'AVALONIAN_BOSS', b'AVALONIAN_CHAMPION', b'AVALONIAN_LORD',
                b'AVALONIAN_ANCIENT', b'CRYSTAL_GUARDIAN', b'ENERGY_CONSTRUCT'
            ],
            'crystal_elements': [
                b'CRYSTAL_CHEST', b'ENERGY_CRYSTAL', b'AVALONIAN_CRYSTAL',
                b'SHARD_CHEST', b'ENERGY_SHARD', b'CRYSTAL_FRAGMENT'
            ]
        }
    
    def detect_floor_transition(self, payload: bytes) -> Optional[int]:
        """Detect floor transitions with enhanced pattern matching"""
        for pattern in self.avalonian_patterns['floor_transitions']:
            if pattern in payload:
                # Advanced floor number extraction
                floor_num = self.extract_floor_number_advanced(payload, pattern)
                if floor_num is not None and floor_num != self.current_floor_id:
                    self.transition_to_floor(floor_num)
                    return floor_num
        return None
    
    def extract_floor_number_advanced(self, payload: bytes, pattern: bytes) -> Optional[int]:
        """Advanced floor number extraction with multiple methods"""
        try:
            pattern_pos = payload.find(pattern)
            if pattern_pos == -1:
                return None
            
            # Method 1: Look for numeric sequences near pattern
            search_start = max(0, pattern_pos - 20)
            search_end = min(len(payload), pattern_pos + 50)
            search_region = payload[search_start:search_end]
            
            # Find numeric patterns
            for i in range(len(search_region) - 1):
                if search_region[i:i+1].isdigit():
                    num_str = ""
                    j = i
                    while j < len(search_region) and search_region[j:j+1].isdigit():
                        num_str += search_region[j:j+1].decode('ascii')
                        j += 1
                    
                    if num_str:
                        floor_num = int(num_str)
                        if 1 <= floor_num <= 50:  # Reasonable floor range
                            return floor_num
            
            # Method 2: Binary pattern analysis for encoded floor numbers
            for i in range(0, len(search_region) - 3, 4):
                if i + 4 <= len(search_region):
                    try:
                        # Try to interpret as little-endian integer
                        floor_candidate = struct.unpack('<I', search_region[i:i+4])[0]
                        if 1 <= floor_candidate <= 20:  # Reasonable Avalonian floor range
                            return floor_candidate
                    except:
                        continue
            
            # Fallback: increment current floor
            return self.current_floor_id + 1
            
        except:
            return None

class OpCodeDetector:
    """Enhanced OpCode detection for Photon Protocol"""
    
    def __init__(self):
        self.known_opcodes = {
            # Movement and positioning
            18: 'MOVE',
            19: 'CHARACTER_MOVEMENT', 
            20: 'TELEPORT',
            
            # Entity management
            21: 'NEW_CHARACTER',
            22: 'NEW_MOB',
            23: 'NEW_CHEST',
            24: 'REMOVE_ENTITY',
            25: 'UPDATE_ENTITY',
            
            # Inventory and items
            26: 'INVENTORY_MOVE',
            27: 'ITEM_DROPPED',
            28: 'LOOT_CHEST',
            29: 'ITEM_EQUIPPED',
            
            # Dungeon/Cluster management
            30: 'CHANGE_CLUSTER',
            31: 'DUNGEON_ENTER',
            32: 'DUNGEON_EXIT',
            33: 'FLOOR_CHANGE',
            
            # Combat
            40: 'CAST_SPELL',
            41: 'DAMAGE_DEALT',
            42: 'MOB_HEALTH_UPDATE',
            43: 'PLAYER_HEALTH_UPDATE',
            
            # Chat and social
            50: 'CHAT_MESSAGE',
            51: 'GUILD_MESSAGE',
            52: 'ALLIANCE_MESSAGE'
        }
        
        self.opcode_handlers = {
            22: self.handle_new_mob,
            23: self.handle_new_chest,
            30: self.handle_cluster_change,
            33: self.handle_floor_change
        }
    
    def detect_opcodes(self, payload: bytes) -> List[Dict]:
        """Detect and parse Photon OpCodes"""
        opcodes_found = []
        
        # Look for Photon packet structure
        if len(payload) < 12:
            return opcodes_found
        
        try:
            # Check for Photon signature (simplified)
            offset = 0
            while offset < len(payload) - 3:
                # Look for potential opcode (1 byte) + length (2 bytes)
                if offset + 3 <= len(payload):
                    opcode = payload[offset]
                    length = struct.unpack('>H', payload[offset+1:offset+3])[0]
                    
                    if opcode in self.known_opcodes and length < 1000:  # Reasonable length
                        operation_data = payload[offset+3:offset+3+length]
                        
                        opcodes_found.append({
                            'opcode': opcode,
                            'operation': self.known_opcodes[opcode],
                            'data': operation_data,
                            'length': length,
                            'offset': offset
                        })
                        
                        offset += 3 + length
                    else:
                        offset += 1
                else:
                    break
                    
        except struct.error:
            pass
        
        return opcodes_found
    
    def handle_new_mob(self, data: bytes) -> Optional[Dict]:
        """Handle new mob OpCode"""
        if len(data) < 20:
            return None
        
        try:
            mob_id = struct.unpack('<I', data[0:4])[0]
            x = struct.unpack('<f', data[4:8])[0]
            y = struct.unpack('<f', data[8:12])[0]
            z = struct.unpack('<f', data[12:16])[0] if len(data) >= 16 else 0
            
            return {
                'type': 'mob_spawn',
                'mob_id': mob_id,
                'position': {'x': x, 'y': y, 'z': z},
                'timestamp': time.time()
            }
        except:
            return None
    
    def handle_new_chest(self, data: bytes) -> Optional[Dict]:
        """Handle new chest OpCode"""
        if len(data) < 16:
            return None
        
        try:
            chest_id = struct.unpack('<I', data[0:4])[0]
            x = struct.unpack('<f', data[4:8])[0]
            y = struct.unpack('<f', data[8:12])[0]
            z = struct.unpack('<f', data[12:16])[0] if len(data) >= 16 else 0
            
            return {
                'type': 'chest_spawn',
                'chest_id': chest_id,
                'position': {'x': x, 'y': y, 'z': z},
                'timestamp': time.time()
            }
        except:
            return None
    
    def handle_cluster_change(self, data: bytes) -> Optional[Dict]:
        """Handle cluster/zone change OpCode - MISSING METHOD FIXED"""
        if len(data) < 8:
            return None
        
        try:
            # Extract cluster/zone information
            cluster_id = struct.unpack('<I', data[0:4])[0] if len(data) >= 4 else 0
            zone_type = struct.unpack('<I', data[4:8])[0] if len(data) >= 8 else 0
            
            return {
                'type': 'cluster_change',
                'cluster_id': cluster_id,
                'zone_type': zone_type,
                'timestamp': time.time()
            }
        except:
            return None
    
    def handle_floor_change(self, data: bytes) -> Optional[Dict]:
        """Handle floor change OpCode - MISSING METHOD FIXED"""
        if len(data) < 4:
            return None
        
        try:
            # Extract floor information
            floor_id = struct.unpack('<I', data[0:4])[0] if len(data) >= 4 else 0
            floor_type = struct.unpack('<I', data[4:8])[0] if len(data) >= 8 else 0
            
            return {
                'type': 'floor_change',
                'floor_id': floor_id,
                'floor_type': floor_type,
                'timestamp': time.time()
            }
        except:
            return None
    
    def handle_new_chest(self, data: bytes) -> Optional[Dict]:
        """Handle new chest OpCode"""
        if len(data) < 16:
            return None
        
        try:
            chest_id = struct.unpack('<I', data[0:4])[0]
            x = struct.unpack('<f', data[4:8])[0]
            y = struct.unpack('<f', data[8:12])[0]
            z = struct.unpack('<f', data[12:16])[0] if len(data) >= 16 else 0
            
            return {
                'type': 'chest_spawn',
                'chest_id': chest_id,
                'position': {'x': x, 'y': y, 'z': z},
                'timestamp': time.time()
            }
        except:
            return None

class WebSocketBridge:
    """WebSocket server for real-time visualization"""
    
    def __init__(self, scanner):
        self.scanner = scanner
        self.clients = set()
        self.server = None
        
    async def register_client(self, websocket, path):
        """Register new WebSocket client"""
        self.clients.add(websocket)
        logger.info(f"WebSocket client connected: {websocket.remote_address}")
        
        # Send current state
        await self.send_current_state(websocket)
        
        try:
            async for message in websocket:
                data = json.loads(message)
                await self.handle_client_message(websocket, data)
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            self.clients.remove(websocket)
            logger.info("WebSocket client disconnected")
    
    async def send_current_state(self, websocket):
        """Send current scanner state"""
        unique_entities = self.scanner.dedup_manager.get_unique_entities()
        
        state_data = {
            'type': 'full_state',
            'timestamp': datetime.now().isoformat(),
            'dungeon_state': self.scanner.dungeon_state,
            'unique_entities': [entity for entity in unique_entities.values()],
            'avalonian_floors': {fid: asdict(floor) for fid, floor in self.scanner.avalonian_tracker.floors.items()},
            'stats': {
                **self.scanner.stats,
                'unique_mobs': list(self.scanner.stats['unique_mobs']),
                'unique_chests': list(self.scanner.stats['unique_chests'])
            }
        }
        
        await websocket.send(json.dumps(state_data, default=str))
    
    async def broadcast_update(self, update_data):
        """Broadcast update to all clients"""
        if not self.clients:
            return
        
        message = json.dumps(update_data, default=str)
        disconnected = set()
        
        for client in self.clients:
            try:
                await client.send(message)
            except websockets.exceptions.ConnectionClosed:
                disconnected.add(client)
        
        self.clients -= disconnected

class CompleteAlbionScanner:
    """Complete Albion Online Dungeon Scanner v4.0"""
    
    def __init__(self):
        # Network configuration
        self.interface = r"\Device\NPF_{6B3C185F-8A6A-48FA-89E8-F4E0E10196E0}"
        self.client_ip = "192.168.143.243"
        self.albion_servers = {"13.35.238.120", "5.45.187.30", "35.174.127.31"}
        
        # Core components
        self.dedup_manager = EnhancedDeduplicationManager()
        self.avalonian_tracker = AvalonianDungeonTracker()
        self.opcode_detector = OpCodeDetector()
        self.websocket_bridge = WebSocketBridge(self)
        
        # Enhanced detection patterns
        self.entity_patterns = {
            'mobs': [
                b'MOB_', b'CREATURE_', b'MONSTER_', b'BEAST_',
                b'HERETIC_ARCHER_', b'HERETIC_HEALER_', b'HERETIC_MAGE_',
                b'KEEPER_', b'AVALONIAN_', b'BANDIT_', b'UNDEAD_',
                b'MORGANA_', b'DEMON_', b'ELEMENTAL_'
            ],
            'chests': [
                b'CHEST_', b'TREASURE_', b'_CHEST_', b'SOLO_CHEST_',
                b'GROUP_CHEST_', b'HERETIC_SOLO_CHEST_', b'BOOK_CHEST',
                b'AVALONIAN_CHEST_', b'CRYSTAL_CHEST_', b'ENERGY_CHEST_'
            ],
            'shrines': [
                b'SHRINE_', b'AVALONIAN_SHRINE_', b'ALTAR_'
            ],
            'bosses': [
                b'_BOSS_', b'_VETERAN_BOSS_', b'_ANCIENT_', b'_LORD_',
                b'_CHAMPION_', b'_GUARDIAN_'
            ]
        }
        
        # Game state
        self.dungeon_state = {
            'in_dungeon': False,
            'dungeon_type': 'Unknown',
            'floor': 0,
            'entities': {},
            'player_pos': {'x': 0, 'y': 0, 'z': 0},
            'last_update': time.time(),
            'session_id': f"session_{int(time.time())}"
        }
        
        # Enhanced statistics
        self.stats = {
            'session_start': time.time(),
            'packets_analyzed': 0,
            'entities_detected': 0,
            'unique_entities': 0,
            'duplicates_filtered': 0,
            'opcodes_detected': 0,
            'floors_discovered': 0,
            'shrines_activated': 0,
            'bosses_killed': 0,
            'chests_looted': 0,
            'unique_mobs': set(),
            'unique_chests': set(),
            'detection_rate': 0,
            'opcode_success_rate': 0
        }
        
        # Runtime control
        self.scanner_active = False
        self.websocket_server = None
        
    def advanced_entity_detection(self, payload: bytes) -> List[Dict]:
        """Advanced entity detection combining patterns and OpCodes"""
        detected_entities = []
        
        # Method 1: OpCode detection (highest priority)
        opcodes = self.opcode_detector.detect_opcodes(payload)
        for opcode_data in opcodes:
            self.stats['opcodes_detected'] += 1
            
            if opcode_data['opcode'] in self.opcode_detector.opcode_handlers:
                handler = self.opcode_detector.opcode_handlers[opcode_data['opcode']]
                entity_info = handler(opcode_data['data'])
                
                if entity_info:
                    entity_info['detection_method'] = 'opcode'
                    entity_info['opcode'] = opcode_data['opcode']
                    detected_entities.append(entity_info)
        
        # Method 2: Pattern detection (fallback)
        if not detected_entities:  # Only if OpCode detection didn't find anything
            pattern_entities = self.pattern_based_detection(payload)
            detected_entities.extend(pattern_entities)
        
        # Process through deduplication
        unique_entities = []
        current_floor = self.avalonian_tracker.current_floor_id
        
        for entity_info in detected_entities:
            is_dup, entity_hash, dup_reason = self.dedup_manager.is_duplicate(
                entity_info.get('name', entity_info.get('detected_name', 'Unknown')),
                entity_info.get('position'),
                entity_info.get('type', 'unknown'),
                current_floor
            )
            
            if is_dup:
                self.dedup_manager.update_entity(entity_hash)
                self.stats['duplicates_filtered'] += 1
            else:
                entity_hash = self.dedup_manager.add_entity(
                    entity_info.get('name', entity_info.get('detected_name', 'Unknown')),
                    entity_info.get('position'),
                    entity_info.get('type', 'unknown'),
                    current_floor
                )
                entity_info['unique_hash'] = entity_hash
                unique_entities.append(entity_info)
        
        return unique_entities
    
    def pattern_based_detection(self, payload: bytes) -> List[Dict]:
        """Pattern-based entity detection"""
        detected_entities = []
        
        for entity_type in ['chests', 'bosses', 'mobs', 'shrines']:
            patterns = self.entity_patterns.get(entity_type, [])
            for pattern in patterns:
                if pattern in payload:
                    entity_info = self.extract_entity_info(payload, pattern, entity_type)
                    if entity_info:
                        entity_info['detection_method'] = 'pattern'
                        detected_entities.append(entity_info)
        
        return detected_entities
    
    def extract_entity_info(self, payload: bytes, pattern: bytes, entity_type: str) -> Optional[Dict]:
        """Extract entity information from pattern match"""
        try:
            pattern_pos = payload.find(pattern)
            if pattern_pos == -1:
                return None
            
            # Extract name
            entity_name = self.extract_entity_name(payload, pattern_pos, pattern)
            if not entity_name:
                return None
            
            # Determine actual type
            actual_type = self.determine_entity_type(entity_name, entity_type)
            
            # Extract position
            position = self.extract_position(payload, pattern_pos)
            
            # Enhanced classification
            classification = self.get_enhanced_classification(entity_name, actual_type)
            
            entity_info = {
                'detected_name': entity_name,
                'display_name': self.get_display_name(entity_name),
                'name': entity_name,  # For compatibility
                'type': actual_type,
                'classification': classification,
                'detected_at': time.time(),
                'timestamp': datetime.now().strftime("%H:%M:%S.%f")[:-3],
                'enhanced_info': self.get_enhanced_data(entity_name, actual_type)
            }
            
            if position:
                entity_info['position'] = position
                entity_info['distance_from_player'] = self.calculate_distance(
                    position, self.dungeon_state['player_pos']
                )
            
            return entity_info
            
        except Exception as e:
            logger.error(f"Error extracting entity info: {e}")
            return None
    
    def extract_entity_name(self, payload: bytes, pattern_pos: int, pattern: bytes) -> Optional[str]:
        """Extract entity name from payload"""
        try:
            name_start = pattern_pos
            name_end = name_start
            max_name_length = 60
            
            while (name_end < len(payload) and 
                   name_end - name_start < max_name_length and 
                   payload[name_end] != 0):
                char = payload[name_end]
                if not (32 <= char <= 126):
                    break
                name_end += 1
            
            if name_end > name_start + 3:
                entity_name = payload[name_start:name_end].decode('utf-8', 'ignore')
                entity_name = entity_name.strip().rstrip('\x00')
                if len(entity_name) >= 3:
                    return entity_name
            
            return pattern.decode('utf-8', 'ignore').strip()
            
        except:
            return None
    
    def extract_position(self, payload: bytes, reference_pos: int) -> Optional[Dict]:
        """Extract position coordinates"""
        try:
            search_start = max(0, reference_pos - 80)
            search_end = min(len(payload), reference_pos + 80)
            search_region = payload[search_start:search_end]
            
            # Look for 3D coordinates (12 bytes)
            for i in range(0, len(search_region) - 11, 4):
                if i + 12 <= len(search_region):
                    try:
                        x = struct.unpack('<f', search_region[i:i+4])[0]
                        y = struct.unpack('<f', search_region[i+4:i+8])[0]
                        z = struct.unpack('<f', search_region[i+8:i+12])[0]
                        
                        if (all(-3000 < coord < 3000 for coord in [x, y, z]) and
                            all(abs(coord) > 0.01 for coord in [x, y, z])):
                            
                            return {
                                'x': round(x, 2),
                                'y': round(y, 2),
                                'z': round(z, 2)
                            }
                    except:
                        continue
            
            # Fallback to 2D coordinates
            for i in range(0, len(search_region) - 7, 4):
                if i + 8 <= len(search_region):
                    try:
                        x = struct.unpack('<f', search_region[i:i+4])[0]
                        y = struct.unpack('<f', search_region[i+4:i+8])[0]
                        
                        if (all(-3000 < coord < 3000 for coord in [x, y]) and
                            all(abs(coord) > 0.01 for coord in [x, y])):
                            
                            return {
                                'x': round(x, 2),
                                'y': round(y, 2),
                                'z': 0.0
                            }
                    except:
                        continue
            
        except:
            pass
        
        return None
    
    def determine_entity_type(self, entity_name: str, suggested_type: str) -> str:
        """Determine actual entity type"""
        name_lower = entity_name.lower()
        
        if any(chest_pattern in name_lower for chest_pattern in ['chest', 'treasure', 'loot']):
            return 'chests'
        elif any(boss_pattern in name_lower for boss_pattern in ['boss', 'veteran', 'ancient', 'lord', 'champion']):
            return 'bosses'
        elif any(shrine_pattern in name_lower for shrine_pattern in ['shrine', 'altar']):
            return 'shrines'
        else:
            return 'mobs'
    
    def get_enhanced_classification(self, entity_name: str, entity_type: str) -> str:
        """Get enhanced classification with icons"""
        name_lower = entity_name.lower()
        
        if entity_type == 'chests':
            if 'legendary' in name_lower or 'gold' in name_lower:
                return '🏆 LEGENDARY CHEST'
            elif 'epic' in name_lower:
                return '🟣 EPIC CHEST'
            elif 'rare' in name_lower:
                return '🔵 RARE CHEST'
            elif 'uncommon' in name_lower:
                return '🟢 UNCOMMON CHEST'
            elif 'book' in name_lower:
                return '📚 BOOK CHEST'
            elif 'crystal' in name_lower or 'energy' in name_lower:
                return '💎 CRYSTAL CHEST'
            else:
                return '📦 STANDARD CHEST'
        
        elif entity_type == 'bosses':
            if 'ancient' in name_lower:
                return '💀 ANCIENT BOSS'
            elif 'veteran' in name_lower:
                return '👑 VETERAN BOSS'
            elif 'lord' in name_lower or 'champion' in name_lower:
                return '⚔️ ELITE BOSS'
            elif 'guardian' in name_lower:
                return '🛡️ GUARDIAN BOSS'
            else:
                return '👑 BOSS'
        
        elif entity_type == 'mobs':
            if 'heretic' in name_lower:
                return '🔥 HERETIC'
            elif 'keeper' in name_lower:
                return '🛡️ KEEPER'
            elif 'avalonian' in name_lower:
                return '⚪ AVALONIAN'
            elif 'morgana' in name_lower:
                return '🌙 MORGANA'
            elif 'demon' in name_lower:
                return '😈 DEMON'
            else:
                return '👹 MOB'
        
        elif entity_type == 'shrines':
            if 'combat' in name_lower:
                return '⚔️ COMBAT SHRINE'
            elif 'loot' in name_lower:
                return '💰 LOOT SHRINE'
            elif 'energy' in name_lower:
                return '⚡ ENERGY SHRINE'
            else:
                return '⭐ SHRINE'
        
        return '❓ UNKNOWN'
    
    def get_display_name(self, entity_name: str) -> str:
        """Get human-readable display name"""
        return entity_name.replace('_', ' ').title()
    
    def get_enhanced_data(self, entity_name: str, entity_type: str) -> Dict:
        """Get enhanced entity data"""
        name_lower = entity_name.lower()
        
        base_data = {
            'display_name': self.get_display_name(entity_name),
            'unique_name': entity_name,
            'type': self.get_enhanced_classification(entity_name, entity_type),
            'threat_level': 'Unknown',
            'health': 0,
            'damage': 0,
            'tier': 0,
            'faction': 'Unknown'
        }
        
        # Enhanced faction detection
        if 'heretic' in name_lower:
            base_data['faction'] = 'Heretic'
            base_data['threat_level'] = 'High'
            base_data['tier'] = 5
        elif 'keeper' in name_lower:
            base_data['faction'] = 'Keeper'
            base_data['threat_level'] = 'Medium'
            base_data['tier'] = 4
        elif 'avalonian' in name_lower:
            base_data['faction'] = 'Avalonian'
            base_data['threat_level'] = 'Very High'
            base_data['tier'] = 7
        elif 'morgana' in name_lower:
            base_data['faction'] = 'Morgana'
            base_data['threat_level'] = 'High'
            base_data['tier'] = 6
        
        # Enhanced threat assessment
        if 'veteran' in name_lower or 'boss' in name_lower:
            base_data['threat_level'] = 'Very High'
            base_data['tier'] = max(base_data['tier'], 6)
        elif 'ancient' in name_lower or 'lord' in name_lower:
            base_data['threat_level'] = 'Extreme'
            base_data['tier'] = max(base_data['tier'], 8)
        
        return base_data
    
    def calculate_distance(self, pos1: Dict, pos2: Dict) -> float:
        """Calculate 3D distance"""
        try:
            dx = pos1.get('x', 0) - pos2.get('x', 0)
            dy = pos1.get('y', 0) - pos2.get('y', 0)
            dz = pos1.get('z', 0) - pos2.get('z', 0)
            return round((dx**2 + dy**2 + dz**2)**0.5, 1)
        except:
            return 0
    
    def display_complete_ui(self):
        """Display complete enhanced UI"""
        while self.scanner_active:
            import os
            os.system('cls' if os.name == 'nt' else 'clear')
            
            print("🚀 COMPLETE ALBION DUNGEON SCANNER v4.0")
            print("=" * 80)
            
            # Session overview
            runtime = time.time() - self.stats['session_start']
            unique_entities = self.dedup_manager.get_unique_entities()
            dedup_stats = self.dedup_manager.get_stats()
            
            print(f"⏱️  Runtime: {runtime:.1f}s | 📦 Packets: {self.stats['packets_analyzed']:,}")
            print(f"🎮 Detection Rate: {self.stats['detection_rate']:.1f}/min | 🔧 OpCodes: {self.stats['opcodes_detected']}")
            print(f"🔄 Dedup: {len(unique_entities)} unique | {self.stats['duplicates_filtered']} filtered")
            if self.stats['opcodes_detected'] > 0:
                success_rate = (self.stats['entities_detected'] / self.stats['opcodes_detected']) * 100
                print(f"📊 OpCode Success Rate: {success_rate:.1f}%")
            
            # Dungeon status
            print(f"\n🏰 DUNGEON STATUS")
            print("-" * 50)
            print(f"📍 In Dungeon: {'Yes' if self.dungeon_state['in_dungeon'] else 'No'}")
            print(f"🗺️  Type: {self.dungeon_state['dungeon_type']}")
            print(f"🏢 Floor: {self.avalonian_tracker.current_floor_id}")
            print(f"📡 Session: {self.dungeon_state['session_id']}")
            
            # Player position
            pos = self.dungeon_state['player_pos']
            print(f"🚶 Player: ({pos['x']:.1f}, {pos['y']:.1f}, {pos.get('z', 0):.1f})")
            
            # Avalonian floors summary
            if self.avalonian_tracker.floors:
                print(f"\n🏗️  AVALONIAN FLOORS ({len(self.avalonian_tracker.floors)})")
                print("-" * 30)
                for floor_id, floor_data in list(self.avalonian_tracker.floors.items())[-3:]:
                    entity_count = len(floor_data.entities)
                    status = "✅ Complete" if floor_data.completed else "🔄 Active"
                    print(f"   Floor {floor_id}: {entity_count} entities | {status}")
            
            # Unique entities display
            print(f"\n👁️ UNIQUE LIVE ENTITIES ({len(unique_entities)})")
            print("-" * 50)
            
            # Group by type
            entities_by_type = defaultdict(list)
            for entity_hash, entity_data in unique_entities.items():
                entities_by_type[entity_data['type']].append(entity_data)
            
            for entity_type in ['chests', 'bosses', 'mobs', 'shrines']:
                entities = entities_by_type.get(entity_type, [])
                if entities:
                    type_icons = {'chests': '📦', 'bosses': '👑', 'mobs': '👹', 'shrines': '⭐'}
                    print(f"\n{type_icons[entity_type]} {entity_type.upper()} ({len(entities)}):")
                    
                    for entity in entities[-8:]:  # Show last 8 per type
                        name = entity['detected_name'][:30]
                        count = entity['detection_count']
                        last_seen = time.time() - entity['last_seen']
                        
                        if entity.get('position'):
                            pos = entity['position']
                            distance = self.calculate_distance(pos, self.dungeon_state['player_pos'])
                            print(f"  {name} | {count}x | {distance}m | {last_seen:.0f}s ago")
                        else:
                            print(f"  {name} | {count}x | {last_seen:.0f}s ago")
            
            # Advanced statistics
            print(f"\n📊 ADVANCED SESSION STATISTICS")
            print("-" * 40)
            print(f"🎯 Unique Entities: {len(unique_entities)}")
            print(f"📊 Total Detections: {self.stats['entities_detected']}")
            print(f"🔄 Duplicates Filtered: {self.stats['duplicates_filtered']}")
            print(f"🏗️  Floors Discovered: {len(self.avalonian_tracker.floors)}")
            print(f"⭐ Shrines Activated: {self.stats['shrines_activated']}")
            print(f"💰 Chests Looted: {self.stats['chests_looted']}")
            
            # WebSocket status
            if self.websocket_bridge.clients:
                print(f"🌐 WebSocket Clients: {len(self.websocket_bridge.clients)}")
            
            print(f"\n🔄 Complete Scanner Active... (Ctrl+C to stop)")
            print(f"🌐 WebSocket: ws://localhost:8765 | 📊 Real-time visualization available")
            
            time.sleep(2)
    
    def enhanced_packet_handler(self, packet):
        """Enhanced packet handler with all features"""
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
        
        # Check for Avalonian floor transitions
        floor_change = self.avalonian_tracker.detect_floor_transition(payload)
        if floor_change:
            self.stats['floors_discovered'] += 1
        
        # Advanced entity detection
        detected_entities = self.advanced_entity_detection(payload)
        
        for entity in detected_entities:
            self.stats['entities_detected'] += 1
            self.stats['unique_entities'] += 1
            
            # Track by type
            if entity['type'] == 'mobs':
                self.stats['unique_mobs'].add(entity['detected_name'])
            elif entity['type'] == 'chests':
                self.stats['unique_chests'].add(entity['detected_name'])
            elif entity['type'] == 'shrines':
                self.stats['shrines_activated'] += 1
            
            # Update detection rate
            runtime = time.time() - self.stats['session_start']
            if runtime > 0:
                self.stats['detection_rate'] = (self.stats['entities_detected'] / runtime) * 60
            
            # Broadcast via WebSocket
            if self.websocket_bridge.clients:
                asyncio.run_coroutine_threadsafe(
                    self.websocket_bridge.broadcast_update({
                        'type': 'entity_update',
                        'entity': entity,
                        'timestamp': datetime.now().isoformat()
                    }),
                    asyncio.get_event_loop()
                )
        
        # Update player position
        self.update_player_position(payload)
    
    def update_player_position(self, payload: bytes):
        """Update player position"""
        position = self.extract_position(payload, 0)
        if position:
            old_pos = self.dungeon_state['player_pos']
            distance_moved = self.calculate_distance(position, old_pos)
            
            if 0.5 < distance_moved < 150:  # Reasonable movement
                self.dungeon_state['player_pos'] = position
                self.dungeon_state['last_update'] = time.time()
                
                # Broadcast player movement
                if self.websocket_bridge.clients:
                    asyncio.run_coroutine_threadsafe(
                        self.websocket_bridge.broadcast_update({
                            'type': 'player_movement',
                            'position': position,
                            'timestamp': datetime.now().isoformat()
                        }),
                        asyncio.get_event_loop()
                    )
                
                return True
        return False
    
    async def start_websocket_server(self, port=8765):
        """Start WebSocket server"""
        self.websocket_server = await websockets.serve(
            self.websocket_bridge.register_client,
            "localhost",
            port
        )
        logger.info(f"WebSocket server started on ws://localhost:{port}")
        
    def run_complete_scanner(self, duration=None, websocket_port=8765):
        """Run the complete scanner with all features"""
        print("🚀 STARTING COMPLETE ALBION SCANNER v4.0")
        print("=" * 70)
        print("Features enabled:")
        print("  ✅ Advanced Deduplication with Database")
        print("  ✅ Avalonian Multi-Floor Support")
        print("  ✅ OpCode Detection (Photon Protocol)")
        print("  ✅ WebSocket Real-time Visualization")
        print("  ✅ Advanced Analytics & Reporting")
        print("  ✅ Professional UI with Live Statistics")
        print()
        
        self.scanner_active = True
        
        # Start WebSocket server
        async def start_websocket():
            await self.start_websocket_server(websocket_port)
            
        websocket_thread = threading.Thread(
            target=lambda: asyncio.run(start_websocket()),
            daemon=True
        )
        websocket_thread.start()
        
        # Start UI thread
        ui_thread = threading.Thread(target=self.display_complete_ui, daemon=True)
        ui_thread.start()
        
        # Give server time to start
        time.sleep(1)
        
        try:
            # Create enhanced filter
            server_filter = ' or '.join([f'host {server}' for server in self.albion_servers])
            bpf_filter = f"udp and (({server_filter}) or host {self.client_ip})"
            
            print(f"🌐 WebSocket server: ws://localhost:{websocket_port}")
            print(f"🎯 Starting packet capture...")
            print(f"📊 Open browser to see real-time visualization!")
            print()
            
            # Start packet capture
            sniff(
                iface=self.interface,
                filter=bpf_filter,
                prn=self.enhanced_packet_handler,
                timeout=duration,
                store=0
            )
            
        except KeyboardInterrupt:
            print(f"\n⏹️ Complete scanner stopped by user")
        except Exception as e:
            print(f"\n❌ Scanner error: {e}")
            logger.error(f"Scanner error: {e}")
        finally:
            self.scanner_active = False
            if self.websocket_server:
                self.websocket_server.close()
            self.save_complete_results()
    
    def save_complete_results(self):
        """Save comprehensive scan results"""
        try:
            unique_entities = self.dedup_manager.get_unique_entities()
            dedup_stats = self.dedup_manager.get_stats()
            
            results = {
                'scanner_version': '4.0',
                'features_enabled': [
                    'advanced_deduplication',
                    'avalonian_multi_floor',
                    'opcode_detection', 
                    'websocket_integration',
                    'advanced_analytics'
                ],
                'timestamp': time.time(),
                'session_duration': time.time() - self.stats['session_start'],
                'session_id': self.dungeon_state['session_id'],
                
                # Enhanced statistics
                'advanced_stats': {
                    **self.stats,
                    'unique_mobs': list(self.stats['unique_mobs']),
                    'unique_chests': list(self.stats['unique_chests']),
                    'dedup_stats': dedup_stats,
                    'opcode_success_rate': (self.stats['entities_detected'] / max(self.stats['opcodes_detected'], 1)) * 100
                },
                
                # Game state
                'dungeon_state': self.dungeon_state,
                
                # Avalonian floors
                'avalonian_floors': {
                    fid: asdict(floor) for fid, floor in self.avalonian_tracker.floors.items()
                },
                
                # Unique entities with metadata
                'unique_entities': [
                    {**entity_data, 'entity_hash': entity_hash}
                    for entity_hash, entity_data in unique_entities.items()
                ],
                
                # Technical details
                'interface_used': self.interface,
                'servers_monitored': list(self.albion_servers),
                'websocket_clients_connected': len(self.websocket_bridge.clients)
            }
            
            filename = f"complete_albion_scan_v4_{int(time.time())}.json"
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"\n💾 Complete results saved to: {filename}")
            print(f"📊 FINAL SUMMARY:")
            print(f"   🎯 Unique Entities: {len(unique_entities)}")
            print(f"   📊 Total Detections: {self.stats['entities_detected']}")
            print(f"   🔄 Duplicates Filtered: {self.stats['duplicates_filtered']} ({dedup_stats.get('duplicate_rate', 0):.1f}%)")
            print(f"   🔧 OpCodes Detected: {self.stats['opcodes_detected']}")
            print(f"   🏗️  Floors Discovered: {len(self.avalonian_tracker.floors)}")
            print(f"   ⭐ Shrines Activated: {self.stats['shrines_activated']}")
            
        except Exception as e:
            print(f"⚠️ Could not save results: {e}")
            logger.error(f"Save error: {e}")

def main():
    """Main entry point"""
    print("🚀 COMPLETE ALBION ONLINE DUNGEON SCANNER SUITE v4.0")
    print("=" * 70)
    print("This is the most advanced Albion dungeon scanner available!")
    print()
    print("Requirements check:")
    print("  📦 Scapy: ", end="")
    try:
        import scapy
        print("✅ Installed")
    except ImportError:
        print("❌ Missing - run: pip install scapy")
        return
    
    print("  🌐 WebSockets: ", end="")
    try:
        import websockets
        print("✅ Installed")
    except ImportError:
        print("❌ Missing - run: pip install websockets")
        return
    
    print()
    print("🎯 Starting complete scanner...")
    
    scanner = CompleteAlbionScanner()
    scanner.run_complete_scanner(websocket_port=8765)

if __name__ == "__main__":
    main()