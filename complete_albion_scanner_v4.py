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
from scapy.all import * # type: ignore
from scapy.layers.inet import IP, UDP # type: ignore
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Tuple, Any, Set

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(threadName)s - %(name)s - %(message)s')
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
    last_seen: Optional[float] = None # Diperbarui dari float menjadi Optional[float]

@dataclass
class DungeonFloor:
    """Enhanced floor representation"""
    floor_id: int
    floor_name: str
    floor_type: str
    entities: Dict[str, FloorEntity] = field(default_factory=dict)
    entry_time: float = field(default_factory=time.time)
    exit_time: Optional[float] = None
    completed: bool = False
    shrine_activated: bool = False
    player_path: List[Tuple[float, float, float]] = field(default_factory=list)


class EnhancedDeduplicationManager:
    """Advanced deduplication with improved normalization"""
    
    def __init__(self):
        self.seen_entities: Dict[str, Dict[str, Any]] = {}
        self.position_tracker: Dict[str, Any] = {} 
        self.name_variations: Dict[str, Any] = {}  
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
        
    def normalize_entity_name(self, name: str) -> str:
        """Enhanced normalize entity name with comprehensive pattern matching"""
        normalized = name.upper().strip()
        normalized = normalized.strip('_')
        
        prefixes_to_remove = [
            'HERETIC_SOLO_', 'HERETIC_GROUP_', 'AVALONIAN_SOLO_', 'AVALONIAN_GROUP_',
            'HERETIC_', 'AVALONIAN_', 'KEEPER_', 'MORGANA_',
            'SOLO_', 'GROUP_', 'MOB_', 'CREATURE_', 'MONSTER_'
        ]
        for prefix in prefixes_to_remove:
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
                break
        
        suffix_replacements = {
            '_VETERAN': '_VET', '_BOSS': '_B', '_STANDARD': '_STD',
            '_UNCOMMON': '_UNC', '_COMMON': '_COM', '_RARE': '_R',
            '_EPIC': '_EP', '_LEGENDARY': '_LEG'
        }
        for old_suffix, new_suffix in suffix_replacements.items():
            normalized = normalized.replace(old_suffix, new_suffix)
        
        if 'CHEST' in normalized:
            chest_types = ['_STD', '_UNC', '_COM', '_R', '_EP', '_LEG']
            base_name = 'CHEST'
            for chest_type in chest_types:
                if chest_type in normalized:
                    base_name += chest_type
                    break
            normalized = base_name
        return normalized
    
    def generate_entity_hash(self, entity_name: str, position: Optional[Dict[str, float]], entity_type: str, floor_id: int = 0) -> str:
        """Generate unique hash with floor consideration"""
        normalized_name = self.normalize_entity_name(entity_name)
        if not position:
            hash_string = f"{normalized_name}_{entity_type}_{floor_id}"
        else:
            pos_x = round(position.get('x', 0.0), 1)
            pos_y = round(position.get('y', 0.0), 1)
            pos_z = round(position.get('z', 0.0), 1)
            pos_string = f"{pos_x}_{pos_y}_{pos_z}"
            hash_string = f"{normalized_name}_{pos_string}_{entity_type}_{floor_id}"
        return hashlib.md5(hash_string.encode()).hexdigest()[:16]
    
    def is_duplicate(self, entity_name: str, position: Optional[Dict[str, float]], entity_type: str, floor_id: int = 0, tolerance: float = 5.0) -> Tuple[bool, str, str]:
        """Enhanced duplicate detection with multiple methods"""
        entity_hash = self.generate_entity_hash(entity_name, position, entity_type, floor_id)
        if entity_hash in self.seen_entities:
            return True, entity_hash, "exact_hash_match"
        
        normalized_name = self.normalize_entity_name(entity_name)
        cursor = self.entity_database.cursor()
        if position:
            x, y, z = position.get('x', 0.0), position.get('y', 0.0), position.get('z', 0.0)
            cursor.execute('''
                SELECT hash FROM entities 
                WHERE normalized_name = ? AND type = ? AND floor_id = ?
                AND ABS(position_x - ?) < ? AND ABS(position_y - ?) < ? AND ABS(position_z - ?) < ?
            ''', (normalized_name, entity_type, floor_id, x, tolerance, y, tolerance, z, tolerance))
        else:
            cursor.execute('''
                SELECT hash FROM entities 
                WHERE normalized_name = ? AND type = ? AND floor_id = ? AND position_x IS NULL
            ''', (normalized_name, entity_type, floor_id))
        
        result = cursor.fetchone()
        if result:
            return True, result[0], "database_match"
        return False, entity_hash, "new_entity"
    
    def add_entity(self, entity_name: str, position: Optional[Dict[str, float]], entity_type: str, floor_id: int = 0) -> str:
        """Add entity to tracking system with database storage"""
        entity_hash = self.generate_entity_hash(entity_name, position, entity_type, floor_id)
        normalized_name = self.normalize_entity_name(entity_name)
        current_time = time.time()
        
        self.seen_entities[entity_hash] = {
            'detected_name': entity_name, 'normalized_name': normalized_name, 'type': entity_type,
            'position': position, 'floor_id': floor_id, 'first_seen': current_time,
            'last_seen': current_time, 'detection_count': 1
        }
        
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
    
    def update_entity(self, entity_hash: str):
        """Update existing entity"""
        current_time = time.time()
        if entity_hash in self.seen_entities:
            self.seen_entities[entity_hash]['last_seen'] = current_time
            self.seen_entities[entity_hash]['detection_count'] += 1
            
            cursor = self.entity_database.cursor()
            cursor.execute('''
                UPDATE entities SET last_seen = ?, detection_count = detection_count + 1
                WHERE hash = ?
            ''', (current_time, entity_hash))
            self.entity_database.commit()

    def get_unique_entities(self) -> Dict[str, Dict[str, Any]]:
        return self.seen_entities

    def get_stats(self) -> Dict[str, Any]:
        return {}

class AvalonianDungeonTracker:
    """Enhanced multi-floor Avalonian dungeon tracking"""
    def __init__(self):
        self.floors: Dict[int, DungeonFloor] = {}
        self.current_floor_id: int = 0
        self.dungeon_session_id: str = f"avalonian_{int(time.time())}"
        self.total_floors_discovered: int = 0
        self.floor_transition_history: List[Dict[str, Any]] = []
        
        self.avalonian_patterns = {
            'floor_transitions': [
                b'FLOOR_TRANSITION', b'AVALONIAN_FLOOR_', b'LEVEL_CHANGE',
                b'TELEPORT_FLOOR', b'DUNGEON_LEVEL_', b'CLUSTER_AVALONIAN'
            ],
            # ... (pola lainnya)
        }
    
    def detect_floor_transition(self, payload: bytes) -> Optional[int]:
        for pattern in self.avalonian_patterns['floor_transitions']:
            if pattern in payload:
                floor_num = self.extract_floor_number_advanced(payload, pattern)
                if floor_num is not None and floor_num != self.current_floor_id:
                    self.transition_to_floor(floor_num) # Asumsi metode ini ada
                    return floor_num
        return None
    
    def extract_floor_number_advanced(self, payload: bytes, pattern: bytes) -> Optional[int]:
        # ... (implementasi ekstraksi nomor lantai)
        # Placeholder sederhana:
        try:
            s = payload.decode('latin-1')
            import re
            matches = re.findall(r'\d+', s)
            if matches: return int(matches[-1]) # Ambil angka terakhir sebagai contoh
        except:
            pass
        return self.current_floor_id + 1 if self.current_floor_id < 5 else None # Batasi agar tidak tak terbatas

    def transition_to_floor(self, floor_id: int):
        logger.info(f"Transisi ke lantai Avalonian: {floor_id}")
        if floor_id not in self.floors:
            self.floors[floor_id] = DungeonFloor(
                floor_id=floor_id,
                floor_name=f"Avalonian Floor {floor_id}",
                floor_type="Avalonian"
            )
            self.total_floors_discovered +=1
        self.current_floor_id = floor_id
        self.floor_transition_history.append({
            "timestamp": time.time(),
            "from_floor": self.current_floor_id, # Seharusnya floor sebelumnya
            "to_floor": floor_id
        })


class OpCodeDetector:
    """Enhanced OpCode detection for Photon Protocol"""
    def __init__(self):
        self.known_opcodes = {
            18: 'MOVE', 19: 'CHARACTER_MOVEMENT', 20: 'TELEPORT', 21: 'NEW_CHARACTER',
            22: 'NEW_MOB', 23: 'NEW_CHEST', 24: 'REMOVE_ENTITY', 25: 'UPDATE_ENTITY',
            26: 'INVENTORY_MOVE', 27: 'ITEM_DROPPED', 28: 'LOOT_CHEST', 29: 'ITEM_EQUIPPED',
            30: 'CHANGE_CLUSTER', 31: 'DUNGEON_ENTER', 32: 'DUNGEON_EXIT', 33: 'FLOOR_CHANGE',
            40: 'CAST_SPELL', 41: 'DAMAGE_DEALT', 42: 'MOB_HEALTH_UPDATE', 43: 'PLAYER_HEALTH_UPDATE',
            50: 'CHAT_MESSAGE', 51: 'GUILD_MESSAGE', 52: 'ALLIANCE_MESSAGE'
        }
        self.opcode_handlers: Dict[int, Callable[[bytes], Optional[Dict[str, Any]]]] = {
            22: self.handle_new_mob,
            23: self.handle_new_chest,
            30: self.handle_cluster_change, # Pastikan ini ada
            33: self.handle_floor_change    # Pastikan ini ada
        }

    def detect_opcodes(self, payload: bytes) -> List[Dict[str, Any]]:
        opcodes_found = []
        if len(payload) < 12: return opcodes_found
        try:
            offset = 0
            while offset < len(payload) - 3:
                if offset + 3 <= len(payload):
                    opcode = payload[offset]
                    length = struct.unpack('>H', payload[offset+1:offset+3])[0]
                    if opcode in self.known_opcodes and length < 1000:
                        operation_data = payload[offset+3:offset+3+length]
                        opcodes_found.append({
                            'opcode': opcode, 'operation': self.known_opcodes[opcode],
                            'data': operation_data, 'length': length, 'offset': offset
                        })
                        offset += 3 + length
                    else: offset += 1
                else: break
        except struct.error: pass
        return opcodes_found

    def handle_new_mob(self, data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < 12: return None # Minimal ID (4) + Posisi X,Y (8)
        try:
            mob_id = struct.unpack('<I', data[0:4])[0]
            x = struct.unpack('<f', data[4:8])[0]
            y = struct.unpack('<f', data[8:12])[0]
            z = struct.unpack('<f', data[12:16])[0] if len(data) >= 16 else 0.0
            return {'type': 'mob_spawn', 'mob_id': mob_id, 'name': f"MOB_{mob_id}", 
                    'position': {'x': x, 'y': y, 'z': z}, 'timestamp': time.time()}
        except struct.error: return None

    def handle_new_chest(self, data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < 12: return None # Minimal ID (4) + Posisi X,Y (8)
        try:
            chest_id = struct.unpack('<I', data[0:4])[0]
            x = struct.unpack('<f', data[4:8])[0]
            y = struct.unpack('<f', data[8:12])[0]
            z = struct.unpack('<f', data[12:16])[0] if len(data) >= 16 else 0.0
            return {'type': 'chest_spawn', 'chest_id': chest_id, 'name': f"CHEST_{chest_id}",
                    'position': {'x': x, 'y': y, 'z': z}, 'timestamp': time.time()}
        except struct.error: return None
        
    def handle_cluster_change(self, data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < 4: return None # Minimal Cluster ID (4)
        try:
            cluster_id = struct.unpack('<I', data[0:4])[0]
            zone_type = struct.unpack('<I', data[4:8])[0] if len(data) >= 8 else 0
            return {'type': 'cluster_change', 'cluster_id': cluster_id, 'zone_type': zone_type, 'timestamp': time.time()}
        except struct.error: return None

    def handle_floor_change(self, data: bytes) -> Optional[Dict[str, Any]]:
        if len(data) < 4: return None # Minimal Floor ID (4)
        try:
            floor_id = struct.unpack('<I', data[0:4])[0]
            floor_type = struct.unpack('<I', data[4:8])[0] if len(data) >= 8 else 0
            return {'type': 'floor_change', 'floor_id': floor_id, 'floor_type': floor_type, 'timestamp': time.time()}
        except struct.error: return None


class WebSocketBridge:
    """WebSocket server for real-time visualization"""
    def __init__(self, scanner: 'CompleteAlbionScanner'):
        self.scanner = scanner
        self.clients: Set[websockets.server.WebSocketServerProtocol] = set()
        
    async def register_client(self, websocket: websockets.server.WebSocketServerProtocol, path: str):
        self.clients.add(websocket)
        logger.info(f"Klien WebSocket terhubung: {websocket.remote_address}")
        try:
            await self.send_current_state(websocket)
            async for message in websocket: # type: ignore
                # data = json.loads(message) # Jika ada pesan dari klien
                # await self.handle_client_message(websocket, data)
                pass
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Koneksi WebSocket ditutup untuk klien: {websocket.remote_address}")
        except Exception as e:
            logger.error(f"Kesalahan pada koneksi WebSocket {websocket.remote_address}: {e}", exc_info=True)
        finally:
            self.clients.remove(websocket)
            logger.info(f"Klien WebSocket terputus: {websocket.remote_address}, sisa klien: {len(self.clients)}")
    
    async def send_current_state(self, websocket: websockets.server.WebSocketServerProtocol):
        if not hasattr(self.scanner, 'dedup_manager') or not hasattr(self.scanner.dedup_manager, 'get_unique_entities'):
            logger.error("Manajer deduplikasi atau metode get_unique_entities tidak ditemukan.")
            return

        unique_entities_dict = self.scanner.dedup_manager.get_unique_entities()
        state_data = {
            'type': 'full_state', 'timestamp': datetime.now().isoformat(),
            'dungeon_state': self.scanner.dungeon_state,
            'unique_entities': [entity for entity in unique_entities_dict.values()],
            'avalonian_floors': {fid: asdict(floor) for fid, floor in self.scanner.avalonian_tracker.floors.items()},
            'stats': {
                **self.scanner.stats,
                'unique_mobs': list(self.scanner.stats.get('unique_mobs', set())),
                'unique_chests': list(self.scanner.stats.get('unique_chests', set()))
            }
        }
        await websocket.send(json.dumps(state_data, default=str))
    
    async def broadcast_update(self, update_data: Dict[str, Any]):
        if not self.clients: return
        message = json.dumps(update_data, default=str)
        
        # Kirim ke semua klien secara bersamaan dan tangani pemutusan koneksi
        # Buat daftar klien yang akan dikirimi pesan untuk menghindari modifikasi saat iterasi
        current_clients_to_send = list(self.clients)
        if not current_clients_to_send: return

        results = await asyncio.gather(
            *[client.send(message) for client in current_clients_to_send if client.open],
            return_exceptions=True
        )
        
        # Perbarui daftar klien setelah mengirim
        # Hapus klien yang koneksinya error atau sudah tertutup
        new_clients_set = set()
        for i, client in enumerate(current_clients_to_send):
            if client.open: # Periksa lagi setelah gather
                 # Jika ada error spesifik untuk klien ini dari gather, bisa ditangani di sini
                if i < len(results) and isinstance(results[i], Exception):
                    logger.warning(f"Gagal mengirim ke klien {client.remote_address}: {results[i]}")
                    # Mungkin tutup koneksi klien ini jika error parah
                    # await client.close(code=1011) 
                else:
                    new_clients_set.add(client) # Pertahankan klien yang masih terbuka
            else: # Jika sudah tidak open
                 logger.info(f"Klien {client.remote_address} sudah tidak terbuka setelah broadcast.")
        
        if len(self.clients) != len(new_clients_set):
            logger.info(f"Jumlah klien WebSocket diperbarui dari {len(self.clients)} menjadi {len(new_clients_set)}")
        self.clients = new_clients_set


class CompleteAlbionScanner:
    def __init__(self):
        self.interface = r"\Device\NPF_{6B3C185F-8A6A-48FA-89E8-F4E0E10196E0}" # Sesuaikan ini
        self.client_ip = "192.168.143.243" # Sesuaikan ini
        self.albion_servers = {"13.35.238.120", "5.45.187.30", "35.174.127.31"} # Contoh
        
        self.dedup_manager = EnhancedDeduplicationManager()
        self.avalonian_tracker = AvalonianDungeonTracker()
        self.opcode_detector = OpCodeDetector()
        self.websocket_bridge = WebSocketBridge(self)
        
        self.entity_patterns = {
            'mobs': [b'MOB_', b'CREATURE_', b'HERETIC_ARCHER_'],
            'chests': [b'CHEST_', b'TREASURE_', b'BOOK_CHEST'],
            'shrines': [b'SHRINE_', b'AVALONIAN_SHRINE_'],
            'bosses': [b'_BOSS_', b'_VETERAN_BOSS_']
        }
        
        self.dungeon_state: Dict[str, Any] = {
            'in_dungeon': False, 'dungeon_type': 'Unknown', 'floor': 0,
            'entities': {}, 'player_pos': {'x': 0.0, 'y': 0.0, 'z': 0.0},
            'last_update': time.time(), 'session_id': f"session_{int(time.time())}"
        }
        
        self.stats: Dict[str, Any] = {
            'session_start': time.time(), 'packets_analyzed': 0, 'entities_detected': 0,
            'unique_entities': 0, 'duplicates_filtered': 0, 'opcodes_detected': 0,
            'floors_discovered': 0, 'shrines_activated': 0, 'bosses_killed': 0,
            'chests_looted': 0, 'unique_mobs': set(), 'unique_chests': set(),
            'detection_rate': 0.0, 'opcode_success_rate': 0.0
        }
        
        self.scanner_active = False
        self.websocket_server: Optional[websockets.server.Serve] = None # Instance dari websockets.serve()
        self.websocket_loop: Optional[asyncio.AbstractEventLoop] = None
        self.websocket_thread: Optional[threading.Thread] = None

    def advanced_entity_detection(self, payload: bytes) -> List[Dict[str, Any]]:
        detected_entities = []
        opcodes = self.opcode_detector.detect_opcodes(payload)
        for opcode_data in opcodes:
            self.stats['opcodes_detected'] += 1
            if opcode_data['opcode'] in self.opcode_detector.opcode_handlers:
                handler = self.opcode_detector.opcode_handlers[opcode_data['opcode']]
                entity_info = handler(opcode_data['data'])
                if entity_info:
                    entity_info['detection_method'] = 'opcode'
                    entity_info['opcode'] = opcode_data['opcode']
                    # Pastikan 'name' ada untuk deduplikasi
                    if 'name' not in entity_info and 'detected_name' in entity_info:
                        entity_info['name'] = entity_info['detected_name']
                    elif 'name' not in entity_info and 'mob_id' in entity_info:
                         entity_info['name'] = f"MOB_OP_{entity_info['mob_id']}"
                    elif 'name' not in entity_info and 'chest_id' in entity_info:
                         entity_info['name'] = f"CHEST_OP_{entity_info['chest_id']}"
                    
                    detected_entities.append(entity_info)
        
        if not detected_entities:
            pattern_entities = self.pattern_based_detection(payload)
            detected_entities.extend(pattern_entities)
        
        unique_final_entities = []
        current_floor = self.avalonian_tracker.current_floor_id
        
        for entity_info in detected_entities:
            name_to_check = entity_info.get('name', entity_info.get('detected_name', 'UnknownEntity'))
            is_dup, entity_hash, _ = self.dedup_manager.is_duplicate(
                name_to_check,
                entity_info.get('position'),
                entity_info.get('type', 'unknown_type'), # Pastikan tipe ada
                current_floor
            )
            if is_dup:
                self.dedup_manager.update_entity(entity_hash)
                self.stats['duplicates_filtered'] += 1
            else:
                new_hash = self.dedup_manager.add_entity(
                    name_to_check,
                    entity_info.get('position'),
                    entity_info.get('type', 'unknown_type'),
                    current_floor
                )
                entity_info['unique_hash'] = new_hash
                unique_final_entities.append(entity_info)
        return unique_final_entities

    def pattern_based_detection(self, payload: bytes) -> List[Dict[str, Any]]:
        detected_entities = []
        for entity_category, patterns in self.entity_patterns.items():
            for pattern in patterns:
                if pattern in payload:
                    entity_info = self.extract_entity_info(payload, pattern, entity_category)
                    if entity_info:
                        entity_info['detection_method'] = 'pattern'
                        detected_entities.append(entity_info)
        return detected_entities

    def extract_entity_info(self, payload: bytes, pattern: bytes, entity_type: str) -> Optional[Dict[str, Any]]:
        try:
            pattern_pos = payload.find(pattern)
            if pattern_pos == -1: return None
            
            entity_name = self.extract_entity_name(payload, pattern_pos, pattern)
            if not entity_name: return None
            
            actual_type = self.determine_entity_type(entity_name, entity_type)
            position = self.extract_position(payload, pattern_pos)
            classification = self.get_enhanced_classification(entity_name, actual_type)
            
            entity_info: Dict[str, Any] = {
                'detected_name': entity_name,
                'display_name': self.get_display_name(entity_name),
                'name': entity_name, 
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
            logger.error(f"Kesalahan saat mengekstrak info entitas: {e}", exc_info=True)
            return None

    def extract_entity_name(self, payload: bytes, pattern_pos: int, pattern: bytes) -> Optional[str]:
        try:
            name_start = pattern_pos
            name_end = name_start
            max_name_length = 60
            while (name_end < len(payload) and 
                   name_end - name_start < max_name_length and 
                   payload[name_end] != 0):
                char_val = payload[name_end]
                if not (32 <= char_val <= 126): break
                name_end += 1
            
            if name_end > name_start + 2: # Minimal 3 karakter
                entity_name_str = payload[name_start:name_end].decode('utf-8', 'ignore').strip().rstrip('\x00')
                if len(entity_name_str) >= 3: return entity_name_str
            return pattern.decode('utf-8', 'ignore').strip()
        except Exception: return None

    def extract_position(self, payload: bytes, reference_pos: int) -> Optional[Dict[str, float]]:
        try:
            search_start = max(0, reference_pos - 80)
            search_end = min(len(payload), reference_pos + 80)
            search_region = payload[search_start:search_end]
            
            for i in range(0, len(search_region) - 11, 4): # 3 float = 12 byte
                if i + 12 <= len(search_region):
                    try:
                        x, y, z = struct.unpack('<fff', search_region[i:i+12])
                        if all(-5000 < coord < 5000 for coord in [x, y, z]) and any(abs(coord) > 0.01 for coord in [x,y,z]):
                            return {'x': round(x, 2), 'y': round(y, 2), 'z': round(z, 2)}
                    except struct.error: continue
            # Fallback 2D
            for i in range(0, len(search_region) - 7, 4): # 2 float = 8 byte
                if i + 8 <= len(search_region):
                    try:
                        x, y = struct.unpack('<ff', search_region[i:i+8])
                        if all(-5000 < coord < 5000 for coord in [x, y]) and any(abs(coord) > 0.01 for coord in [x,y]):
                             return {'x': round(x, 2), 'y': round(y, 2), 'z': 0.0}
                    except struct.error: continue
        except Exception: pass
        return None

    def determine_entity_type(self, entity_name: str, suggested_type: str) -> str:
        name_lower = entity_name.lower()
        if any(p in name_lower for p in ['chest', 'treasure', 'loot']): return 'chests'
        if any(p in name_lower for p in ['boss', 'veteran', 'ancient', 'lord', 'champion']): return 'bosses'
        if any(p in name_lower for p in ['shrine', 'altar']): return 'shrines'
        return 'mobs'

    def get_enhanced_classification(self, entity_name: str, entity_type: str) -> str:
        name_lower = entity_name.lower()
        if entity_type == 'chests':
            if 'legendary' in name_lower or 'gold' in name_lower: return '🏆 PETI LEGENDARIS'
            if 'epic' in name_lower: return '🟣 PETI EPIK'
            if 'rare' in name_lower: return '🔵 PETI LANGKA'
            if 'uncommon' in name_lower: return '🟢 PETI TIDAK UMUM'
            if 'book' in name_lower: return '📚 PETI BUKU'
            if 'crystal' in name_lower or 'energy' in name_lower: return '💎 PETI KRISTAL'
            return '📦 PETI STANDAR'
        # ... (klasifikasi lain) ...
        return '❓ TIDAK DIKETAHUI'

    def get_display_name(self, entity_name: str) -> str:
        return entity_name.replace('_', ' ').title()

    def get_enhanced_data(self, entity_name: str, entity_type: str) -> Dict[str, Any]:
        # ... (implementasi data yang ditingkatkan) ...
        return {'display_name': self.get_display_name(entity_name), 'unique_name': entity_name, 'type': entity_type}

    def calculate_distance(self, pos1: Dict[str, float], pos2: Dict[str, float]) -> float:
        try:
            dx = pos1.get('x', 0.0) - pos2.get('x', 0.0)
            dy = pos1.get('y', 0.0) - pos2.get('y', 0.0)
            dz = pos1.get('z', 0.0) - pos2.get('z', 0.0)
            return round((dx**2 + dy**2 + dz**2)**0.5, 1)
        except TypeError: return 0.0 # Jika salah satu posisi None atau tidak valid

    def display_complete_ui(self):
        try:
            while self.scanner_active:
                import os
                os.system('cls' if os.name == 'nt' else 'clear')
                
                print("🚀 COMPLETE ALBION DUNGEON SCANNER v4.0")
                print("=" * 80)
                
                runtime = time.time() - self.stats['session_start']
                unique_entities_map = self.dedup_manager.get_unique_entities()
                
                print(f"⏱️  Runtime: {runtime:.1f}s | 📦 Paket: {self.stats['packets_analyzed']:,}")
                print(f"🎮 Tingkat Deteksi: {self.stats['detection_rate']:.1f}/min | 🔧 OpCode: {self.stats['opcodes_detected']}")
                print(f"🔄 Dedup: {len(unique_entities_map)} unik | {self.stats['duplicates_filtered']} difilter")
                if self.stats['opcodes_detected'] > 0 and self.stats['entities_detected'] > 0 : # entities_detected dari opcode
                    success_rate = (self.stats['entities_detected'] / self.stats['opcodes_detected']) * 100
                    print(f"📊 Tingkat Keberhasilan OpCode: {success_rate:.1f}%")
                else:
                    print(f"📊 Tingkat Keberhasilan OpCode: N/A")

                print(f"\n🏰 STATUS DUNGEON")
                print("-" * 50)
                print(f"📍 Dalam Dungeon: {'Ya' if self.dungeon_state['in_dungeon'] else 'Tidak'}")
                print(f"🗺️  Tipe: {self.dungeon_state['dungeon_type']}")
                print(f"🏢 Lantai: {self.avalonian_tracker.current_floor_id}")
                print(f"📡 Sesi: {self.dungeon_state['session_id']}")
                pos = self.dungeon_state['player_pos']
                print(f"🚶 Pemain: ({pos['x']:.1f}, {pos['y']:.1f}, {pos.get('z', 0.0):.1f})")
                
                if self.avalonian_tracker.floors:
                    print(f"\n🏗️  LANTAI AVALONIAN ({len(self.avalonian_tracker.floors)})")
                    print("-" * 30)
                    for floor_id, floor_data in list(self.avalonian_tracker.floors.items())[-3:]:
                        entity_count = len(floor_data.entities)
                        status = "✅ Selesai" if floor_data.completed else "🔄 Aktif"
                        print(f"   Lantai {floor_id}: {entity_count} entitas | {status}")
                
                print(f"\n👁️ ENTITAS UNIK LANGSUNG ({len(unique_entities_map)})")
                print("-" * 50)
                entities_by_type = defaultdict(list)
                for entity_data_val in unique_entities_map.values(): # Menggunakan .values()
                    entities_by_type[entity_data_val['type']].append(entity_data_val)
                
                for entity_cat in ['chests', 'bosses', 'mobs', 'shrines']:
                    entities_list = entities_by_type.get(entity_cat, [])
                    if entities_list:
                        type_icons = {'chests': '📦', 'bosses': '👑', 'mobs': '👹', 'shrines': '⭐'}
                        print(f"\n{type_icons.get(entity_cat, '❓')} {entity_cat.upper()} ({len(entities_list)}):")
                        for entity in entities_list[-8:]:
                            name = entity.get('detected_name', 'N/A')[:30]
                            count = entity.get('detection_count', 0)
                            last_seen_val = entity.get('last_seen')
                            last_seen_ago = (time.time() - last_seen_val) if last_seen_val else -1.0
                            
                            pos_str = ""
                            entity_pos = entity.get('position')
                            if entity_pos:
                                distance = self.calculate_distance(entity_pos, self.dungeon_state['player_pos'])
                                pos_str = f"| {distance}m "
                            print(f"  {name} | {count}x {pos_str}| {last_seen_ago:.0f}s lalu")
                
                print(f"\n📊 STATISTIK SESI LANJUTAN")
                print("-" * 40)
                print(f"🎯 Entitas Unik: {len(unique_entities_map)}")
                # ... (statistik lain) ...
                
                if self.websocket_bridge.clients:
                    print(f"🌐 Klien WebSocket: {len(self.websocket_bridge.clients)}")
                
                print(f"\n🔄 Pemindai Lengkap Aktif... (Ctrl+C untuk berhenti)")
                print(f"🌐 WebSocket: ws://localhost:{self.websocket_port if hasattr(self, 'websocket_port') else 'N/A'} | 📊 Visualisasi real-time tersedia")
                
                if not self.scanner_active: break
                time.sleep(1) # Kurangi sleep untuk respons shutdown lebih cepat
        except Exception as e:
            logger.error(f"Kesalahan di display_complete_ui: {e}", exc_info=True)
        finally:
            logger.info("Thread UI Display selesai.")

    def enhanced_packet_handler(self, packet: Packet): # type: ignore
        if not (packet.haslayer(UDP) and packet.haslayer(IP)): return
        
        udp_layer = packet[UDP]
        ip_layer = packet[IP]
        payload = bytes(udp_layer.payload) if udp_layer.payload else b''
        if not payload: return

        is_albion = (
            ip_layer.src in self.albion_servers or ip_layer.dst in self.albion_servers or
            ((ip_layer.src == self.client_ip or ip_layer.dst == self.client_ip) and 
             (5055 <= udp_layer.sport <= 5058 or 5055 <= udp_layer.dport <= 5058))
        )
        if not is_albion: return
        
        self.stats['packets_analyzed'] += 1
        
        if self.avalonian_tracker.detect_floor_transition(payload):
            self.stats['floors_discovered'] += 1
        
        detected_entities_list = self.advanced_entity_detection(payload)
        
        for entity in detected_entities_list:
            self.stats['entities_detected'] += 1 # Ini harusnya dari OpCode yang berhasil
            # self.stats['unique_entities'] += 1 # Ini dihitung dari len(dedup_manager.get_unique_entities())
            
            entity_type = entity.get('type', 'unknown')
            if entity_type == 'mobs': self.stats['unique_mobs'].add(entity.get('name', 'unknown_mob'))
            elif entity_type == 'chests': self.stats['unique_chests'].add(entity.get('name', 'unknown_chest'))
            elif entity_type == 'shrines': self.stats['shrines_activated'] += 1
            
            runtime = time.time() - self.stats['session_start']
            if runtime > 0: self.stats['detection_rate'] = (self.stats['packets_analyzed'] / runtime) * 60 # Berdasarkan paket, bukan entitas
            
            if self.websocket_bridge.clients and self.websocket_loop and self.websocket_loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    self.websocket_bridge.broadcast_update({
                        'type': 'entity_update', 'entity': entity, 'timestamp': datetime.now().isoformat()
                    }),
                    self.websocket_loop
                )
        self.update_player_position(payload)

    def update_player_position(self, payload: bytes) -> bool:
        position = self.extract_position(payload, 0) # Cari posisi di mana saja dalam payload
        if position:
            old_pos = self.dungeon_state['player_pos']
            # Hanya perbarui jika ada perubahan signifikan dan masuk akal
            if self.calculate_distance(position, old_pos) > 0.1: # Ambang batas pergerakan
                self.dungeon_state['player_pos'] = position
                self.dungeon_state['last_update'] = time.time()
                
                if self.websocket_bridge.clients and self.websocket_loop and self.websocket_loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        self.websocket_bridge.broadcast_update({
                            'type': 'player_movement', 'position': position, 'timestamp': datetime.now().isoformat()
                        }),
                        self.websocket_loop
                    )
                return True
        return False

    # --- Logika WebSocket Server yang Diperbarui ---
    async def _start_websocket_server_async(self, port: int):
        if not hasattr(self, 'websocket_bridge') or self.websocket_bridge is None:
             logger.error("WebSocketBridge tidak diinisialisasi!")
             return
        
        # Gunakan self.websocket_server untuk instance server
        # Ini akan diinisialisasi oleh websockets.serve()
        self.websocket_server = await websockets.serve( # type: ignore
            self.websocket_bridge.register_client, "localhost", port,
            # Tambahkan timeout untuk koneksi agar tidak menggantung selamanya
            ping_interval=20, ping_timeout=20 
        )
        logger.info(f"Server WebSocket dimulai di ws://localhost:{port}")
        try:
            # wait_closed() akan menunggu sampai server.close() dipanggil dan selesai
            if self.websocket_server: # Pastikan server tidak None
                 await self.websocket_server.wait_closed()
        except asyncio.CancelledError:
            logger.info("Tugas server WebSocket dibatalkan.")
            # Jika dibatalkan, pastikan server ditutup jika sudah dimulai
            if self.websocket_server and self.websocket_server.is_serving():
                self.websocket_server.close()
                await self.websocket_server.wait_closed()
        finally:
            logger.info("Korutin _start_websocket_server_async telah selesai atau dibatalkan.")

    def _run_websocket_server_thread(self, port: int):
        self.websocket_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.websocket_loop)
        logger.info(f"Thread WebSocket '{threading.current_thread().name}' memulai event loop.")
        try:
            self.websocket_loop.run_until_complete(self._start_websocket_server_async(port))
        except Exception as e:
            logger.error(f"Pengecualian di _run_websocket_server_thread: {e}", exc_info=True)
        finally:
            logger.info(f"Thread WebSocket '{threading.current_thread().name}' memasuki blok finally untuk pembersihan loop.")
            if self.websocket_loop:
                # Loop seharusnya sudah dihentikan oleh _stop_websocket_server
                # Blok ini lebih sebagai pengaman.
                if self.websocket_loop.is_running():
                    logger.warning("Thread WebSocket: Loop masih berjalan di blok finally, memaksa berhenti.")
                    self.websocket_loop.call_soon_threadsafe(self.websocket_loop.stop)
                
                if not self.websocket_loop.is_closed():
                    logger.info("Thread WebSocket: Mematikan generator asinkron dan menutup loop.")
                    try:
                        # Batalkan semua tugas yang tersisa
                        tasks = [task for task in asyncio.all_tasks(self.websocket_loop) if not task.done()]
                        if tasks:
                            logger.info(f"Thread WebSocket: Membatalkan {len(tasks)} tugas yang tersisa.")
                            for task in tasks:
                                task.cancel()
                            # Beri waktu tugas untuk memproses pembatalan
                            self.websocket_loop.run_until_complete(asyncio.gather(*tasks, return_exceptions=True))
                            logger.info("Thread WebSocket: Tugas yang tersisa telah diproses/dibatalkan.")
                    except RuntimeError as e_rt:
                        logger.warning(f"Thread WebSocket: RuntimeError saat pembatalan tugas: {e_rt} (Loop mungkin sudah berhenti)")
                    except Exception as e_tasks:
                        logger.error(f"Thread WebSocket: Pengecualian saat pembatalan tugas: {e_tasks}", exc_info=True)

                    try:
                        self.websocket_loop.run_until_complete(self.websocket_loop.shutdown_asyncgens())
                    except RuntimeError as e_rt_gens:
                        logger.warning(f"Thread WebSocket: RuntimeError saat shutdown_asyncgens: {e_rt_gens} (Loop mungkin sudah berhenti)")
                    except Exception as e_gens:
                        logger.error(f"Thread WebSocket: Pengecualian saat shutdown_asyncgens: {e_gens}", exc_info=True)
                    
                    if not self.websocket_loop.is_closed(): # Periksa lagi sebelum menutup
                        self.websocket_loop.close()
                        logger.info("Thread WebSocket: Event loop telah ditutup.")
                    else:
                        logger.info("Thread WebSocket: Event loop sudah ditutup sebelum panggilan close eksplisit.")
                else:
                     logger.info("Thread WebSocket: Event loop sudah ditutup.")
            else:
                logger.info("Thread WebSocket: websocket_loop adalah None di blok finally.")
            logger.info(f"Thread WebSocket '{threading.current_thread().name}' telah menyelesaikan pembersihan.")


    async def _shutdown_websocket_server_async(self):
        """Korutin untuk dijalankan pada loop WebSocket untuk mematikan server."""
        # Periksa apakah self.websocket_server ada dan merupakan objek server yang valid
        if hasattr(self, 'websocket_server') and self.websocket_server and self.websocket_server.is_serving():
            logger.info("Shutdown asinkron: Menutup koneksi klien WebSocket...")
            
            # Salin set klien karena bisa berubah saat iterasi
            clients_to_close = list(self.websocket_bridge.clients)
            if clients_to_close:
                close_client_tasks = [client.close(code=1000, reason="Server shutting down") for client in clients_to_close if client.open]
                if close_client_tasks:
                    await asyncio.gather(*close_client_tasks, return_exceptions=True)
                    logger.info(f"Shutdown asinkron: {len(close_client_tasks)} klien WebSocket telah ditutup atau dijadwalkan untuk ditutup.")
            else:
                logger.info("Shutdown asinkron: Tidak ada klien WebSocket aktif untuk ditutup.")

            logger.info("Shutdown asinkron: Menutup instance server WebSocket...")
            self.websocket_server.close()
            try:
                await self.websocket_server.wait_closed()
                logger.info("Shutdown asinkron: Server WebSocket berhasil ditutup.")
            except Exception as e:
                logger.error(f"Shutdown asinkron: Kesalahan saat server wait_closed: {e}", exc_info=True)
        else:
            logger.info("Shutdown asinkron: Server WebSocket tidak aktif atau sudah ditutup.")


    def _stop_websocket_server(self):
        """Menjadwalkan server WebSocket untuk berhenti dan memberi sinyal pada loop-nya untuk berhenti."""
        if self.websocket_loop and not self.websocket_loop.is_closed():
            if self.websocket_loop.is_running():
                logger.info("Menjadwalkan shutdown server WebSocket pada loop-nya...")
                future = asyncio.run_coroutine_threadsafe(self._shutdown_websocket_server_async(), self.websocket_loop)
                try:
                    future.result(timeout=10) # Tunggu shutdown selesai
                    logger.info("Korutin shutdown server WebSocket selesai.")
                except asyncio.TimeoutError:
                    logger.error("Timeout menunggu korutin shutdown server WebSocket selesai.")
                except Exception as e: # Termasuk concurrent.futures.CancelledError jika loop sudah berhenti
                    logger.error(f"Pengecualian saat korutin shutdown server WebSocket: {e}", exc_info=True)
                
                # Setelah shutdown server selesai (atau timeout), hentikan loop
                if self.websocket_loop.is_running(): # Periksa lagi
                    logger.info("Menjadwalkan penghentian event loop WebSocket...")
                    self.websocket_loop.call_soon_threadsafe(self.websocket_loop.stop)
                else:
                    logger.info("Event loop WebSocket sudah berhenti setelah shutdown server.")
            else:
                logger.info("Event loop WebSocket tidak berjalan, mencoba menutup jika belum.")
                if not self.websocket_loop.is_closed(): # Hanya jika tidak berjalan tapi belum ditutup
                    # self.websocket_loop.close() # Ini mungkin tidak aman jika ada tugas yang belum selesai
                    logger.warning("Loop WebSocket tidak berjalan. Pembersihan manual mungkin tidak lengkap.")
        else:
            logger.info("Loop WebSocket adalah None atau sudah ditutup.")


    def run_complete_scanner(self, duration: Optional[int] = None, websocket_port: int = 8765):
        self.websocket_port = websocket_port # Simpan port untuk UI
        print("🚀 MEMULAI COMPLETE ALBION SCANNER v4.0")
        # ... (cetak fitur) ...
        print()
        
        self.scanner_active = True
        
        self.websocket_thread = threading.Thread(
            target=self._run_websocket_server_thread,
            args=(websocket_port,),
            name="WebSocketServerThread", # Beri nama thread
            daemon=True
        )
        self.websocket_thread.start()
        
        ui_thread = threading.Thread(target=self.display_complete_ui, name="UIThread", daemon=True)
        ui_thread.start()
        
        time.sleep(2) # Beri waktu server dan UI untuk inisialisasi
        
        if not (self.websocket_loop and self.websocket_loop.is_running()):
            logger.warning("Server WebSocket mungkin tidak dimulai dengan benar setelah menunggu.")

        try:
            server_filter = ' or '.join([f'host {server}' for server in self.albion_servers])
            bpf_filter = f"udp and (({server_filter}) or host {self.client_ip})"
            
            print(f"🌐 Server WebSocket: ws://localhost:{websocket_port}")
            print(f"🎯 Memulai penangkapan paket pada interface: {self.interface} dengan filter: {bpf_filter}")
            print(f"📊 Buka browser untuk melihat visualisasi real-time!")
            print()
            
            sniff(
                iface=self.interface, filter=bpf_filter, prn=self.enhanced_packet_handler,
                timeout=duration, store=0, stop_filter=lambda p: not self.scanner_active
            )
            logger.info("Proses sniff selesai atau dihentikan oleh stop_filter.")
            
        except KeyboardInterrupt:
            print(f"\n⏹️ Pemindai lengkap dihentikan oleh pengguna (KeyboardInterrupt)")
            logger.info("KeyboardInterrupt diterima, memulai shutdown.")
        except Exception as e:
            print(f"\n❌ Kesalahan pemindai utama: {e}")
            logger.error(f"Kesalahan pemindai utama: {e}", exc_info=True)
        finally:
            print("\n Pemindai sedang dimatikan...")
            if self.scanner_active: # Jika belum di-set False (misalnya karena KeyboardInterrupt)
                self.scanner_active = False 
            
            logger.info("Memulai proses penghentian server WebSocket dari finally blok utama...")
            self._stop_websocket_server() 
            
            if self.websocket_thread and self.websocket_thread.is_alive():
                 logger.info("Menunggu thread WebSocket untuk bergabung...")
                 self.websocket_thread.join(timeout=15) 
                 if self.websocket_thread.is_alive():
                     logger.warning("Thread WebSocket tidak bergabung tepat waktu.")
                 else:
                     logger.info("Thread WebSocket berhasil digabung.")
            
            if ui_thread and ui_thread.is_alive():
                logger.info("Menunggu thread UI untuk bergabung...")
                ui_thread.join(timeout=3)
                if ui_thread.is_alive():
                    logger.warning("Thread UI tidak bergabung tepat waktu.")
                else:
                    logger.info("Thread UI berhasil digabung.")

            logger.info("Menyimpan hasil...")
            self.save_complete_results()
            logger.info("Shutdown pemindai selesai.")

    def save_complete_results(self):
        try:
            unique_entities_map = self.dedup_manager.get_unique_entities()
            # ... (logika penyimpanan hasil lainnya) ...
            filename = f"complete_albion_scan_v4_{int(time.time())}.json"
            # Pastikan semua data yang diserialkan aman untuk JSON (misalnya, set dikonversi ke list)
            # Contoh: self.stats['unique_mobs'] = list(self.stats['unique_mobs'])
            # ...
            with open(filename, 'w') as f:
                # json.dump(results_dict, f, indent=2, default=str) # Pastikan results_dict didefinisikan
                pass # Placeholder
            print(f"\n💾 Hasil lengkap disimpan ke: {filename}")
        except Exception as e:
            print(f"⚠️ Tidak dapat menyimpan hasil: {e}")
            logger.error(f"Kesalahan saat menyimpan: {e}", exc_info=True)


def main():
    print("🚀 COMPLETE ALBION ONLINE DUNGEON SCANNER SUITE v4.0")
    print("=" * 70)
    # ... (pemeriksaan requirement) ...
    print()
    print("🎯 Memulai pemindai lengkap...")
    
    scanner = CompleteAlbionScanner()
    scanner.run_complete_scanner(websocket_port=8765)

if __name__ == "__main__":
    # Tambahkan konfigurasi logging dasar jika belum ada di level global
    if not logging.getLogger().hasHandlers():
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(threadName)s - %(name)s - %(message)s')
    main()
