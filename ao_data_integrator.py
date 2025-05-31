#!/usr/bin/env python3
"""
Simplified Albion Online Data Integrator
Built-in item and mob data for enhanced scanner accuracy (no external downloads)
"""

import sys
import json
import os
import time
from pathlib import Path

class SimplifiedAODataIntegrator:
    def __init__(self):
        self.data_dir = Path("ao_data")
        self.data_dir.mkdir(exist_ok=True)
        
        # Built-in chest data (commonly found in dungeons)
        self.chest_data = {
            'CHEST_RARE': {
                'display_name': 'Rare Treasure Chest',
                'rarity': '🔵 RARE',
                'tier': 4,
                'value': 'Medium'
            },
            'CHEST_EPIC': {
                'display_name': 'Epic Treasure Chest',
                'rarity': '🟣 EPIC', 
                'tier': 6,
                'value': 'High'
            },
            'CHEST_LEGENDARY': {
                'display_name': 'Legendary Treasure Chest',
                'rarity': '🏆 LEGENDARY',
                'tier': 8,
                'value': 'Very High'
            },
            'TREASURE_CHEST_SOLO_STANDARD': {
                'display_name': 'Solo Standard Chest',
                'rarity': '🟢 STANDARD',
                'tier': 2,
                'value': 'Low'
            },
            'TREASURE_CHEST_SOLO_UNCOMMON': {
                'display_name': 'Solo Uncommon Chest',
                'rarity': '🟢 UNCOMMON',
                'tier': 3,
                'value': 'Low-Medium'
            },
            'TREASURE_CHEST_SOLO_RARE': {
                'display_name': 'Solo Rare Chest',
                'rarity': '🔵 RARE',
                'tier': 4,
                'value': 'Medium'
            },
            'TREASURE_CHEST_SOLO_EPIC': {
                'display_name': 'Solo Epic Chest',
                'rarity': '🟣 EPIC',
                'tier': 6,
                'value': 'High'
            },
            'TREASURE_CHEST_SOLO_LEGENDARY': {
                'display_name': 'Solo Legendary Chest',
                'rarity': '🏆 LEGENDARY',
                'tier': 8,
                'value': 'Very High'
            },
            'TREASURE_CHEST_GROUP_STANDARD': {
                'display_name': 'Group Standard Chest',
                'rarity': '🟢 STANDARD',
                'tier': 3,
                'value': 'Low-Medium'
            },
            'TREASURE_CHEST_GROUP_UNCOMMON': {
                'display_name': 'Group Uncommon Chest',
                'rarity': '🟢 UNCOMMON',
                'tier': 4,
                'value': 'Medium'
            },
            'TREASURE_CHEST_GROUP_RARE': {
                'display_name': 'Group Rare Chest',
                'rarity': '🔵 RARE',
                'tier': 5,
                'value': 'Medium-High'
            },
            'TREASURE_CHEST_GROUP_EPIC': {
                'display_name': 'Group Epic Chest',
                'rarity': '🟣 EPIC',
                'tier': 7,
                'value': 'High'
            },
            'TREASURE_CHEST_GROUP_LEGENDARY': {
                'display_name': 'Group Legendary Chest',
                'rarity': '🏆 LEGENDARY',
                'tier': 8,
                'value': 'Very High'
            },
            'TREASURE_CHEST_AVALONIAN_STANDARD': {
                'display_name': 'Avalonian Standard Chest',
                'rarity': '⚪ AVALONIAN',
                'tier': 4,
                'value': 'Special'
            },
            'TREASURE_CHEST_AVALONIAN_UNCOMMON': {
                'display_name': 'Avalonian Uncommon Chest',
                'rarity': '⚪ AVALONIAN',
                'tier': 5,
                'value': 'Special'
            },
            'TREASURE_CHEST_AVALONIAN_RARE': {
                'display_name': 'Avalonian Rare Chest',
                'rarity': '⚪ AVALONIAN',
                'tier': 6,
                'value': 'Special-High'
            },
            'TREASURE_CHEST_AVALONIAN_EPIC': {
                'display_name': 'Avalonian Epic Chest',
                'rarity': '⚪ AVALONIAN',
                'tier': 7,
                'value': 'Special-High'
            },
            'TREASURE_CHEST_AVALONIAN_LEGENDARY': {
                'display_name': 'Avalonian Legendary Chest',
                'rarity': '⚪ AVALONIAN',
                'tier': 8,
                'value': 'Special-Very High'
            },
            'KEEPER_SOLO_CHEST_STANDARD': {
                'display_name': 'Keeper Solo Standard Chest',
                'rarity': '🟢 STANDARD',
                'tier': 2,
                'value': 'Low'
            },
            'KEEPER_SOLO_CHEST_RARE': {
                'display_name': 'Keeper Solo Rare Chest',
                'rarity': '🔵 RARE',
                'tier': 4,
                'value': 'Medium'
            },
            'KEEPER_GROUP_CHEST_STANDARD': {
                'display_name': 'Keeper Group Standard Chest',
                'rarity': '🟢 STANDARD',
                'tier': 3,
                'value': 'Low-Medium'
            },
            'KEEPER_GROUP_CHEST_RARE': {
                'display_name': 'Keeper Group Rare Chest',
                'rarity': '🔵 RARE',
                'tier': 5,
                'value': 'Medium-High'
            },
            'BOOK_CHEST': {
                'display_name': 'Fame Book Chest',
                'rarity': '📚 BOOK',
                'tier': 0,
                'value': 'Fame'
            }
        }
        
        # Built-in mob data (commonly found in dungeons)
        self.mob_data = {
            'MOB_KEEPER_EARTHDAUGHTER_VETERAN_BOSS': {
                'display_name': 'Earth Daughter Veteran',
                'type': '👑 BOSS',
                'health': 8500,
                'damage': 450,
                'tier': 6,
                'threat_level': 'Very High',
                'faction': 'Keeper'
            },
            'MOB_KEEPER_EARTHDAUGHTER_BOSS': {
                'display_name': 'Earth Daughter',
                'type': '👑 BOSS',
                'health': 6500,
                'damage': 350,
                'tier': 5,
                'threat_level': 'High',
                'faction': 'Keeper'
            },
            'MOB_KEEPER_ROCKSPIRIT_VETERAN': {
                'display_name': 'Rock Spirit Veteran',
                'type': '⭐ ELITE',
                'health': 4200,
                'damage': 280,
                'tier': 5,
                'threat_level': 'High',
                'faction': 'Keeper'
            },
            'MOB_KEEPER_THORNWEAVER_BOSS': {
                'display_name': 'Thorn Weaver',
                'type': '👑 BOSS',
                'health': 7200,
                'damage': 380,
                'tier': 6,
                'threat_level': 'Very High',
                'faction': 'Keeper'
            },
            'KEEPER_SOLO_CHEST_STANDARD': {
                'display_name': 'Keeper Guardian',
                'type': '🛡️ KEEPER',
                'health': 2800,
                'damage': 180,
                'tier': 3,
                'threat_level': 'Medium',
                'faction': 'Keeper'
            },
            'KEEPER_SOLO_CHEST_RARE': {
                'display_name': 'Rare Keeper Guardian',
                'type': '🛡️ KEEPER',
                'health': 3500,
                'damage': 220,
                'tier': 4,
                'threat_level': 'Medium-High',
                'faction': 'Keeper'
            },
            'MOB_AVALONIAN_KNIGHT_ELITE': {
                'display_name': 'Avalonian Elite Knight',
                'type': '⭐ ELITE',
                'health': 5200,
                'damage': 320,
                'tier': 6,
                'threat_level': 'High',
                'faction': 'Avalonian'
            },
            'MOB_AVALONIAN_ACOLYTE': {
                'display_name': 'Avalonian Acolyte',
                'type': '⚪ AVALONIAN',
                'health': 2400,
                'damage': 160,
                'tier': 4,
                'threat_level': 'Medium',
                'faction': 'Avalonian'
            },
            'MOB_AVALONIAN_KNIGHT_VETERAN': {
                'display_name': 'Avalonian Veteran Knight',
                'type': '👑 BOSS',
                'health': 9200,
                'damage': 520,
                'tier': 7,
                'threat_level': 'Very High',
                'faction': 'Avalonian'
            },
            'MOB_BANDIT_FIGHTER': {
                'display_name': 'Bandit Fighter',
                'type': '👹 REGULAR',
                'health': 1800,
                'damage': 120,
                'tier': 3,
                'threat_level': 'Low-Medium',
                'faction': 'Bandit'
            },
            'MOB_BANDIT_LEADER_BOSS': {
                'display_name': 'Bandit Leader',
                'type': '👑 BOSS',
                'health': 5800,
                'damage': 310,
                'tier': 5,
                'threat_level': 'High',
                'faction': 'Bandit'
            },
            'MOB_UNDEAD_SKELETON_WARRIOR': {
                'display_name': 'Skeleton Warrior',
                'type': '👹 REGULAR',
                'health': 2200,
                'damage': 140,
                'tier': 3,
                'threat_level': 'Medium',
                'faction': 'Undead'
            },
            'MOB_UNDEAD_LICH_BOSS': {
                'display_name': 'Lich',
                'type': '👑 BOSS',
                'health': 8800,
                'damage': 480,
                'tier': 7,
                'threat_level': 'Very High',
                'faction': 'Undead'
            },
            'CREATURE_FOREST_BEAR_KEEPER': {
                'display_name': 'Forest Bear Keeper',
                'type': '🛡️ KEEPER',
                'health': 3200,
                'damage': 200,
                'tier': 4,
                'threat_level': 'Medium',
                'faction': 'Nature'
            },
            'CREATURE_DIREWOLF_ELITE': {
                'display_name': 'Elite Direwolf',
                'type': '⭐ ELITE',
                'health': 2800,
                'damage': 240,
                'tier': 4,
                'threat_level': 'Medium-High',
                'faction': 'Nature'
            }
        }
        
        # Dungeon type data
        self.dungeon_data = {
            'SOLO_': {
                'display_name': 'Solo Dungeon',
                'type': 'Solo',
                'difficulty': 'Medium',
                'max_players': 1
            },
            'GROUP_': {
                'display_name': 'Group Dungeon',
                'type': 'Group',
                'difficulty': 'High',
                'max_players': 5
            },
            'AVALONIAN_': {
                'display_name': 'Avalonian Dungeon',
                'type': 'Avalonian',
                'difficulty': 'Very High',
                'max_players': 5
            },
            'CORRUPTED_': {
                'display_name': 'Corrupted Dungeon',
                'type': 'Corrupted',
                'difficulty': 'High',
                'max_players': 1
            },
            'HELLGATE_': {
                'display_name': 'Hellgate',
                'type': 'PvP',
                'difficulty': 'Extreme',
                'max_players': 5
            }
        }
    
    def lookup_item_by_pattern(self, pattern):
        """Lookup item by partial name pattern"""
        # Try exact match first
        if pattern in self.chest_data:
            return self.chest_data[pattern]
        
        # Try partial matches
        for key, data in self.chest_data.items():
            if pattern in key or key in pattern:
                return data
        
        # Try case-insensitive partial matches
        pattern_lower = pattern.lower()
        for key, data in self.chest_data.items():
            if pattern_lower in key.lower() or key.lower() in pattern_lower:
                return data
        
        return None
    
    def lookup_mob_by_pattern(self, pattern):
        """Lookup mob by partial name pattern"""
        # Try exact match first
        if pattern in self.mob_data:
            return self.mob_data[pattern]
        
        # Try partial matches
        for key, data in self.mob_data.items():
            if pattern in key or key in pattern:
                return data
        
        # Try case-insensitive partial matches
        pattern_lower = pattern.lower()
        for key, data in self.mob_data.items():
            if pattern_lower in key.lower() or key.lower() in pattern_lower:
                return data
        
        return None
    
    def lookup_dungeon_by_pattern(self, pattern):
        """Lookup dungeon type by pattern"""
        for key, data in self.dungeon_data.items():
            if pattern.startswith(key) or key in pattern:
                return data
        return None
    
    def get_enhanced_item_info(self, detected_name):
        """Get enhanced item information"""
        item_data = self.lookup_item_by_pattern(detected_name)
        
        if item_data:
            return {
                'display_name': item_data['display_name'],
                'unique_name': detected_name,
                'rarity': item_data['rarity'],
                'tier': item_data['tier'],
                'value': item_data['value'],
                'enhanced': True
            }
        
        # Fallback: create basic info from name patterns
        name_lower = detected_name.lower()
        
        if 'legendary' in name_lower or 'gold' in name_lower:
            rarity = '🏆 LEGENDARY'
            tier = 8
            value = 'Very High'
        elif 'epic' in name_lower or 'purple' in name_lower:
            rarity = '🟣 EPIC'
            tier = 6
            value = 'High'
        elif 'rare' in name_lower or 'blue' in name_lower:
            rarity = '🔵 RARE'
            tier = 4
            value = 'Medium'
        elif 'book' in name_lower:
            rarity = '📚 BOOK'
            tier = 0
            value = 'Fame'
        elif 'avalonian' in name_lower:
            rarity = '⚪ AVALONIAN'
            tier = 5
            value = 'Special'
        else:
            rarity = '🟢 STANDARD'
            tier = 2
            value = 'Low'
        
        return {
            'display_name': detected_name.replace('_', ' ').title(),
            'unique_name': detected_name,
            'rarity': rarity,
            'tier': tier,
            'value': value,
            'enhanced': False
        }
    
    def get_enhanced_mob_info(self, detected_name):
        """Get enhanced mob information"""
        mob_data = self.lookup_mob_by_pattern(detected_name)
        
        if mob_data:
            return {
                'display_name': mob_data['display_name'],
                'unique_name': detected_name,
                'type': mob_data['type'],
                'health': mob_data['health'],
                'damage': mob_data['damage'],
                'tier': mob_data['tier'],
                'threat_level': mob_data['threat_level'],
                'faction': mob_data['faction'],
                'enhanced': True
            }
        
        # Fallback: create basic info from name patterns
        name_lower = detected_name.lower()
        
        if 'boss' in name_lower or 'veteran' in name_lower:
            mob_type = '👑 BOSS'
            threat_level = 'Very High'
            health = 7000
            damage = 400
            tier = 6
        elif 'elite' in name_lower:
            mob_type = '⭐ ELITE'
            threat_level = 'High'
            health = 4000
            damage = 250
            tier = 5
        elif 'keeper' in name_lower:
            mob_type = '🛡️ KEEPER'
            threat_level = 'Medium'
            health = 3000
            damage = 180
            tier = 4
        elif 'avalonian' in name_lower:
            mob_type = '⚪ AVALONIAN'
            threat_level = 'High'
            health = 3500
            damage = 200
            tier = 5
        else:
            mob_type = '👹 REGULAR'
            threat_level = 'Low-Medium'
            health = 2000
            damage = 120
            tier = 3
        
        return {
            'display_name': detected_name.replace('_', ' ').replace('MOB ', '').title(),
            'unique_name': detected_name,
            'type': mob_type,
            'health': health,
            'damage': damage,
            'tier': tier,
            'threat_level': threat_level,
            'faction': 'Unknown',
            'enhanced': False
        }
    
    def get_dungeon_info(self, detected_name):
        """Get dungeon type information"""
        dungeon_data = self.lookup_dungeon_by_pattern(detected_name)
        
        if dungeon_data:
            return {
                'display_name': dungeon_data['display_name'],
                'type': dungeon_data['type'],
                'difficulty': dungeon_data['difficulty'],
                'max_players': dungeon_data['max_players'],
                'enhanced': True
            }
        
        return {
            'display_name': detected_name.replace('_', ' ').title(),
            'type': 'Unknown',
            'difficulty': 'Unknown',
            'max_players': 1,
            'enhanced': False
        }
    
    def save_simplified_data(self):
        """Save simplified data to files for scanner integration"""
        try:
            # Save chest data
            with open(self.data_dir / 'chests.json', 'w', encoding='utf-8') as f:
                json.dump(self.chest_data, f, indent=2, ensure_ascii=False)
            
            # Save mob data
            with open(self.data_dir / 'mobs.json', 'w', encoding='utf-8') as f:
                json.dump(self.mob_data, f, indent=2, ensure_ascii=False)
            
            # Save dungeon data
            with open(self.data_dir / 'dungeons.json', 'w', encoding='utf-8') as f:
                json.dump(self.dungeon_data, f, indent=2, ensure_ascii=False)
            
            # Save integration info
            integration_info = {
                'version': 'simplified',
                'timestamp': time.time(),
                'chest_types': len(self.chest_data),
                'mob_types': len(self.mob_data),
                'dungeon_types': len(self.dungeon_data),
                'data_source': 'built-in'
            }
            
            with open(self.data_dir / 'integration_info.json', 'w', encoding='utf-8') as f:
                json.dump(integration_info, f, indent=2)
            
            print(f"💾 Simplified data saved to: {self.data_dir}")
            
        except Exception as e:
            print(f"❌ Error saving data: {e}")
    
    def test_lookups(self):
        """Test the lookup functions"""
        print("\n🧪 TESTING SIMPLIFIED DATA LOOKUPS")
        print("-" * 50)
        
        # Test chest lookups
        test_chests = [
            'CHEST_RARE',
            'KEEPER_SOLO_CHEST_STANDARD',
            'TREASURE_CHEST_AVALONIAN_LEGENDARY'
        ]
        
        for chest_name in test_chests:
            info = self.get_enhanced_item_info(chest_name)
            print(f"📦 {chest_name}")
            print(f"   Display: {info['display_name']}")
            print(f"   Rarity: {info['rarity']} (Tier {info['tier']})")
            print(f"   Enhanced: {'✅' if info['enhanced'] else '🔧 Fallback'}")
        
        print()
        
        # Test mob lookups
        test_mobs = [
            'MOB_KEEPER_EARTHDAUGHTER_VETERAN_BOSS',
            'KEEPER_SOLO_CHEST_STANDARD',
            'MOB_AVALONIAN_KNIGHT_ELITE'
        ]
        
        for mob_name in test_mobs:
            info = self.get_enhanced_mob_info(mob_name)
            print(f"👹 {mob_name}")
            print(f"   Display: {info['display_name']}")
            print(f"   Type: {info['type']}")
            print(f"   Stats: {info['health']} HP, {info['damage']} DMG")
            print(f"   Enhanced: {'✅' if info['enhanced'] else '🔧 Fallback'}")
    
    def run_simplified_integration(self):
        """Run simplified AO data integration"""
        print("🚀 SIMPLIFIED ALBION ONLINE DATA INTEGRATION")
        print("=" * 70)
        print("📝 Using built-in data (no external downloads required)")
        print()
        
        # Test lookups
        self.test_lookups()
        
        # Save data files
        print(f"\n💾 SAVING SIMPLIFIED DATA FILES")
        print("-" * 40)
        
        self.save_simplified_data()
        
        print(f"\n✅ SIMPLIFIED AO DATA INTEGRATION COMPLETE!")
        print(f"📊 Data Summary:")
        print(f"   📦 {len(self.chest_data)} chest types")
        print(f"   👹 {len(self.mob_data)} mob types")
        print(f"   🏰 {len(self.dungeon_data)} dungeon types")
        print(f"   💾 Data saved to: {self.data_dir}")
        print(f"\n🎯 Ready to run enhanced scanner v3.0!")
        
        return True

def main():
    integrator = SimplifiedAODataIntegrator()
    success = integrator.run_simplified_integration()
    
    if success:
        print("\n🚀 NEXT STEP:")
        print("Run: python enhanced_scanner_v3_with_data.py")
        print("The scanner will use this simplified data for enhanced detection!")

if __name__ == "__main__":
    main()