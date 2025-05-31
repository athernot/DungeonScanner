 #!/usr/bin/env python3
"""
Albion Online Packet Capture Test
Tes dasar untuk mendeteksi apakah kita bisa capture packet Albion Online
"""

import sys
import time
from scapy.all import *
from scapy.layers.inet import IP, UDP

# Konfigurasi
ALBION_PORT = 5056  # Port UDP standar Photon untuk Albion Online
INTERFACE = None  # None = auto-detect, atau specify interface seperti "eth0"

def get_available_interfaces():
    """Mendapatkan daftar interface jaringan yang tersedia"""
    interfaces = get_if_list()
    print("=== Interface Jaringan Tersedia ===")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface}")
    return interfaces

def packet_handler(packet):
    """Handler untuk setiap packet yang di-capture"""
    if packet.haslayer(UDP) and packet.haslayer(IP):
        udp_layer = packet[UDP]
        ip_layer = packet[IP]
        
        # Filter untuk port Albion Online
        if udp_layer.sport == ALBION_PORT or udp_layer.dport == ALBION_PORT:
            timestamp = time.strftime("%H:%M:%S", time.localtime())
            direction = "→" if udp_layer.dport == ALBION_PORT else "←"
            
            print(f"[{timestamp}] {direction} Albion Packet Detected!")
            print(f"  Source: {ip_layer.src}:{udp_layer.sport}")
            print(f"  Dest:   {ip_layer.dst}:{udp_layer.dport}")
            print(f"  Size:   {len(packet)} bytes")
            print(f"  Data:   {len(udp_layer.payload)} bytes payload")
            
            # Tampilkan beberapa byte pertama payload (hex)
            if len(udp_layer.payload) > 0:
                payload_preview = bytes(udp_layer.payload)[:16]
                hex_preview = ' '.join(f'{b:02x}' for b in payload_preview)
                print(f"  Preview: {hex_preview}...")
            print("-" * 50)
            
            return True  # Packet Albion ditemukan
    return False

def test_packet_capture(interface=None, duration=30):
    """
    Test packet capture untuk Albion Online
    
    Args:
        interface: Network interface to use (None for auto)
        duration: Duration to capture in seconds
    """
    
    print("🔍 Albion Online Packet Capture Test")
    print("=" * 50)
    
    # Tampilkan interface yang tersedia
    interfaces = get_available_interfaces()
    
    if interface is None:
        print(f"\n📡 Auto-detecting interface...")
        interface = conf.iface
    
    print(f"📡 Using interface: {interface}")
    print(f"🎯 Filtering for UDP port {ALBION_PORT}")
    print(f"⏱️  Capturing for {duration} seconds...")
    print("\n🚨 PASTIKAN ALBION ONLINE SEDANG RUNNING!")
    print("🚨 Lakukan aktivitas in-game (jalan, buka inventory, etc.)")
    print("\nStarting capture...\n")
    
    try:
        # Filter untuk UDP traffic pada port Albion
        bpf_filter = f"udp port {ALBION_PORT}"
        
        # Capture packets
        packets = sniff(
            iface=interface,
            filter=bpf_filter,
            prn=packet_handler,
            timeout=duration,
            store=1
        )
        
        print(f"\n📊 Capture selesai!")
        print(f"Total packets captured: {len(packets)}")
        
        # Analisis hasil
        albion_packets = []
        for pkt in packets:
            if pkt.haslayer(UDP):
                udp = pkt[UDP]
                if udp.sport == ALBION_PORT or udp.dport == ALBION_PORT:
                    albion_packets.append(pkt)
        
        print(f"Albion packets detected: {len(albion_packets)}")
        
        if len(albion_packets) > 0:
            print("✅ SUCCESS: Albion Online packets terdeteksi!")
            print("✅ Network capture berfungsi dengan baik")
            
            # Analisis server yang terdeteksi
            servers = set()
            for pkt in albion_packets:
                ip = pkt[IP]
                udp = pkt[UDP]
                if udp.dport == ALBION_PORT:  # Outgoing to server
                    servers.add(ip.dst)
                else:  # Incoming from server
                    servers.add(ip.src)
            
            print(f"🖥️  Server IPs detected: {', '.join(servers)}")
            
        else:
            print("❌ PROBLEM: Tidak ada packet Albion Online terdeteksi!")
            print("\n🔧 Troubleshooting:")
            print("1. Pastikan Albion Online sedang running")
            print("2. Pastikan melakukan aktivitas in-game")
            print("3. Coba run script sebagai administrator/root")
            print("4. Cek firewall settings")
            print("5. Jika menggunakan VPN, pastikan interface benar")
            
    except PermissionError:
        print("❌ ERROR: Permission denied!")
        print("🔧 Solution: Run script sebagai administrator/root")
        print("   Windows: Run Command Prompt as Administrator")
        print("   Linux/Mac: sudo python3 script.py")
        
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        print("🔧 Cek apakah Npcap/libpcap terinstall dengan benar")

def main():
    """Main function"""
    print("Albion Online Network Capture Test") 
    print("Pastikan requirements terinstall:")
    print("pip install scapy")
    print("Dan pastikan Npcap/libpcap terinstall\n")
    
    # Test basic capture
    test_packet_capture(duration=30)
    
    print("\n" + "="*50)
    print("Test selesai!")
    print("Jika berhasil, kita bisa lanjut ke parsing Photon protocol")

if __name__ == "__main__":
    main()