import socket
import time
import sys
import argparse

TARGET_IP = "127.0.0.1"

def syn_flood_simulation(duration=5):
    """Simulates SYN flood pattern - high rate of connection attempts"""
    print("🔴 Simulating SYN Flood (high connection rate)...")
    print(f"   Duration: {duration} seconds")
    print("   This should trigger CRITICAL/HIGH severity alerts\n")
    
    target_ip = TARGET_IP
    target_port = 80
    
    start = time.time()
    count = 0
    
    while time.time() - start < duration:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.001)
            sock.connect((target_ip, target_port))
            sock.close()
            count += 1
        except:
            count += 1  
    
    print(f"✓ Sent {count} connection attempts ({count/duration:.0f} per second)")
    print(f"   Expected detection: CRITICAL - SYN flood pattern\n")

def port_scan_simulation():
    """Simulates port scanning - many connections to different ports"""
    print("🟠 Simulating Port Scan (rapid multi-port probing)...")
    print("   Scanning ports 1-500")
    print("   This should trigger HIGH/MEDIUM severity alerts\n")
    
    target_ip = TARGET_IP
    count = 0
    
    start = time.time()
    for port in range(1, 501):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.001)
            sock.connect((target_ip, port))
            sock.close()
        except:
            pass
        count += 1
    
    duration = time.time() - start
    print(f"✓ Scanned {count} ports in {duration:.1f}s ({count/duration:.0f} per second)")
    print(f"   Expected detection: HIGH - Packet burst/scan pattern\n")

def udp_flood_simulation(duration=5):
    """Simulates UDP flood - high rate of UDP packets"""
    print("🟠 Simulating UDP Flood (high-rate UDP traffic)...")
    print(f"   Duration: {duration} seconds")
    print("   This should trigger HIGH severity alerts\n")
    
    target_ip = TARGET_IP
    target_port = 53
    payload = b"X" * 64
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    start = time.time()
    count = 0
    
    while time.time() - start < duration:
        try:
            sock.sendto(payload, (target_ip, target_port))
            count += 1
        except:
            pass
    
    sock.close()
    print(f"✓ Sent {count} UDP packets ({count/duration:.0f} per second)")
    print(f"   Expected detection: HIGH - UDP amplification pattern\n")

def data_transfer_simulation():
    """Simulates large data transfer"""
    print("🟡 Simulating Large Data Transfer...")
    print("   Sending 10MB of data")
    print("   This should trigger MEDIUM severity alerts\n")
    
    target_ip = TARGET_IP
    target_port = 9999
    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind((target_ip, target_port))
    except Exception:
        print("   (Port in use, skipping server bind)")
        return
    server.listen(1)
    server.settimeout(1)
    
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    try:
        client.connect((target_ip, target_port))
        try:
            conn, addr = server.accept()
        except Exception:
            print("   (Accept timeout, skipping)")
            client.close()
            server.close()
            return

        payload = b"X" * 1024 * 1024  
        total_sent = 0
        start = time.time()

        for _ in range(10):  
            client.send(payload)
            total_sent += len(payload)

        duration = time.time() - start

        conn.close()
        client.close()
        server.close()

        print(f"✓ Transferred {total_sent/1024/1024:.1f}MB in {duration:.1f}s")
        print(f"   Expected detection: MEDIUM - Large rapid transfer\n")
    except Exception as e:
        print(f"   (Skipped - client connect failed or timeout: {e})\n")
        try:
            client.close()
            server.close()
        except Exception:
            pass

def normal_traffic_baseline():
    """Generates normal-looking traffic for comparison"""
    print("🟢 Generating Normal Traffic Baseline...")
    print("   This should NOT trigger alerts\n")
    
    target_ip = TARGET_IP
    
    for i in range(5):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            sock.connect((target_ip, 80))
            sock.close()
            time.sleep(0.5)  
        except:
            pass
    
    print(f"✓ Sent 5 normal connections with realistic delays")
    print(f"   Expected: No alerts (normal traffic)\n")

def main():
    parser = argparse.ArgumentParser(description="Safe attack traffic simulator for detector testing")
    parser.add_argument("--syn", action="store_true", help="Run SYN-flood style connection attempts")
    parser.add_argument("--scan", action="store_true", help="Run rapid port scan simulation")
    parser.add_argument("--udp", action="store_true", help="Run UDP flood simulation")
    parser.add_argument("--data", action="store_true", help="Run large data transfer simulation")
    parser.add_argument("--baseline", action="store_true", help="Run normal traffic baseline")
    parser.add_argument("--duration", type=int, default=5, help="Duration in seconds for flood tests")
    parser.add_argument("--target-ip", type=str, default=None, help="Target IP (default: 127.0.0.1). Use your LAN IP to hit a NIC.")
    args = parser.parse_args()

    print("=" * 60)
    print("AI-Driven Cyber Threat Detector - Attack Simulator")
    global TARGET_IP
    if args.target_ip:
        TARGET_IP = args.target_ip
    print(f"Safe: traffic only to {TARGET_IP}")
    print("=" * 60)

    run_all = not (args.syn or args.scan or args.udp or args.data or args.baseline)

    try:
        if args.baseline or run_all:
            normal_traffic_baseline()
        if args.syn or run_all:
            syn_flood_simulation(args.duration)
        if args.scan or run_all:
            port_scan_simulation()
        if args.udp or run_all:
            udp_flood_simulation(args.duration)
        if args.data or run_all:
            data_transfer_simulation()
    except KeyboardInterrupt:
        print("\nStopped by user")
    finally:
        print("\nDone. Check detector console and logs/alerts.log.")

if __name__ == "__main__":
    main()
