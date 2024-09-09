from scapy.all import sr1, IP, ICMP
import argparse
import time
import socket

def ping(destination, count=4, ttl=64, size=56, timeout=1):
    try:
        # Validate destination IP
        socket.inet_aton(destination)
    except socket.error:
        print(f"Invalid IP address: {destination}")
        return

    if count <= 0:
        print("Count must be a positive integer.")
        return
    
    if ttl <= 0:
        print("TTL must be a positive integer.")
        return

    rtts = []
    lost_packets = 0

    print(f"Pinging {destination} with {count} packets, TTL={ttl}, size={size} bytes, timeout={timeout}s:")

    for i in range(count):
        packet = IP(dst=destination, ttl=ttl)/ICMP()/(b'x'*size)
        start_time = time.time()
        try:
            reply = sr1(packet, timeout=timeout, verbose=False)
            end_time = time.time()

            if reply:
                rtt = (end_time - start_time) * 1000  # Convert to milliseconds
                rtts.append(rtt)
                print(f"Reply from {destination}: bytes={len(reply[ICMP].payload)} time={rtt:.2f} ms TTL={reply[IP].ttl}")
            else:
                print(f"Request timed out.")
                lost_packets += 1
        except Exception as e:
            print(f"An error occurred while pinging: {e}")
            lost_packets += 1
        time.sleep(1)

    # Calculate statistics
    if rtts:
        average_rtt = sum(rtts) / len(rtts)
        min_rtt = min(rtts)
        max_rtt = max(rtts)
        packet_loss = (lost_packets / count) * 100
    else:
        average_rtt = 0
        min_rtt = 0
        max_rtt = 0
        packet_loss = 100

    print("\nPing statistics:")
    print(f"    Packets sent: {count}")
    print(f"    Packets received: {count - lost_packets}")
    print(f"    Packet loss: {packet_loss:.2f}%")
    print(f"    Minimum RTT: {min_rtt:.2f} ms")
    print(f"    Maximum RTT: {max_rtt:.2f} ms")
    print(f"    Average RTT: {average_rtt:.2f} ms")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ping utility using Scapy")
    parser.add_argument("destination", help="Destination IP address or hostname")
    parser.add_argument("-c", "--count", type=int, default=4, help="Number of packets to send")
    parser.add_argument("-t", "--ttl", type=int, default=64, help="Time-To-Live (TTL) for packets")
    parser.add_argument("-s", "--size", type=int, default=56, help="Size of each packet in bytes")
    parser.add_argument("-w", "--timeout", type=int, default=1, help="Timeout in seconds")

    args = parser.parse_args()

    if args.count <= 0:
        print("Error: Count must be a positive integer.")
        exit(1)
    
    if args.ttl <= 0:
        print("Error: TTL must be a positive integer.")
        exit(1)

    ping(args.destination, args.count, args.ttl, args.size, args.timeout)
