import argparse
from scapy.all import *
import time
import socket

def scapy_tracert(destination, max_ttl=30, timeout=2000, resolve_names=True, src_ip=None):
    output_lines = []
    
    # Error Handling: Validate input parameters
    try:
        # Validate destination IP or hostname
        socket.gethostbyname(destination)
    except socket.gaierror:
        print(f"Error: Invalid destination IP or domain name '{destination}'")
        return
    
    if not isinstance(max_ttl, int) or max_ttl <= 0:
        print("Error: max_ttl must be a positive integer.")
        return
    
    if not isinstance(timeout, int) or timeout <= 0:
        print("Error: timeout must be a positive integer.")
        return
    
    # Check if source IP is valid and configured on the system
    if src_ip:
        try:
            socket.inet_aton(src_ip)
        except socket.error:
            print(f"Error: Source IP '{src_ip}' is invalid or not configured.")
            return

    print(f"Tracing route to {destination} with max TTL {max_ttl}, timeout {timeout} milliseconds.")
    output_lines.append(f"Tracing route to {destination} with max TTL {max_ttl}, timeout {timeout} milliseconds.\n")
    
    for ttl in range(1, max_ttl + 1):
        packet = IP(dst=destination, ttl=ttl, src=src_ip) / ICMP() / Raw(b'X' * 64)
        start_time = time.time()
        reply = None
        
        try:
            reply = sr1(packet, verbose=0, timeout=timeout / 1000.0)  # Convert milliseconds to seconds
        except Exception as e:
            print(f"Error: {e}")
            break
            
        end_time = time.time()
        rtt = (end_time - start_time) * 1000  # Convert to milliseconds
        
        if reply:
            hop_ip = reply.src
            line = f"{ttl:<4} {hop_ip:<20} {round(rtt, 2):>7} ms"
        else:
            hop_ip = "*"
            line = f"{ttl:<4} {hop_ip:<20} Request timed out."
        
        print(line)
        output_lines.append(line + "\n")

        # If we reached the destination, break the loop
        if reply and reply.haslayer(ICMP) and reply[ICMP].type == 0:
            print(f"Reached destination: {destination} in {ttl} hops.")
            output_lines.append(f"Reached destination: {destination} in {ttl} hops.\n")
            break
if __name__ == "__main__":
    # Set up argument parsing
    parser = argparse.ArgumentParser(description="Scapy-based tracert tool")
    parser.add_argument("destination", help="The destination hostname or IP address")
    parser.add_argument("-t", "--max-ttl", type=int, default=30, help="Max number of hops (TTL)")
    parser.add_argument("-w", "--timeout", type=int, default=2000, help="Timeout in milliseconds for each hop")
    parser.add_argument("-d", "--no-resolve", action='store_true', help="Do not resolve hostnames to IP addresses")
    
    # Parse the arguments
    args = parser.parse_args()
    
    # Call the scapy_tracert function with the provided arguments
    scapy_tracert(args.destination, max_ttl=args.max_ttl, timeout=args.timeout, resolve_names=not args.no_resolve)
