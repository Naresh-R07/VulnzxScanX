import argparse
import sys
from core.scanner import ScannerCore, SCAN_COMMANDS

def main():
    parser = argparse.ArgumentParser(description="VulnzxScanX - Vulnerability Scanner CLI")
    parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
    parser.add_argument("-s", "--type", choices=SCAN_COMMANDS.keys(), default="Quick", help="Scan type (default: Quick)")
    parser.add_argument("-o", "--output", help="Output file to save results")
    parser.add_argument("-r", "--rotate", action="store_true", help="Rotate IP using Tor before scanning")

    args = parser.parse_args()

    scanner = ScannerCore()

    print(f"[*] Target: {args.target}")
    print(f"[*] Scan Type: {args.type}")

    if args.rotate:
        scanner.rotate_ip()

    if not scanner.is_host_up(args.target):
        print(f"[!] Warning: Target {args.target} appears to be down. Proceeding anyway...")

    command = SCAN_COMMANDS[args.type](args.target)
    
    try:
        output_file = None
        if args.output:
            output_file = open(args.output, "a")

        for line in scanner.run_scan(command, args.target):
            sys.stdout.write(line)
            sys.stdout.flush()
            if output_file:
                output_file.write(line)
        
        if output_file:
            output_file.close()
            print(f"\n[+] Results saved to {args.output}")

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Cleaning up...")
        scanner.stop_scan()
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
