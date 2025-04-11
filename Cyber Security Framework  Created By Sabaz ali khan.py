#!/usr/bin/env python3
import socket
import hashlib
import threading
import queue
import time

# Simple Cybersecurity Framework by Mr. Sabaz Ali Khan (for educational purposes only)
class CyberFramework:
    def __init__(self):
        self.target = ""
        self.ports = []
        self.q = queue.Queue()

    def set_target(self, target):
        """Set the target IP or hostname."""
        self.target = target
        print(f"Target set to: {self.target}")

    def port_scan(self, port):
        """Scan a single port on the target."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target, port))
            if result == 0:
                print(f"Port {port} is open")
                self.ports.append(port)
            sock.close()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")

    def scan_ports(self, start_port, end_port):
        """Scan a range of ports using threads."""
        print(f"Scanning ports {start_port} to {end_port} on {self.target}...")
        for port in range(start_port, end_port + 1):
            self.q.put(port)

        threads = []
        for _ in range(50):  # Adjust number of threads as needed
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            threads.append(t)

        self.q.join()
        print("Scan completed. Open ports:", self.ports)

    def worker(self):
        """Thread worker for port scanning."""
        while True:
            try:
                port = self.q.get_nowait()
            except queue.Empty:
                break
            self.port_scan(port)
            self.q.task_done()

    def hash_password(self, password):
        """Hash a password using SHA-256."""
        try:
            hashed = hashlib.sha256(password.encode()).hexdigest()
            print(f"Password: {password} -> Hashed: {hashed}")
            return hashed
        except Exception as e:
            print(f"Error hashing password: {e}")
            return None

    def save_results(self, filename):
        """Save scan results to a file."""
        try:
            with open(filename, "w") as f:
                f.write(f"Cyber Framework Results\n")
                f.write(f"Target: {self.target}\n")
                f.write(f"Open Ports: {self.ports}\n")
                f.write(f"Timestamp: {time.ctime()}\n")
            print(f"Results saved to {filename}")
        except Exception as e:
            print(f"Error saving results: {e}")

def main():
    print("Cyber Framework by Mr. Sabaz Ali Khan - Educational Tool")
    framework = CyberFramework()

    # Example usage
    target = input("Enter target IP or hostname (e.g., 127.0.0.1): ")
    framework.set_target(target)

    start_port = int(input("Enter start port (e.g., 1): "))
    end_port = int(input("Enter end port (e.g., 100): "))
    framework.scan_ports(start_port, end_port)

    password = input("Enter a password to hash: ")
    framework.hash_password(password)

    framework.save_results("scan_results.txt")

if __name__ == "__main__":
    main()