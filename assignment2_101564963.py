"""
Author: Ghazaleh AzimiKorf
Assignment: #2
Description: Port Scanner — A tool that scans a target machine for open network ports
"""

# importing modules for networking, threading, database, and system info
import socket
import threading
import sqlite3
import os
import platform
import datetime


# printing system info to know environment
print("Python Version:", platform.python_version())
print("Operating System:", os.name)

# this dictionary stores common port numbers and their corresponding service names
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Alt"
}

# this class is the base class and only handles target
class NetworkTool:
    def __init__(self, target):
        # storing target as private so it can't be accessed directly
        self.__target = target

    # Q3: What is the benefit of using @property and @target.setter?
    # Using @property lets me access target like a normal variable while still keeping control over it.
    # The setter gives me a place to validate the value before saving it.
    # This is better than changing self.__target directly because it prevents invalid values like empty strings.
    @property
    def target(self):
        # returning the target value
        return self.__target

    @target.setter
    def target(self, value):
        # checking if value is valid before setting it
        if value != "":
            self.__target = value
        else:
            print("Error: Target cannot be empty")

    def __del__(self):
        # message when object is destroyed
        print("NetworkTool instance destroyed")

# Q1: How does PortScanner reuse code from NetworkTool?
# PortScanner reuses code from NetworkTool by inheriting the target property, setter, and constructor behavior.
# Instead of writing the same target-handling code again, I call super().__init__(target) in the child class.
# For example, the target validation still works in PortScanner because it uses the parent class setter.
class PortScanner(NetworkTool):
    def __init__(self, target):
        # calling parent constructor
        super().__init__(target)

        # list to store scan results
        self.scan_results = []

        # lock is used to prevent multiple threads writing at the same time
        self.lock = threading.Lock()

    def __del__(self):
        print("PortScanner instance destroyed")
        super().__del__()

    # this function scans one port
    def scan_port(self, port):
        sock = None

        # Q4: What would happen without try-except here?
        # Without try-except, a socket or network error could stop the whole program while scanning.
        # If the target machine is unreachable, the scan could crash before checking the rest of the ports.
        # Using try-except allows the program to handle the error and continue running safely.
        try:
            # creating TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # setting timeout so it doesn't wait too long
            sock.settimeout(1)

            # trying to connect to the port
            result = sock.connect_ex((self.target, port))

            # if result is 0, port is open
            status = "Open" if result == 0 else "Closed"

            # get service name or Unknown if not in dictionary
            service = common_ports.get(port, "Unknown")

            # using lock before modifying shared list
            self.lock.acquire()

            # saving result as tuple
            self.scan_results.append((port, status, service))

            # releasing lock after writing
            self.lock.release()

        except socket.error as e:
            # printing error if something goes wrong
            print(f"Error scanning port {port}: {e}")

        finally:
            # always closing socket to free resources
            if sock is not None:
                sock.close()

    # returns only open ports using list comprehension
    def get_open_ports(self):
        return [r for r in self.scan_results if r[1] == "Open"]

    # Q2: Why do we use threading instead of scanning one port at a time?
    # Threading lets the program check many ports at the same time instead of waiting for one port to finish before starting the next.
    # This makes scanning much faster, especially when each port can wait up to one second because of the timeout.
    # If I scanned 1024 ports one by one, the program could take a very long time to finish.
    def scan_range(self, start_port, end_port):
        threads = []

        # creating a thread for each port
        for port in range(start_port, end_port + 1):
            t = threading.Thread(target=self.scan_port, args=(port,))
            threads.append(t)

        # starting all threads
        for t in threads:
            t.start()

        # waiting for all threads to finish
        for t in threads:
            t.join()


# this function saves scan results into database
def save_results(target, results):
    conn = None
    try:
        # connecting to database
        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        # creating table if it does not exist
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            port INTEGER,
            status TEXT,
            service TEXT,
            scan_date TEXT
        )
        """)

        # inserting each result
        for r in results:
            cursor.execute("""
            INSERT INTO scans (target, port, status, service, scan_date)
            VALUES (?, ?, ?, ?, ?)
            """, (target, r[0], r[1], r[2], str(datetime.datetime.now())))

        # saving changes
        conn.commit()

    except sqlite3.Error as e:
        print("Database error:", e)

    finally:
        # closing connection
        if conn:
            conn.close()


# this function loads and prints past scan results
def load_past_scans():
    conn = None
    try:
        # checking if database exists
        if not os.path.exists("scan_history.db"):
            print("No past scans found.")
            return

        conn = sqlite3.connect("scan_history.db")
        cursor = conn.cursor()

        # selecting all rows
        cursor.execute("SELECT target, port, status, service, scan_date FROM scans")
        rows = cursor.fetchall()

        # printing results nicely
        if not rows:
            print("No past scans found.")
        else:
            for row in rows:
                print(f"[{row[4]}] {row[0]} : Port {row[1]} ({row[3]}) - {row[2]}")

    except sqlite3.Error:
        print("No past scans found.")

    finally:
        if conn:
            conn.close()


# ================= MAIN =================
if __name__ == "__main__":

    # getting target IP from user
    target = input("Enter target IP address: ").strip()
    if target == "":
        target = "127.0.0.1"

    # getting valid start port
    while True:
        try:
            start_port = int(input("Enter starting port number (1-1024): "))
            if not (1 <= start_port <= 1024):
                print("Port must be between 1 and 1024.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # getting valid end port
    while True:
        try:
            end_port = int(input("Enter ending port number (1-1024): "))
            if not (1 <= end_port <= 1024):
                print("Port must be between 1 and 1024.")
                continue
            if end_port < start_port:
                print("End port must be greater than or equal to start port.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a valid integer.")

    # creating scanner object
    scanner = PortScanner(target)

    print(f"Scanning {target} from port {start_port} to {end_port}...")

    # starting scan
    scanner.scan_range(start_port, end_port)

    # getting open ports
    open_ports = scanner.get_open_ports()

    print(f"--- Scan Results for {target} ---")

    # printing results
    for p, s, svc in open_ports:
        print(f"Port {p}: {s} ({svc})")

    print("------")
    print(f"Total open ports found: {len(open_ports)}")

    # saving results to database
    save_results(target, scanner.scan_results)

    # asking user if they want history
    choice = input("Would you like to see past scan history? (yes/no): ").lower()
    if choice in ["yes", "y"]:
        load_past_scans()


# Q5: New Feature Proposal
# I would add a feature to export only open ports to a CSV file so I can save the most useful results.
# I would use a list comprehension to filter only the tuples where the status is "Open" and then write those results into the CSV file.
# Diagram: See diagram_101564963.png in the repository root