import tkinter as tk
import time
import re
import psutil
import ctypes
import sys
import os
import winreg
import subprocess

class KeyloggerDetector:
    def __init__(self):
        # Initialize the GUI
        self.root = tk.Tk()
        self.root.title("Keylogger Detector")

        # Create a button to start the detection
        self.start_button = tk.Button(self.root, text="Start Detector", command=self.start_detector)
        self.start_button.pack(pady=10)

        # Create a text widget for displaying logs
        self.console_text = tk.Text(self.root, height=40, width=100, bg="black", fg="#0078D4")
        self.console_text.pack(pady=5)

        # Define a list of known keylogger signatures or patterns
        self.known_signatures = [
            re.compile(r'.*logs the keys struck on your keyboard.*covert manner.*', re.IGNORECASE),
            re.compile(r'.*keystroke recorder.*', re.IGNORECASE),
            re.compile(r'.*keyboard monitoring.*', re.IGNORECASE),
            re.compile(r'.*keylogger.*', re.IGNORECASE),
            re.compile(r'.*keystroke capture.*', re.IGNORECASE),
            re.compile(r'.*key press logger.*', re.IGNORECASE),
            re.compile(r'.*keyboard tracking.*', re.IGNORECASE),
            re.compile(r'.*input recorder.*', re.IGNORECASE),
            re.compile(r'.*keyboard spy.*', re.IGNORECASE),
            re.compile(r'.*key record.*', re.IGNORECASE),
            re.compile(r'.*keystroke logger.*', re.IGNORECASE),
            re.compile(r'.*activity monitor.*', re.IGNORECASE),
            re.compile(r'.*system surveillance.*', re.IGNORECASE),
            re.compile(r'.*password grabber.*', re.IGNORECASE),
            re.compile(r'.*screen capture.*', re.IGNORECASE),
            re.compile(r'.*remote access.*', re.IGNORECASE),
            re.compile(r'.*data theft.*', re.IGNORECASE),
            re.compile(r'.*spyware.*', re.IGNORECASE),
            re.compile(r'.*invisible mode.*', re.IGNORECASE),
            re.compile(r'.*undetectable.*', re.IGNORECASE),
            # Add more signatures here
        ]

    def start_detector(self):
        # Disable the start button during detection
        self.start_button.config(state=tk.DISABLED)
        # Clear the console text widget
        self.clear_console_text()
        # Insert a message indicating the start of detection
        self.insert_console_text("Starting keylogger detection...")
        # Start the keylogger detection process
        self.detect_keyloggers()
        # Insert a message indicating the end of detection
        self.insert_console_text("Detection complete.")
        # Re-enable the start button
        self.start_button.config(state=tk.NORMAL)

    def insert_console_text(self, text):
        # Get the current timestamp
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        # Format the log message with a timestamp
        formatted_text = f"{timestamp} - INFO - {text}"
        # Insert the formatted message into the console text widget
        self.console_text.insert(tk.END, formatted_text + "\n")
        # Scroll to the end of the text widget
        self.console_text.see(tk.END)
        # Update the GUI
        self.root.update()

    def clear_console_text(self):
        # Clear the console text widget
        self.console_text.delete(1.0, tk.END)

    def detect_keyloggers(self):
        # Disable the start button during detection
        self.start_button.config(state=tk.DISABLED)
        # Clear the console text widget
        self.clear_console_text()
        # Insert a message indicating the start of detection
        self.insert_console_text("Starting keylogger detection...")

        # List to store detected keyloggers
        detected_keyloggers = []

        # Call the detection methods individually
        self.scan_registry(detected_keyloggers)
        self.scan_file_system(detected_keyloggers)
        self.analyze_process_tree(detected_keyloggers)

        # Filter out any non-process objects (strings) from detected_keyloggers
        detected_keyloggers = [process for process in detected_keyloggers if isinstance(process, psutil.Process)]

        # Iterate through running processes and perform additional checks
        for process in psutil.process_iter(attrs=['pid', 'name', 'cmdline']):
            process_name = process.info['name']

            # Check if 'cmdline' is iterable before joining it
            if 'cmdline' in process.info and isinstance(process.info['cmdline'], (list, tuple)):
                process_description = " ".join(process.info['cmdline'])
            else:
                process_description = "Unknown"

            
            # Check if this process has already been detected
            if process in detected_keyloggers:
                continue

            # Monitor CPU and memory usage of the process
            try:
                process_cpu_percent = process.cpu_percent()
                process_memory_percent = process.memory_percent()
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                process_cpu_percent = 0
                process_memory_percent = 0

            # Insert process info into the console, including CPU and memory usage
            self.insert_console_text(f"Scanning process: {process_name}")
            self.insert_console_text(f"Retrieved process description: {process_description}")
            self.insert_console_text(f"CPU Usage: {process_cpu_percent}%")
            self.insert_console_text(f"Memory Usage: {process_memory_percent}%")
            self.insert_console_text("==============================================================")

            # Check for both high CPU usage and a matching signature
            if (
                process_name not in detected_keyloggers
                and process.cpu_percent() > 50  # Adjust the CPU usage threshold as needed
                and any(signature.match(process_description) for signature in self.known_signatures)
            ):
                detected_keyloggers.append(process_name)

            # Check for heuristic matches based on process name or window title
            if process_name not in detected_keyloggers and (self.heuristic_process_name(process_name) or self.heuristic_window_title(process_name)):
                detected_keyloggers.append(process_name)

        # Insert a message indicating the end of the scan
        self.insert_console_text("Complete scan.")

        # If keyloggers are detected, prompt the user to delete them
        if detected_keyloggers:
            self.insert_console_text("Detected keyloggers:")
            for keylogger in detected_keyloggers:
                self.insert_console_text(f"Process Name: {keylogger}")
                self.insert_console_text("=" * 30)
            # Prompt the user for deletion
            user_response = input("Detected keyloggers. Do you want to delete them? (yes/no): ").strip().lower()
            if user_response == 'yes':
                self.delete_keyloggers(detected_keyloggers)
        else:
            # If no keyloggers are detected, inform the user
            self.insert_console_text("No keyloggers detected.")



    def heuristic_process_name(self, process_name):
        # Check if the process name contains 'keylogger'
        return "keylogger" in process_name.lower()

    def heuristic_window_title(self, process_name):
        # Check if any process has a window title containing 'keylogger'
        for window in psutil.process_iter(attrs=['pid', 'name']):
            if window.info['name'] == process_name:
                try:
                    window_title = window.info['name']
                    if "keylogger" in window_title.lower():
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        return False
    
    def scan_registry(self, detected_keyloggers):
        # Define the Windows Registry keys to check
        registry_keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServices"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\RunServicesOnce"),
            # Add more keys as needed
        ]

        for root_key, subkey in registry_keys:
            try:
                with winreg.OpenKey(root_key, subkey, 0, winreg.KEY_READ) as key:
                    values = []
                    try:
                        i = 0
                        while True:
                            try:
                                value = winreg.EnumValue(key, i)
                                name = value[0]  # Extract the name from the values tuple
                                values.append(name)
                                i += 1
                            except WindowsError:
                                break
                    except WindowsError:
                        pass

                    # Check if any of the values match known signatures
                    matching_values = [val for val in values if any(signature.match(val) for signature in self.known_signatures)]
                    if matching_values:
                        self.insert_console_text(f"Detected keylogger-related registry entries: {matching_values}")
                        detected_keyloggers.extend(matching_values)
            except WindowsError:
                pass

    def analyze_process_tree(self, detected_keyloggers):
        # Get a list of all running processes
        all_processes = psutil.process_iter(attrs=['pid', 'name', 'ppid'])

        # Create a dictionary to store parent-child process relationships
        process_tree = {}

        for process in all_processes:
            pid = process.info['pid']
            parent_pid = process.info['ppid']
            process_name = process.info['name']

            if parent_pid in process_tree:
                process_tree[parent_pid].append(pid)
            else:
                process_tree[parent_pid] = [pid]

            # Check if the current process is a potential keylogger
            if any(signature.match(process_name) for signature in self.known_signatures):
                keylogger_pid = pid  # Define keylogger_pid in this scope
                # Append the entire process object to the list
                detected_keyloggers.append(process)

            # Check for child processes of potential keyloggers
            for keylogger_process in detected_keyloggers:
                if isinstance(keylogger_process, psutil.Process):  # Check if it's a valid process object
                    keylogger_pid = keylogger_process.pid  # Access 'pid' directly
                    if keylogger_pid in process_tree:
                        child_pids = process_tree[keylogger_pid]
                        for child_pid in child_pids:
                            try:
                                child_process = psutil.Process(child_pid)
                                child_process_name = child_process.name  # Access 'name' directly
                                self.insert_console_text(f"Child process of potential keylogger ({keylogger_pid}): {child_process_name}")
                            except psutil.NoSuchProcess:
                                pass

    # # Insert a message indicating the end of the scan
    # self.insert_console_text("Complete scan.")


    def scan_file_system(self, detected_keyloggers):
        # Define directories to check for keylogger-related files
        directories_to_check = [
            os.environ.get("APPDATA"),  # User's AppData directory
            os.path.join(os.environ.get("SYSTEMROOT"), "System32"),  # System32 directory
            # Add more directories to check here
        ]

        for directory in directories_to_check:
            if directory:
                for root, _, files in os.walk(directory):
                    for file_name in files:
                        # Initialize file_path with None (or an appropriate default value)
                        file_path = None
                        try:
                            file_path = os.path.join(root, file_name)
                            if any(signature.match(file_name) for signature in self.known_signatures):
                                self.insert_console_text(f"Detected keylogger-related file: {file_path}")
                                detected_keyloggers.append(file_path)
                        except Exception as e:
                            # Handle exceptions that may occur during file analysis
                            self.insert_console_text(f"Error analyzing file {file_path}: {str(e)}")

    def delete_keyloggers(self, keyloggers):
        for keylogger in keyloggers:
            if isinstance(keylogger, psutil.Process):  # Check if it's a valid process object
                try:
                    # Get information about the keylogger process
                    process = keylogger
                    process_info = process.as_dict(attrs=['pid', 'name'])  # Use 'as_dict' to get process information

                    # Check if the 'pid' attribute is present in process_info
                    if 'pid' in process_info:
                        process_pid = process_info['pid']
                        process_name = process_info['name']

                        # Check if the process is still running
                        if self.is_process_running(process_name):
                            # Terminate the process using the 'taskkill' command
                            os.system(f"taskkill /F /PID {process_pid}")
                            # Wait for a moment
                            time.sleep(2)

                            # Check if the process is still running after termination
                            if self.is_process_running(process_name):
                                self.insert_console_text(f"Failed to terminate keylogger process: {process_name}")
                            else:
                                # Insert a message indicating successful termination
                                self.insert_console_text(f"Terminated keylogger process: {process_name}")
                                # Delete keylogger files
                                self.delete_keylogger_files(process_pid)
                        else:
                            self.insert_console_text(f"Keylogger process not found: {process_name}")

                    else:
                        # Handle cases where 'pid' is not present in process_info
                        self.insert_console_text(f"Process information missing 'pid' attribute: {process_info}")
                    
                except psutil.NoSuchProcess:
                    self.insert_console_text(f"Keylogger process not found: {process_name}")
                except (psutil.AccessDenied, ValueError):
                    self.insert_console_text(f"Error while terminating keylogger process: {process_name}")
            elif isinstance(keylogger, str):
                # Handle the case where keylogger is a string (e.g., a registry entry)
                self.insert_console_text(f"Deleting keylogger-related entry: {keylogger}")
                self.delete_keylogger_entry(keylogger)

    def delete_keylogger_entry(self, registry_entry):
        try:
            # Construct the command as a list of arguments
            cmd = ["reg", "delete", registry_entry, "/f"]
        
            # Execute the command using subprocess
            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            self.insert_console_text(f"Deleted keylogger-related entry: {registry_entry}")
        except subprocess.CalledProcessError as e:
            self.insert_console_text(f"Error deleting keylogger-related entry: {e}")



    def is_process_running(self, process_name):
        # Check if a process with the given name is running
        for process in psutil.process_iter(attrs=['name']):
            if process.info['name'] == process_name:
                return True
        return False

    def delete_keylogger_files(self, process_pid):
        # Get the filepath of the keylogger associated with the process
        keylogger_filepath = self.get_keylogger_filepath(process_pid)
        # Check if the filepath exists and delete the file
        if keylogger_filepath and os.path.exists(keylogger_filepath):
            os.remove(keylogger_filepath)
            # Insert a message indicating successful file deletion
            self.insert_console_text(f"Deleted keylogger file: {keylogger_filepath}")

    def get_keylogger_filepath(self, process_pid):
        try:
            # Get the list of open files for the process
            process = psutil.Process(process_pid)
            for file_info in process.open_files():
                filepath = file_info.path
                # Check if the filepath contains 'keylogger'
                if "keylogger" in filepath.lower():
                    return filepath
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return None

    def run(self):
        # Start the main GUI event loop
        self.root.mainloop()

if __name__ == "__main__":
    # Check if the script is running with administrator privileges
    if ctypes.windll.shell32.IsUserAnAdmin():
        # Create an instance of the KeyloggerDetector class and start the GUI
        detector = KeyloggerDetector()
        detector.run()
    else:
        # If not running as admin, prompt the user for admin rights and restart
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
