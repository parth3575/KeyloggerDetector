# Keylogger Detector

This is a Python-based Keylogger Detector tool implemented using the Tkinter GUI framework and various system monitoring techniques. It helps identify potential keyloggers running on your Windows system and provides options to terminate processes, delete registry entries, and remove keylogger-related files.

## Features

- Detects keyloggers by searching for known keylogger signatures in process descriptions, registry entries, and file paths.
- Monitors CPU and memory usage of running processes.
- Analyzes the process tree to identify parent-child process relationships.
- Provides options to terminate keylogger processes.
- Allows the deletion of keylogger-related registry entries.
- Deletes keylogger files associated with identified processes.
- User-friendly graphical interface.

## Prerequisites

- Python 3.x
- Tkinter (usually included with Python)
- psutil library (`pip install psutil`)
- ctypes library (usually included with Python)
- Windows OS (tested on Windows)

## Usage

1. Clone the repository or download the source code.

2. Run the `keylogger_detector.py` script.

3. If not running with administrator privileges, the script will prompt you to run as an administrator.

4. Click the "Start Detector" button to begin the detection process.

5. The tool will display information about running processes, CPU and memory usage, and detected keyloggers in the GUI console.

6. If keyloggers are detected, you will have the option to delete them. The tool will prompt you for confirmation.

## Known Signatures

The tool uses a list of known keylogger signatures to detect potential threats. You can customize this list by adding or removing regular expressions in the `known_signatures` list within the script.

## Disclaimer

This tool is intended for educational and informational purposes only. It is not guaranteed to detect all keyloggers, and its effectiveness may vary based on the specific keylogger and system configuration. Use this tool responsibly and in compliance with applicable laws and regulations.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
