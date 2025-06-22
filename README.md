# USB Security Monitor

A lightweight cybersecurity tool designed to monitor USB device connections in real-time. It provides a simple, user-friendly interface to track when USB drives are connected or disconnected from your system.

## Features

- **Real-Time USB Monitoring**: Detects USB drive connections and disconnections instantly.
- **Simple GUI**: A clean, single-window interface with essential controls.
-   - **Start/Stop Monitoring**: Easily start and stop the monitoring process with dedicated buttons.
-   - **Status Indicator**: Shows whether monitoring is "Active" or "Stopped."
- **Activity Terminal**: A built-in terminal window that logs all USB events, such as drive detection and removal, providing a clear and immediate history of activity.

## Requirements

- Python 3.7 or higher
- **Tkinter**: This library is required for the GUI.
  - On macOS, you may need to install it separately if it's not included with your Python installation. You can install it with Homebrew:
    ```bash
    brew install python-tk
    ```

## How to Use

1. **Clone or download the project.**

2. **Install any required packages** (if you have a `requirements.txt` file):
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python cyber/main.py
   ```

4. **Operate the GUI**:
   - Click **"Start Monitoring"** to begin watching for USB device changes.
   - The terminal at the bottom of the window will display logs for any connected or removed drives.
   - Click **"Stop Monitoring"** to pause the process.

## Project Structure

- `main.py`: The entry point of the application.
- `usb_gui.py`: Contains the code for the graphical user interface (GUI).
- `monitor.py`: The backend logic for detecting and monitoring USB devices.
- `config.py`: (If used) a file for storing configuration variables.

---

No email notifications or advanced settings are included in this simplified version.



