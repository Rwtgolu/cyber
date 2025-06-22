import tkinter as tk
from tkinter import ttk, scrolledtext
from datetime import datetime
from monitor import USBMonitor

# Global variables for GUI elements and monitor
root = None
monitor = None
start_button = None
status_label = None
drives_tree = None
log_text = None

def create_gui():
    global root, start_button, status_label, drives_tree, log_text
    root = tk.Tk()
    root.title("USB Security Monitor")
    root.geometry("600x500")

    main_frame = ttk.Frame(root, padding="10")
    main_frame.pack(fill=tk.BOTH, expand=True)

    # Start/Stop Monitoring button
    start_button = ttk.Button(main_frame, text="Start Monitoring", command=toggle_monitoring)
    start_button.pack(pady=5, anchor=tk.W)

    # Status label
    status_label = ttk.Label(main_frame, text="Monitoring: Stopped")
    status_label.pack(pady=5, anchor=tk.W)

    # Connected USB Drives
    drives_frame = ttk.LabelFrame(main_frame, text="Connected USB Drives", padding="5")
    drives_frame.pack(fill=tk.X, pady=5)
    drives_tree = ttk.Treeview(drives_frame, columns=('Type',), height=3)
    drives_tree.heading('#0', text='Drive Name')
    drives_tree.heading('Type', text='Type')
    drives_tree.pack(fill=tk.X, padx=5, pady=5)

    # Activity Log
    log_frame = ttk.LabelFrame(main_frame, text="Activity Log", padding="5")
    log_frame.pack(fill=tk.BOTH, expand=True, pady=5)
    log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, height=15)
    log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

def toggle_monitoring():
    global monitor, start_button, status_label, drives_tree
    if not monitor.is_monitoring:
        monitor.start_monitoring()
        start_button.configure(text="Stop Monitoring")
        status_label.configure(text="Monitoring: Active")
        update_drives_list()
    else:
        monitor.stop_monitoring()
        start_button.configure(text="Start Monitoring")
        status_label.configure(text="Monitoring: Stopped")
        drives_tree.delete(*drives_tree.get_children())

def update_drives_list():
    global monitor, drives_tree
    drives_tree.delete(*drives_tree.get_children())
    for drive in monitor.detected_drives:
        drive_info = monitor.get_drive_info(drive)
        drives_tree.insert('', 'end', text=f"{drive_info['name']}", values=(drive_info['type'],))

def update_log(message: str):
    global log_text
    log_text.insert(tk.END, f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {message}\n")
    log_text.see(tk.END)
    if "USB drive detected" in message or "USB drive removed" in message:
        update_drives_list()

def main():
    global monitor
    monitor = USBMonitor()
    monitor.set_callback(update_log)
    create_gui()
    root.mainloop()

if __name__ == "__main__":
    main() 