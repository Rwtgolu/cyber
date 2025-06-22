import os
import time
import logging
from typing import List, Optional, Callable
import threading
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import platform
import shutil

from config import EMAIL_CONFIG, DEFAULT_SUSPICIOUS_EXTENSIONS

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class USBMonitor:
    def __init__(self):
        self.is_monitoring = False
        self.monitor_thread: Optional[threading.Thread] = None
        self.suspicious_extensions = DEFAULT_SUSPICIOUS_EXTENSIONS.copy()
        self.callback: Optional[Callable] = None
        self.detected_drives = set()
        self.is_windows = platform.system() == 'Windows'

    def set_callback(self, callback: Callable) -> None:
        """Set callback function for GUI updates."""
        self.callback = callback

    def log_event(self, message: str, level: str = 'info') -> None:
        """Log events and trigger callback if set."""
        getattr(logging, level)(message)
        if self.callback:
            self.callback(message)

    def get_drive_info(self, drive: str) -> dict:
        """Get basic drive information."""
        try:
            if self.is_windows:
                import win32file
                import win32api
                
                volume_name = win32api.GetVolumeInformation(drive)[0]
                drive_type = win32file.GetDriveType(drive)
                drive_types = {
                    win32file.DRIVE_REMOVABLE: "Removable",
                    win32file.DRIVE_FIXED: "Fixed",
                    win32file.DRIVE_REMOTE: "Network",
                    win32file.DRIVE_CDROM: "CD-ROM",
                    win32file.DRIVE_RAMDISK: "RAM Disk"
                }
                drive_type_name = drive_types.get(drive_type, "Unknown")
            else:
                volume_name = os.path.basename(drive)
                drive_type_name = "Removable"
            
            return {
                "name": volume_name or "Unnamed Drive",
                "type": drive_type_name,
                "path": drive
            }
        except Exception as e:
            self.log_event(f"Error getting drive info for {drive}: {str(e)}", 'error')
            return {
                "name": os.path.basename(drive) or "Unknown",
                "type": "Unknown",
                "path": drive
            }

    def get_connected_drives(self) -> set:
        """Get currently connected removable USB drives only."""
        if self.is_windows:
            try:
                import win32file
                drives = set()
                bitmask = win32file.GetLogicalDrives()
                for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                    if bitmask & 1:
                        drive = f"{letter}:\\"
                        # Only add if it's specifically a removable drive
                        if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                            drives.add(drive)
                    bitmask >>= 1
                return drives
            except ImportError:
                self.log_event("Windows-specific modules not available", 'error')
                return set()
        else:
            # macOS implementation - only detect removable volumes
            drives = set()
            volumes_dir = '/Volumes'
            try:
                for volume in os.listdir(volumes_dir):
                    volume_path = os.path.join(volumes_dir, volume)
                    # Skip internal drive and non-mounted volumes
                    if (volume != 'Macintosh HD' and 
                        os.path.ismount(volume_path) and 
                        not volume.startswith('.')):  # Skip hidden volumes
                        # Additional check for removable media on macOS
                        try:
                            # Use diskutil to check if it's a removable drive
                            import subprocess
                            result = subprocess.run(['diskutil', 'info', volume_path], 
                                                 capture_output=True, text=True)
                            if 'Removable Media: Yes' in result.stdout:
                                drives.add(volume_path)
                        except Exception:
                            # If diskutil check fails, use basic mount point check
                            if not volume_path.startswith('/Volumes/Macintosh'):
                                drives.add(volume_path)
                return drives
            except Exception as e:
                self.log_event(f"Error getting drives: {str(e)}", 'error')
                return set()

    def scan_drive(self, drive: str) -> List[str]:
        """Scan a drive for suspicious files based on extensions."""
        suspicious_files = []
        drive = os.path.abspath(drive)  # Normalize the path
        
        # Verify this is actually a removable drive before scanning
        if self.is_windows:
            try:
                import win32file
                if win32file.GetDriveType(drive) != win32file.DRIVE_REMOVABLE:
                    self.log_event(f"Skipping scan of non-removable drive: {drive}", 'warning')
                    return []
            except ImportError:
                pass
        else:
            # For macOS, verify it's in /Volumes and not the system drive
            if not (drive.startswith('/Volumes/') and 
                   not drive.startswith('/Volumes/Macintosh')):
                self.log_event(f"Skipping scan of non-removable drive: {drive}", 'warning')
                return []
        
        for root, _, files in os.walk(drive, followlinks=False):
            # Double check we're still within the USB drive
            if not os.path.abspath(root).startswith(drive):
                continue
                
            for file in files:
                file_path = os.path.join(root, file)
                
                # Skip if it's a symlink or not on the USB drive
                if os.path.islink(file_path):
                    continue
                    
                # Verify we're still on the USB drive
                abs_file_path = os.path.abspath(file_path)
                if not abs_file_path.startswith(drive):
                    continue
                
                try:
                    # Check file extension
                    if any(file.lower().endswith(ext) for ext in self.suspicious_extensions):
                        rel_path = os.path.relpath(file_path, drive)
                        self.log_event(f"Suspicious file found on USB: {rel_path}", 'warning')
                        suspicious_files.append(rel_path)
                
                except (PermissionError, OSError) as e:
                    self.log_event(f"Access denied to USB file: {os.path.relpath(file_path, drive)}: {str(e)}", 'warning')
                except Exception as e:
                    self.log_event(f"Error scanning USB file: {os.path.relpath(file_path, drive)}: {str(e)}", 'error')
        
        return suspicious_files

    def send_email_alert(self, suspicious_files: List[str], drive: str) -> None:
        """Send email alert for suspicious files."""
        if not all([EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['sender_email'],
                   EMAIL_CONFIG['sender_password'], EMAIL_CONFIG['recipient_email']]):
            self.log_event("Email configuration incomplete. Skipping alert.", 'warning')
            return

        try:
            msg = MIMEMultipart()
            msg['From'] = EMAIL_CONFIG['sender_email']
            msg['To'] = EMAIL_CONFIG['recipient_email']
            msg['Subject'] = f"USB Security Alert - Suspicious Files Detected"

            drive_info = self.get_drive_info(drive)
            body = f"""
            USB Security Alert

            Drive Information:
            - Name: {drive_info['name']}
            - Type: {drive_info['type']}
            - Path: {drive_info['path']}
            
            Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            
            Suspicious files detected:
            {chr(10).join(suspicious_files)}
            
            This is an automated alert from your USB Security Monitor.
            """
            
            msg.attach(MIMEText(body, 'plain'))

            with smtplib.SMTP(EMAIL_CONFIG['smtp_server'], EMAIL_CONFIG['smtp_port']) as server:
                server.starttls()
                server.login(EMAIL_CONFIG['sender_email'], EMAIL_CONFIG['sender_password'])
                server.send_message(msg)
                
            self.log_event("Email alert sent successfully")
        except Exception as e:
            self.log_event(f"Failed to send email alert: {str(e)}", 'error')

    def monitor_loop(self) -> None:
        """Main monitoring loop - only checks for USB insertions/removals."""
        last_no_usb_message = 0
        message_interval = 60  # Show "No USB connected" message every 60 seconds
        
        while self.is_monitoring:
            try:
                current_drives = self.get_connected_drives()
                current_time = time.time()
                
                if not current_drives:
                    # Show "No USB connected" message periodically
                    if current_time - last_no_usb_message >= message_interval:
                        self.log_event("No USB drives connected")
                        last_no_usb_message = current_time
                else:
                    # Reset the message timer when USB is connected
                    last_no_usb_message = 0
                    
                    # Check for new drives and scan them once on insertion
                    new_drives = current_drives - self.detected_drives
                    for drive in new_drives:
                        drive_info = self.get_drive_info(drive)
                        self.log_event(f"New USB drive detected: {drive_info['name']} ({drive})")
                        
                        # One-time scan of the newly inserted drive
                        self.log_event(f"Starting one-time scan of newly inserted drive: {drive}")
                        suspicious_files = self.scan_drive(drive)
                        if suspicious_files:
                            self.log_event(f"Found {len(suspicious_files)} suspicious files during initial scan")
                            self.send_email_alert(suspicious_files, drive)
                        else:
                            self.log_event(f"Initial scan complete - no suspicious files found")
                    
                    # Track removed drives
                    removed_drives = self.detected_drives - current_drives
                    for drive in removed_drives:
                        self.log_event(f"USB drive removed: {drive}")
                
                self.detected_drives = current_drives
                time.sleep(1)  # Check for new/removed drives every second
                
            except Exception as e:
                self.log_event(f"Error in monitor loop: {str(e)}", 'error')
                time.sleep(5)  # Wait longer on error

    def start_monitoring(self) -> None:
        """Start USB monitoring."""
        if not self.is_monitoring:
            self.is_monitoring = True
            self.monitor_thread = threading.Thread(target=self.monitor_loop)
            self.monitor_thread.daemon = True
            self.monitor_thread.start()
            self.log_event("USB monitoring started")

    def stop_monitoring(self) -> None:
        """Stop USB monitoring."""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()
        self.log_event("USB monitoring stopped")

    def update_suspicious_extensions(self, extensions: List[str]) -> None:
        """Update the list of suspicious file extensions."""
        self.suspicious_extensions = extensions
        self.log_event(f"Updated suspicious extensions: {', '.join(extensions)}")

    def get_usb_history(self) -> List[dict]:
        """Get USB activity history."""
        return self.usb_history 