# Default suspicious file extensions to monitor
DEFAULT_SUSPICIOUS_EXTENSIONS = [
    '.exe', '.bat', '.vbs', '.ps1', '.cmd', '.scr', '.js',
    '.jar', '.msi', '.dll', '.hta', '.com', '.pif', '.reg'
]
EMAIL_CONFIG = {
    'smtp_server': 'smtp.gmail.com',
    'smtp_port': 587,
    'sender_email': '',  # To be configured by user
    'sender_password': '',  # To be configured by user
    'recipient_email': '',  # To be configured by user
}
GUI_CONFIG = {
    'window_title': 'USB Security Monitor',
    'window_size': '800x600',
    'theme_bg': '#f0f0f0',
    'theme_primary': '#2196F3',
    'theme_danger': '#f44336',
    'theme_success': '#4CAF50',
    'font_family': 'Helvetica',
    'font_size': 10
}
# Logging Configuration
LOG_CONFIG = {
    'log_file': 'usb_monitor.log',
    'max_log_size': 5242880,  # 5MB
    'backup_count': 3,
    'log_format': '%(asctime)s - %(levelname)s - %(message)s'
} 