import sys
import logging
from usb_gui import USBMonitorGUI
from config import LOG_CONFIG

def setup_logging():
    """Configure logging for the application."""
    logging.basicConfig(
        level=logging.INFO,
        format=LOG_CONFIG['log_format'],
        handlers=[
            logging.FileHandler(LOG_CONFIG['log_file']),
            logging.StreamHandler(sys.stdout)
        ]
    )
def main():
    """Main entry point of the application."""
    try:
        # Setup logging
        setup_logging()
        logging.info("Starting USB Security Monitor...")
        
        # Create and run GUI
        app = USBMonitorGUI()
        app.run()
        
    except Exception as e:
        logging.error(f"Application error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 