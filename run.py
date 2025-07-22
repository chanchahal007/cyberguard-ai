#!/usr/bin/env python3
"""
CyberGuard AI - Intelligent Security Operations Tool
Main application launcher

Authors: Jimmy Lu, Chanpreet Singh
Course: INFO 3171 S10
Date: July 17, 2025
"""

import sys
import os
import argparse
import logging
from pathlib import Path

# Add src directory to Python path
src_dir = Path(__file__).parent / "src"
sys.path.insert(0, str(src_dir))

from src.main import CyberGuardAI
from src.utils.logger import setup_logging
from src.utils.config import ConfigManager

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="CyberGuard AI - Intelligent Security Operations Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py --gui                    # Launch with GUI
  python run.py --cli --log-file /path   # CLI mode with log file
  python run.py --scan --directory /logs # Batch scan directory
        """
    )
    
    parser.add_argument(
        "--gui", 
        action="store_true", 
        help="Launch GUI interface (default)"
    )
    
    parser.add_argument(
        "--cli", 
        action="store_true", 
        help="Run in command line interface mode"
    )
    
    parser.add_argument(
        "--log-file", 
        type=str, 
        help="Path to log file for analysis"
    )
    
    parser.add_argument(
        "--directory", 
        type=str, 
        help="Directory containing log files to scan"
    )
    
    parser.add_argument(
        "--scan", 
        action="store_true", 
        help="Perform batch scanning operation"
    )
    
    parser.add_argument(
        "--config", 
        type=str, 
        default="config/settings.json",
        help="Path to configuration file"
    )
    
    parser.add_argument(
        "--debug", 
        action="store_true", 
        help="Enable debug logging"
    )
    
    parser.add_argument(
        "--output", 
        type=str, 
        help="Output file for reports"
    )
    
    return parser.parse_args()

def main():
    """Main application entry point"""
    try:
        # Parse command line arguments
        args = parse_arguments()
        
        # Setup logging
        log_level = logging.DEBUG if args.debug else logging.INFO
        setup_logging(level=log_level)
        
        logger = logging.getLogger(__name__)
        logger.info("Starting CyberGuard AI Security Tool")
        
        # Load configuration
        config_manager = ConfigManager(args.config)
        config = config_manager.load_config()
        
        # Initialize the main application
        app = CyberGuardAI(config)
        
        # Determine run mode
        if args.cli or args.scan:
            logger.info("Running in CLI mode")
            app.run_cli(args)
        else:
            logger.info("Launching GUI interface")
            app.run_gui()
            
    except KeyboardInterrupt:
        logger.info("Application interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
