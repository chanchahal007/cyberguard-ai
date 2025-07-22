"""
CyberGuard AI - Main Application Controller
Coordinates all components and manages application lifecycle
"""

import logging
import sys
import threading
import time
from pathlib import Path
from typing import Dict, Any, Optional

from core.log_analyzer import LogAnalyzer
from core.threat_detector import ThreatDetector
from core.incident_responder import IncidentResponder
from ai.ml_models import MLModelManager
from gui.main_window import MainWindow
from data.database import DatabaseManager
from utils.config import ConfigManager

class CyberGuardAI:
    """Main application controller class"""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the CyberGuard AI application"""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.running = False
        
        # Initialize core components
        self._initialize_components()
        
    def _initialize_components(self):
        """Initialize all application components"""
        try:
            self.logger.info("Initializing CyberGuard AI components...")
            
            # Database manager
            self.db_manager = DatabaseManager(self.config.get('database', {}))
            
            # ML Model manager
            self.ml_manager = MLModelManager(self.config.get('ml_models', {}))
            
            # Core security components
            self.log_analyzer = LogAnalyzer(self.config.get('log_analysis', {}))
            self.threat_detector = ThreatDetector(
                self.ml_manager, 
                self.config.get('threat_detection', {})
            )
            self.incident_responder = IncidentResponder(self.config.get('incident_response', {}))
            
            # Connect components
            self.log_analyzer.set_threat_detector(self.threat_detector)
            self.threat_detector.set_incident_responder(self.incident_responder)
            
            self.logger.info("All components initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize components: {e}")
            raise
    
    def run_gui(self):
        """Launch the GUI interface"""
        try:
            self.logger.info("Starting GUI interface...")
            
            # Create and run main window
            self.main_window = MainWindow(
                self.log_analyzer,
                self.threat_detector,
                self.incident_responder,
                self.config
            )
            
            # Start background monitoring
            self._start_background_monitoring()
            
            # Run GUI main loop
            self.main_window.run()
            
        except Exception as e:
            self.logger.error(f"GUI error: {e}")
            raise
    
    def run_cli(self, args):
        """Run in command line interface mode"""
        try:
            self.logger.info("Starting CLI mode...")
            
            if args.scan and args.directory:
                self._batch_scan_directory(args.directory, args.output)
            elif args.log_file:
                self._analyze_single_file(args.log_file, args.output)
            else:
                self._interactive_cli()
                
        except Exception as e:
            self.logger.error(f"CLI error: {e}")
            raise
    
    def _batch_scan_directory(self, directory: str, output_file: Optional[str] = None):
        """Perform batch scanning of a directory"""
        directory_path = Path(directory)
        
        if not directory_path.exists():
            self.logger.error(f"Directory not found: {directory}")
            return
        
        self.logger.info(f"Scanning directory: {directory}")
        
        log_files = list(directory_path.glob("*.log")) + list(directory_path.glob("*.txt"))
        
        if not log_files:
            self.logger.warning("No log files found in directory")
            return
        
        results = []
        for log_file in log_files:
            self.logger.info(f"Analyzing: {log_file.name}")
            
            try:
                # Analyze log file
                analysis_result = self.log_analyzer.analyze_file(str(log_file))
                
                # Detect threats
                threats = self.threat_detector.detect_threats(analysis_result)
                
                results.append({
                    'file': str(log_file),
                    'analysis': analysis_result,
                    'threats': threats
                })
                
            except Exception as e:
                self.logger.error(f"Error analyzing {log_file}: {e}")
        
        # Generate report
        self._generate_batch_report(results, output_file)
    
    def _analyze_single_file(self, log_file: str, output_file: Optional[str] = None):
        """Analyze a single log file"""
        log_path = Path(log_file)
        
        if not log_path.exists():
            self.logger.error(f"Log file not found: {log_file}")
            return
        
        self.logger.info(f"Analyzing log file: {log_file}")
        
        try:
            # Perform analysis
            analysis_result = self.log_analyzer.analyze_file(log_file)
            threats = self.threat_detector.detect_threats(analysis_result)
            
            # Display results
            self._display_analysis_results(analysis_result, threats)
            
            # Save report if requested
            if output_file:
                self._save_analysis_report(analysis_result, threats, output_file)
                
        except Exception as e:
            self.logger.error(f"Error analyzing file: {e}")
    
    def _interactive_cli(self):
        """Run interactive CLI mode"""
        print("CyberGuard AI - Interactive Mode")
        print("Commands: analyze <file>, scan <directory>, status, quit")
        
        while True:
            try:
                command = input("\ncyberguard> ").strip().lower()
                
                if command == "quit" or command == "exit":
                    break
                elif command == "status":
                    self._display_system_status()
                elif command.startswith("analyze "):
                    file_path = command[8:].strip()
                    self._analyze_single_file(file_path)
                elif command.startswith("scan "):
                    dir_path = command[5:].strip()
                    self._batch_scan_directory(dir_path)
                elif command == "help":
                    self._display_help()
                else:
                    print("Unknown command. Type 'help' for available commands.")
                    
            except KeyboardInterrupt:
                print("\nExiting...")
                break
    
    def _start_background_monitoring(self):
        """Start background monitoring thread"""
        def monitor():
            while self.running:
                try:
                    # Perform periodic health checks
                    self._perform_health_check()
                    time.sleep(60)  # Check every minute
                except Exception as e:
                    self.logger.error(f"Monitoring error: {e}")
        
        self.running = True
        self.monitor_thread = threading.Thread(target=monitor, daemon=True)
        self.monitor_thread.start()
    
    def _perform_health_check(self):
        """Perform system health check"""
        # Check component status
        components = [
            self.db_manager,
            self.ml_manager,
            self.log_analyzer,
            self.threat_detector
        ]
        
        for component in components:
            if hasattr(component, 'health_check'):
                status = component.health_check()
                if not status.get('healthy', False):
                    self.logger.warning(f"Component unhealthy: {component.__class__.__name__}")
    
    def _display_analysis_results(self, analysis_result, threats):
        """Display analysis results in CLI"""
        print(f"\n=== Analysis Results ===")
        print(f"Log entries processed: {analysis_result.get('total_entries', 0)}")
        print(f"Suspicious entries: {analysis_result.get('suspicious_count', 0)}")
        print(f"Threats detected: {len(threats)}")
        
        if threats:
            print("\n=== Detected Threats ===")
            for i, threat in enumerate(threats, 1):
                print(f"{i}. {threat.get('type', 'Unknown')} - {threat.get('description', 'No description')}")
                print(f"   Severity: {threat.get('severity', 'Unknown')}")
                print(f"   Confidence: {threat.get('confidence', 0):.2f}")
    
    def _display_system_status(self):
        """Display system status"""
        print("\n=== System Status ===")
        print(f"Application: Running")
        print(f"ML Models: {self.ml_manager.get_model_count()} loaded")
        print(f"Database: {'Connected' if self.db_manager.is_connected() else 'Disconnected'}")
    
    def _display_help(self):
        """Display help information"""
        print("\n=== Available Commands ===")
        print("analyze <file>     - Analyze a single log file")
        print("scan <directory>   - Scan all log files in directory")
        print("status            - Show system status")
        print("help              - Show this help message")
        print("quit              - Exit the application")
    
    def _generate_batch_report(self, results, output_file):
        """Generate batch analysis report"""
        # Implementation for report generation
        pass
    
    def _save_analysis_report(self, analysis_result, threats, output_file):
        """Save analysis report to file"""
        # Implementation for saving reports
        pass
    
    def shutdown(self):
        """Graceful shutdown of the application"""
        self.logger.info("Shutting down CyberGuard AI...")
        self.running = False
        
        # Close database connections
        if hasattr(self, 'db_manager'):
            self.db_manager.close()
        
        self.logger.info("Shutdown complete")
