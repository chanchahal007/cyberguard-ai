"""
Log Analysis Engine
Automated parsing and analysis of security logs with AI enhancement
"""

import re
import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import pandas as pd
from collections import defaultdict, Counter

from ..data.log_parser import LogParser
from ..utils.validators import LogValidator
from .pattern_matcher import PatternMatcher

class LogAnalyzer:
    """Main log analysis engine with AI-powered pattern recognition"""
    
    # Common suspicious patterns
    SUSPICIOUS_PATTERNS = [
        # Failed login attempts
        r'failed\s+login|authentication\s+failed|login\s+denied',
        # Privilege escalation
        r'sudo|su\s+|privilege|escalation|admin\s+access',
        # Network scanning
        r'port\s+scan|nmap|network\s+probe|connection\s+refused',
        # SQL injection attempts
        r'union\s+select|drop\s+table|insert\s+into|or\s+1=1',
        # XSS attempts
        r'<script|javascript:|onload=|onerror=',
        # Directory traversal
        r'\.\./|\.\.\\|directory\s+traversal',
        # Brute force indicators
        r'brute\s+force|dictionary\s+attack|password\s+spray'
    ]
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the log analyzer"""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.log_parser = LogParser()
        self.validator = LogValidator()
        self.pattern_matcher = PatternMatcher()
        self.threat_detector = None  # Set by main application
        
        # Compile regex patterns for performance
        self.compiled_patterns = [re.compile(pattern, re.IGNORECASE) 
                                for pattern in self.SUSPICIOUS_PATTERNS]
        
        # Analysis statistics
        self.stats = {
            'files_processed': 0,
            'entries_analyzed': 0,
            'threats_detected': 0,
            'false_positives': 0
        }
    
    def set_threat_detector(self, threat_detector):
        """Set the threat detector reference"""
        self.threat_detector = threat_detector
    
    def analyze_file(self, file_path: str) -> Dict[str, Any]:
        """
        Analyze a single log file
        
        Args:
            file_path: Path to the log file
            
        Returns:
            Dictionary containing analysis results
        """
        try:
            self.logger.info(f"Starting analysis of: {file_path}")
            
            # Validate file
            if not self.validator.validate_file(file_path):
                raise ValueError(f"Invalid log file: {file_path}")
            
            # Parse log file
            log_entries = self.log_parser.parse_file(file_path)
            
            if not log_entries:
                self.logger.warning(f"No log entries found in {file_path}")
                return self._create_empty_result(file_path)
            
            # Perform analysis
            result = self._analyze_entries(log_entries, file_path)
            
            # Update statistics
            self.stats['files_processed'] += 1
            self.stats['entries_analyzed'] += len(log_entries)
            
            self.logger.info(f"Analysis complete. Processed {len(log_entries)} entries")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {e}")
            raise
    
    def analyze_live_logs(self, log_stream) -> Dict[str, Any]:
        """
        Analyze live log stream in real-time
        
        Args:
            log_stream: Live log data stream
            
        Returns:
            Real-time analysis results
        """
        try:
            # Parse streaming data
            entries = self.log_parser.parse_stream(log_stream)
            
            # Perform real-time analysis
            return self._analyze_entries(entries, "live_stream")
            
        except Exception as e:
            self.logger.error(f"Error analyzing live logs: {e}")
            raise
    
    def _analyze_entries(self, log_entries: List[Dict], source: str) -> Dict[str, Any]:
        """
        Core analysis logic for log entries
        
        Args:
            log_entries: List of parsed log entries
            source: Source of the log data
            
        Returns:
            Comprehensive analysis results
        """
        result = {
            'source': source,
            'timestamp': datetime.now().isoformat(),
            'total_entries': len(log_entries),
            'suspicious_entries': [],
            'patterns_detected': [],
            'anomalies': [],
            'statistics': {},
            'recommendations': []
        }
        
        # Convert to DataFrame for efficient analysis
        df = pd.DataFrame(log_entries)
        
        # Temporal analysis
        temporal_stats = self._analyze_temporal_patterns(df)
        result['statistics'].update(temporal_stats)
        
        # Pattern analysis
        pattern_results = self._detect_patterns(log_entries)
        result['patterns_detected'] = pattern_results
        
        # Anomaly detection
        anomalies = self._detect_anomalies(df)
        result['anomalies'] = anomalies
        
        # Suspicious entry detection
        suspicious = self._find_suspicious_entries(log_entries)
        result['suspicious_entries'] = suspicious
        
        # Generate insights and recommendations
        result['recommendations'] = self._generate_recommendations(result)
        
        # Calculate risk score
        result['risk_score'] = self._calculate_risk_score(result)
        
        return result
    
    def _analyze_temporal_patterns(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Analyze temporal patterns in log data"""
        stats = {}
        
        try:
            if 'timestamp' in df.columns:
                # Convert timestamps
                df['datetime'] = pd.to_datetime(df['timestamp'], errors='coerce')
                df = df.dropna(subset=['datetime'])
                
                if not df.empty:
                    # Time range
                    stats['time_range'] = {
                        'start': df['datetime'].min().isoformat(),
                        'end': df['datetime'].max().isoformat(),
                        'duration_hours': (df['datetime'].max() - df['datetime'].min()).total_seconds() / 3600
                    }
                    
                    # Activity by hour
                    df['hour'] = df['datetime'].dt.hour
                    hourly_counts = df['hour'].value_counts().sort_index()
                    stats['hourly_distribution'] = hourly_counts.to_dict()
                    
                    # Peak activity detection
                    peak_hour = hourly_counts.idxmax()
                    peak_count = hourly_counts.max()
                    stats['peak_activity'] = {'hour': peak_hour, 'count': peak_count}
                    
                    # Detect unusual activity patterns
                    unusual_hours = self._detect_unusual_hours(hourly_counts)
                    if unusual_hours:
                        stats['unusual_activity_hours'] = unusual_hours
                    
        except Exception as e:
            self.logger.error(f"Error in temporal analysis: {e}")
            
        return stats
    
    def _detect_patterns(self, log_entries: List[Dict]) -> List[Dict[str, Any]]:
        """Detect known attack patterns in log entries"""
        patterns_found = []
        
        for entry in log_entries:
            message = entry.get('message', '').lower()
            
            # Check against suspicious patterns
            for i, pattern in enumerate(self.compiled_patterns):
                if pattern.search(message):
                    patterns_found.append({
                        'pattern_id': i,
                        'pattern_type': self._get_pattern_type(i),
                        'entry': entry,
                        'matched_text': pattern.search(message).group(),
                        'severity': self._get_pattern_severity(i)
                    })
        
        # Use advanced pattern matcher
        advanced_patterns = self.pattern_matcher.find_advanced_patterns(log_entries)
        patterns_found.extend(advanced_patterns)
        
        return patterns_found
    
    def _detect_anomalies(self, df: pd.DataFrame) -> List[Dict[str, Any]]:
        """Detect anomalies in log data using statistical methods"""
        anomalies = []
        
        try:
            # Frequency-based anomalies
            if 'source_ip' in df.columns:
                ip_counts = df['source_ip'].value_counts()
                
                # Find IPs with unusually high activity
                threshold = ip_counts.mean() + 3 * ip_counts.std()
                suspicious_ips = ip_counts[ip_counts > threshold]
                
                for ip, count in suspicious_ips.items():
                    anomalies.append({
                        'type': 'high_frequency_ip',
                        'value': ip,
                        'count': count,
                        'threshold': threshold,
                        'severity': 'medium'
                    })
            
            # Time-based anomalies
            if 'datetime' in df.columns:
                # Detect burst activity
                df['hour'] = df['datetime'].dt.hour
                hourly_counts = df.groupby('hour').size()
                
                mean_activity = hourly_counts.mean()
                std_activity = hourly_counts.std()
                
                for hour, count in hourly_counts.items():
                    if count > mean_activity + 3 * std_activity:
                        anomalies.append({
                            'type': 'burst_activity',
                            'hour': hour,
                            'count': count,
                            'expected': mean_activity,
                            'severity': 'high'
                        })
                        
        except Exception as e:
            self.logger.error(f"Error in anomaly detection: {e}")
            
        return anomalies
    
    def _find_suspicious_entries(self, log_entries: List[Dict]) -> List[Dict[str, Any]]:
        """Find and classify suspicious log entries"""
        suspicious = []
        
        for entry in log_entries:
            suspicion_score = 0
            reasons = []
            
            message = entry.get('message', '').lower()
            
            # Check for failed authentication
            if re.search(r'failed|denied|invalid|unauthorized', message):
                suspicion_score += 2
                reasons.append('Authentication failure')
            
            # Check for error codes
            if re.search(r'4\d{2}|5\d{2}', message):  # HTTP error codes
                suspicion_score += 1
                reasons.append('HTTP error code')
            
            # Check for suspicious user agents
            user_agent = entry.get('user_agent', '').lower()
            if any(bot in user_agent for bot in ['bot', 'crawler', 'scanner', 'wget', 'curl']):
                suspicion_score += 1
                reasons.append('Suspicious user agent')
            
            # Check for unusual request patterns
            if re.search(r'\.\.\/|union\s+select|<script', message):
                suspicion_score += 3
                reasons.append('Potential attack pattern')
            
            if suspicion_score >= 2:
                suspicious.append({
                    'entry': entry,
                    'suspicion_score': suspicion_score,
                    'reasons': reasons,
                    'severity': self._calculate_severity(suspicion_score)
                })
        
        return suspicious
    
    def _detect_unusual_hours(self, hourly_counts) -> List[int]:
        """Detect hours with unusual activity patterns"""
        unusual_hours = []
        
        # Normal business hours (9 AM - 5 PM)
        business_hours = list(range(9, 18))
        after_hours = [h for h in range(24) if h not in business_hours]
        
        # Calculate thresholds
        business_avg = hourly_counts[business_hours].mean() if business_hours else 0
        after_hours_counts = hourly_counts[after_hours]
        
        # Flag after-hours activity that's unusually high
        for hour in after_hours:
            if hour in hourly_counts and hourly_counts[hour] > business_avg * 0.5:
                unusual_hours.append(hour)
        
        return unusual_hours
    
    def _get_pattern_type(self, pattern_id: int) -> str:
        """Get pattern type description"""
        pattern_types = [
            'Authentication Failure',
            'Privilege Escalation',
            'Network Scanning',
            'SQL Injection',
            'Cross-Site Scripting',
            'Directory Traversal',
            'Brute Force Attack'
        ]
        return pattern_types[pattern_id] if pattern_id < len(pattern_types) else 'Unknown'
    
    def _get_pattern_severity(self, pattern_id: int) -> str:
        """Get pattern severity level"""
        severity_map = {
            0: 'medium',    # Authentication failure
            1: 'high',      # Privilege escalation
            2: 'medium',    # Network scanning
            3: 'high',      # SQL injection
            4: 'high',      # XSS
            5: 'high',      # Directory traversal
            6: 'high'       # Brute force
        }
        return severity_map.get(pattern_id, 'low')
    
    def _calculate_severity(self, suspicion_score: int) -> str:
        """Calculate severity based on suspicion score"""
        if suspicion_score >= 5:
            return 'critical'
        elif suspicion_score >= 3:
            return 'high'
        elif suspicion_score >= 2:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_risk_score(self, analysis_result: Dict[str, Any]) -> float:
        """Calculate overall risk score for the analysis"""
        risk_score = 0.0
        
        # Factor in suspicious entries
        suspicious_count = len(analysis_result.get('suspicious_entries', []))
        total_entries = analysis_result.get('total_entries', 1)
        
        suspicious_ratio = suspicious_count / total_entries
        risk_score += suspicious_ratio * 40  # Max 40 points
        
        # Factor in detected patterns
        patterns = analysis_result.get('patterns_detected', [])
        high_severity_patterns = [p for p in patterns if p.get('severity') == 'high']
        risk_score += len(high_severity_patterns) * 5  # 5 points per high-severity pattern
        
        # Factor in anomalies
        anomalies = analysis_result.get('anomalies', [])
        critical_anomalies = [a for a in anomalies if a.get('severity') == 'high']
        risk_score += len(critical_anomalies) * 10  # 10 points per critical anomaly
        
        # Cap at 100
        return min(risk_score, 100.0)
    
    def _generate_recommendations(self, analysis_result: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        suspicious_count = len(analysis_result.get('suspicious_entries', []))
        patterns = analysis_result.get('patterns_detected', [])
        anomalies = analysis_result.get('anomalies', [])
        
        if suspicious_count > 10:
            recommendations.append(
                "High number of suspicious entries detected. "
                "Consider implementing additional access controls."
            )
        
        # Pattern-specific recommendations
        pattern_types = [p.get('pattern_type') for p in patterns]
        
        if 'SQL Injection' in pattern_types:
            recommendations.append(
                "SQL injection attempts detected. "
                "Ensure input validation and parameterized queries are implemented."
            )
        
        if 'Brute Force Attack' in pattern_types:
            recommendations.append(
                "Brute force attacks detected. "
                "Consider implementing account lockout policies and rate limiting."
            )
        
        if 'Privilege Escalation' in pattern_types:
            recommendations.append(
                "Privilege escalation attempts detected. "
                "Review and audit administrator access controls."
            )
        
        # Anomaly-specific recommendations
        for anomaly in anomalies:
            if anomaly.get('type') == 'high_frequency_ip':
                recommendations.append(
                    f"IP {anomaly.get('value')} shows unusual activity. "
                    "Consider blocking or monitoring this source."
                )
            
            if anomaly.get('type') == 'burst_activity':
                recommendations.append(
                    "Burst activity detected during off-hours. "
                    "Investigate potential unauthorized access."
                )
        
        # General recommendations
        if not recommendations:
            recommendations.append("No immediate security concerns detected. Continue monitoring.")
        else:
            recommendations.append("Enable real-time monitoring and alerting for detected patterns.")
        
        return recommendations
    
    def _create_empty_result(self, source: str) -> Dict[str, Any]:
        """Create empty result structure"""
        return {
            'source': source,
            'timestamp': datetime.now().isoformat(),
            'total_entries': 0,
            'suspicious_entries': [],
            'patterns_detected': [],
            'anomalies': [],
            'statistics': {},
            'recommendations': ['No log entries found for analysis.'],
            'risk_score': 0.0
        }
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get summary of all analysis performed"""
        return {
            'statistics': self.stats.copy(),
            'patterns_supported': len(self.SUSPICIOUS_PATTERNS),
            'last_analysis': datetime.now().isoformat()
        }
    
    def export_results(self, analysis_result: Dict[str, Any], 
                      output_format: str = 'json') -> str:
        """
        Export analysis results in specified format
        
        Args:
            analysis_result: Analysis results to export
            output_format: Format (json, csv, html)
            
        Returns:
            Exported data as string
        """
        if output_format.lower() == 'json':
            return json.dumps(analysis_result, indent=2, default=str)
        elif output_format.lower() == 'csv':
            return self._export_to_csv(analysis_result)
        elif output_format.lower() == 'html':
            return self._export_to_html(analysis_result)
        else:
            raise ValueError(f"Unsupported export format: {output_format}")
    
    def _export_to_csv(self, analysis_result: Dict[str, Any]) -> str:
        """Export results to CSV format"""
        # Implementation for CSV export
        suspicious_entries = analysis_result.get('suspicious_entries', [])
        
        if not suspicious_entries:
            return "timestamp,message,severity,reasons\n"
        
        csv_lines = ["timestamp,message,severity,reasons"]
        
        for entry in suspicious_entries:
            log_entry = entry.get('entry', {})
            timestamp = log_entry.get('timestamp', '')
            message = log_entry.get('message', '').replace(',', ';')
            severity = entry.get('severity', 'unknown')
            reasons = ';'.join(entry.get('reasons', []))
            
            csv_lines.append(f"{timestamp},{message},{severity},{reasons}")
        
        return '\n'.join(csv_lines)
    
    def _export_to_html(self, analysis_result: Dict[str, Any]) -> str:
        """Export results to HTML format"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>CyberGuard AI - Security Analysis Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #2c3e50; color: white; padding: 15px; border-radius: 5px; }}
                .section {{ margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }}
                .risk-score {{ font-size: 24px; font-weight: bold; }}
                .high {{ color: #e74c3c; }}
                .medium {{ color: #f39c12; }}
                .low {{ color: #27ae60; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Security Analysis Report</h1>
                <p>Source: {analysis_result.get('source', 'Unknown')}</p>
                <p>Generated: {analysis_result.get('timestamp', 'Unknown')}</p>
            </div>
            
            <div class="section">
                <h2>Risk Assessment</h2>
                <div class="risk-score">Risk Score: {analysis_result.get('risk_score', 0):.1f}/100</div>
            </div>
            
            <div class="section">
                <h2>Summary</h2>
                <p>Total Entries: {analysis_result.get('total_entries', 0)}</p>
                <p>Suspicious Entries: {len(analysis_result.get('suspicious_entries', []))}</p>
                <p>Patterns Detected: {len(analysis_result.get('patterns_detected', []))}</p>
                <p>Anomalies Found: {len(analysis_result.get('anomalies', []))}</p>
            </div>
        </body>
        </html>
        """
        return html
    
    def health_check(self) -> Dict[str, Any]:
        """Perform health check of the log analyzer"""
        return {
            'healthy': True,
            'components': {
                'log_parser': self.log_parser is not None,
                'pattern_matcher': self.pattern_matcher is not None,
                'validator': self.validator is not None
            },
            'statistics': self.stats.copy()
        }
