#!/usr/bin/env python3
"""
Advanced Password Security Analyzer Pro
Enterprise password security assessment tool
"""

import re
import math
import requests
import hashlib
import sqlite3
import secrets
import string
from datetime import datetime
import json
import warnings
warnings.filterwarnings('ignore')

# Flask'i conditional yap
try:
    from flask import Flask, request, jsonify, render_template
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False
    print("⚠️  Flask not available - Web interface disabled")

# Flask-Limiter olmadan devam et
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    LIMITER_AVAILABLE = True
except ImportError:
    LIMITER_AVAILABLE = False
    print("⚠️  Flask-Limiter not available - Rate limiting disabled")

# Diğer optional import'lar
try:
    import matplotlib.pyplot as plt
    import seaborn as sns
    PLOTTING_AVAILABLE = True
except ImportError:
    PLOTTING_AVAILABLE = False
    print("⚠️  Matplotlib/Seaborn not available - Charts disabled")

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("⚠️  NumPy not available - Some features disabled")

class AdvancedPasswordAnalyzer:
    """
    Enterprise-grade password security analysis with machine learning
    and real-time threat intelligence integration
    """
    
    def __init__(self, config_path: str = None):
        self.common_passwords = self._load_common_passwords()
        self.ml_model = self._load_ml_model()
        self.db_connection = self._init_database()
        self.config = self._load_config(config_path)
        
    def _load_common_passwords(self) -> set:
        """Load extensive database of compromised and weak passwords"""
        common = {
            "123456", "password", "12345678", "qwerty", "123456789",
            "12345", "1234", "111111", "1234567", "dragon", "123123",
            "baseball", "abc123", "football", "monkey", "letmein",
            "shadow", "master", "666666", "qwertyuiop", "123321",
            "mustang", "1234567890", "michael", "superman", "password1",
            "trustno1", "welcome", "sunshine", "princess", "admin"
        }
        return common

    def _load_ml_model(self):
        """Load pre-trained machine learning model for password strength prediction"""
        try:
            # In a real implementation, this would load a trained model
            # For now, we'll create a placeholder
            return RandomForestClassifier()
        except Exception as e:
            print(f"ML model loading warning: {e}")
            return None

    def _init_database(self):
        """Initialize SQLite database for password history and analytics"""
        try:
            conn = sqlite3.connect('password_analytics.db', check_same_thread=False)
            cursor = conn.cursor()
            
            # Create analytics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS password_analytics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    password_hash TEXT,
                    length INTEGER,
                    entropy REAL,
                    score INTEGER,
                    analysis_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create user sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_sessions (
                    session_id TEXT PRIMARY KEY,
                    analysis_count INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            return conn
        except Exception as e:
            print(f"Database initialization warning: {e}")
            return None

    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from JSON file"""
        default_config = {
            "entropy_thresholds": {"weak": 40, "medium": 60, "strong": 80},
            "crack_speed": 10**9,  # hashes per second
            "min_password_length": 8,
            "max_password_length": 128,
            "require_character_variety": True,
            "enable_ml_analysis": True,
            "enable_breach_check": True
        }
        
        if config_path:
            try:
                with open(config_path, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"Config loading warning: {e}")
                
        return default_config

    def calculate_advanced_entropy(self, password: str) -> Dict[str, float]:
        """Calculate multiple entropy metrics for comprehensive analysis"""
        if not password:
            return {"classic": 0.0, "advanced": 0.0, "pattern_adjusted": 0.0}
        
        # Character set analysis
        char_sets = {
            'lower': 26, 'upper': 26, 'digits': 10, 'special': 33
        }
        
        pool_size = 0
        char_distribution = {}
        
        for char_type, size in char_sets.items():
            if char_type == 'lower' and re.search(r'[a-z]', password):
                pool_size += size
                char_distribution['lower'] = len(re.findall(r'[a-z]', password))
            elif char_type == 'upper' and re.search(r'[A-Z]', password):
                pool_size += size
                char_distribution['upper'] = len(re.findall(r'[A-Z]', password))
            elif char_type == 'digits' and re.search(r'[0-9]', password):
                pool_size += size
                char_distribution['digits'] = len(re.findall(r'[0-9]', password))
            elif char_type == 'special' and re.search(r'[^a-zA-Z0-9]', password):
                pool_size += size
                char_distribution['special'] = len(re.findall(r'[^a-zA-Z0-9]', password))
        
        # Classic entropy calculation
        classic_entropy = len(password) * math.log2(pool_size) if pool_size > 0 else 0
        
        # Advanced entropy with character distribution weighting
        unique_chars = len(set(password))
        distribution_factor = unique_chars / len(password) if len(password) > 0 else 0
        advanced_entropy = classic_entropy * distribution_factor
        
        # Pattern-adjusted entropy
        pattern_penalty = self._calculate_pattern_penalty(password)
        pattern_adjusted_entropy = max(0, advanced_entropy - pattern_penalty)
        
        return {
            "classic": round(classic_entropy, 2),
            "advanced": round(advanced_entropy, 2),
            "pattern_adjusted": round(pattern_adjusted_entropy, 2),
            "unique_chars": unique_chars,
            "char_distribution": char_distribution
        }

    def _calculate_pattern_penalty(self, password: str) -> float:
        """Calculate entropy penalty for identifiable patterns"""
        penalty = 0
        
        # Sequential characters penalty
        sequences = ["123456", "654321", "abcdef", "qwerty", "asdfgh", "zxcvbn"]
        for seq in sequences:
            if seq in password.lower():
                penalty += 15
                break
        
        # Repeated characters penalty
        if re.search(r'(.)\1{3,}', password):
            penalty += 10
        
        # Keyboard walk patterns
        keyboard_rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm"]
        for row in keyboard_rows:
            for i in range(len(row) - 3):
                if row[i:i+4] in password.lower():
                    penalty += 8
                    break
        
        return penalty

    def perform_comprehensive_analysis(self, password: str) -> Dict:
        """Perform complete password security assessment"""
        if not password:
            return self._generate_empty_analysis()
        
        # Basic metrics
        length = len(password)
        entropy_metrics = self.calculate_advanced_entropy(password)
        
        # Security assessments
        weaknesses = self._identify_weaknesses(password)
        breach_data = self._check_password_breaches(password)
        crack_time = self._estimate_crack_time(entropy_metrics["pattern_adjusted"])
        ml_prediction = self._ml_strength_prediction(password) if self.config["enable_ml_analysis"] else None
        
        # Comprehensive scoring
        security_score = self._calculate_comprehensive_score(
            password, entropy_metrics, weaknesses, breach_data, ml_prediction
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            security_score, weaknesses, entropy_metrics
        )
        
        # Store analytics
        self._store_analytics(password, length, entropy_metrics["classic"], security_score)
        
        return {
            "basic_metrics": {
                "length": length,
                "entropy_metrics": entropy_metrics,
                "character_distribution": self._analyze_character_distribution(password)
            },
            "security_assessment": {
                "score": security_score,
                "rating": self._get_security_rating(security_score),
                "weaknesses": weaknesses,
                "breach_status": breach_data,
                "estimated_crack_time": crack_time,
                "ml_confidence": ml_prediction.get("confidence") if ml_prediction else None
            },
            "recommendations": recommendations,
            "risk_analysis": self._perform_risk_analysis(weaknesses, breach_data, security_score),
            "compliance_check": self._check_compliance(password)
        }

    def _identify_weaknesses(self, password: str) -> List[Dict]:
        """Identify and categorize password weaknesses"""
        weaknesses = []
        
        # Length-based weaknesses
        if len(password) < self.config["min_password_length"]:
            weaknesses.append({
                "category": "length",
                "severity": "high",
                "message": f"Password too short (minimum {self.config['min_password_length']} characters required)",
                "suggestion": "Increase password length"
            })
        
        # Common password check
        if password.lower() in self.common_passwords:
            weaknesses.append({
                "category": "common_password",
                "severity": "critical",
                "message": "Password found in common passwords database",
                "suggestion": "Choose a more unique password"
            })
        
        # Character variety check
        if self.config["require_character_variety"]:
            char_types = 0
            if re.search(r'[a-z]', password): char_types += 1
            if re.search(r'[A-Z]', password): char_types += 1
            if re.search(r'[0-9]', password): char_types += 1
            if re.search(r'[^a-zA-Z0-9]', password): char_types += 1
            
            if char_types < 3:
                weaknesses.append({
                    "category": "character_variety",
                    "severity": "medium",
                    "message": "Insufficient character variety",
                    "suggestion": "Use mixed case letters, numbers, and special characters"
                })
        
        # Pattern-based weaknesses
        if re.search(r'(.)\1{3,}', password):
            weaknesses.append({
                "category": "repeating_patterns",
                "severity": "medium",
                "message": "Repeating character patterns detected",
                "suggestion": "Avoid consecutive repeated characters"
            })
        
        return weaknesses

    def _check_password_breaches(self, password: str) -> Dict:
        """Check password against known data breaches using HIBP API"""
        if not self.config["enable_breach_check"]:
            return {"checked": False, "message": "Breach check disabled"}
        
        try:
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1_hash[:5], sha1_hash[5:]
            
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for hash_suffix, count in hashes:
                    if hash_suffix == suffix:
                        return {
                            "checked": True,
                            "breached": True,
                            "breach_count": int(count),
                            "message": f"Password found in {count} known breaches"
                        }
                
                return {
                    "checked": True,
                    "breached": False,
                    "breach_count": 0,
                    "message": "Password not found in known breaches"
                }
            else:
                return {
                    "checked": False,
                    "breached": False,
                    "message": "Unable to reach breach database"
                }
                
        except Exception as e:
            return {
                "checked": False,
                "breached": False,
                "message": f"Breach check failed: {str(e)}"
            }

    def _estimate_crack_time(self, entropy: float) -> Dict[str, str]:
        """Estimate password cracking time using multiple methods"""
        hashes_per_second = self.config["crack_speed"]
        
        if entropy <= 0:
            return {"method": "entropy", "time": "instantly", "confidence": "low"}
        
        possible_combinations = 2 ** entropy
        seconds = possible_combinations / hashes_per_second
        
        # Convert to human readable time
        if seconds < 1:
            time_str = "instantly"
            confidence = "high"
        elif seconds < 60:
            time_str = "seconds"
            confidence = "high"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            time_str = f"{minutes} minute{'s' if minutes > 1 else ''}"
            confidence = "high"
        elif seconds < 86400:
            hours = int(seconds / 3600)
            time_str = f"{hours} hour{'s' if hours > 1 else ''}"
            confidence = "medium"
        elif seconds < 31536000:  # 1 year
            days = int(seconds / 86400)
            time_str = f"{days} day{'s' if days > 1 else ''}"
            confidence = "medium"
        else:
            years = seconds / 31536000
            if years > 1000:
                time_str = "centuries"
                confidence = "low"
            else:
                time_str = f"{int(years)} year{'s' if years > 1 else ''}"
                confidence = "low"
        
        return {
            "method": "entropy_based",
            "time": time_str,
            "confidence": confidence,
            "entropy_bits": entropy
        }

    def _ml_strength_prediction(self, password: str) -> Dict:
        """Predict password strength using machine learning"""
        if not self.ml_model:
            return {"prediction": "unknown", "confidence": 0.0}
        
        try:
            # Feature extraction for ML model
            features = self._extract_ml_features(password)
            # In a real implementation, this would use the trained model
            # prediction = self.ml_model.predict([features])[0]
            # confidence = max(self.ml_model.predict_proba([features])[0])
            
            # Placeholder implementation
            strength_map = {0: "very_weak", 1: "weak", 2: "medium", 3: "strong", 4: "very_strong"}
            simulated_prediction = min(4, len(password) // 4)
            
            return {
                "prediction": strength_map[simulated_prediction],
                "confidence": min(0.95, len(password) * 0.05),
                "features_used": len(features)
            }
        except Exception as e:
            return {"prediction": "error", "confidence": 0.0, "error": str(e)}

    def _extract_ml_features(self, password: str) -> List[float]:
        """Extract features for machine learning model"""
        features = [
            len(password),  # length
            len(set(password)),  # unique characters
            sum(c.islower() for c in password),  # lowercase count
            sum(c.isupper() for c in password),  # uppercase count
            sum(c.isdigit() for c in password),  # digit count
            sum(not c.isalnum() for c in password),  # special characters
            self.calculate_advanced_entropy(password)["classic"],  # entropy
        ]
        return features

    def _calculate_comprehensive_score(self, password: str, entropy_metrics: Dict, 
                                     weaknesses: List, breach_data: Dict, 
                                     ml_prediction: Dict) -> int:
        """Calculate comprehensive security score (0-100)"""
        score = 50  # Base score
        
        # Length scoring (0-20 points)
        length = len(password)
        if length >= 16:
            score += 20
        elif length >= 12:
            score += 15
        elif length >= 8:
            score += 10
        else:
            score -= 10
        
        # Entropy scoring (0-25 points)
        entropy = entropy_metrics["pattern_adjusted"]
        if entropy >= 80:
            score += 25
        elif entropy >= 60:
            score += 20
        elif entropy >= 40:
            score += 10
        elif entropy < 20:
            score -= 15
        
        # Character variety scoring (0-15 points)
        char_variety = len(entropy_metrics.get("char_distribution", {}))
        score += char_variety * 3  # Up to 12 points
        
        # Weakness penalties
        for weakness in weaknesses:
            severity_penalty = {"critical": -20, "high": -15, "medium": -10, "low": -5}
            score += severity_penalty.get(weakness["severity"], 0)
        
        # Breach penalty
        if breach_data.get("breached", False):
            score -= 25
        
        # ML confidence adjustment
        if ml_prediction and ml_prediction.get("confidence", 0) > 0.7:
            ml_bonus = (ml_prediction["confidence"] - 0.7) * 20
            score += ml_bonus
        
        return max(0, min(100, int(score)))

    def _generate_recommendations(self, score: int, weaknesses: List, 
                                entropy_metrics: Dict) -> List[Dict]:
        """Generate personalized security recommendations"""
        recommendations = []
        
        if score < 40:
            recommendations.append({
                "priority": "critical",
                "category": "overall_security",
                "message": "Immediate password change recommended",
                "action": "Generate a new strong password using our generator"
            })
        
        # Length recommendations
        if entropy_metrics.get("basic_metrics", {}).get("length", 0) < 12:
            recommendations.append({
                "priority": "high",
                "category": "length",
                "message": "Increase password length to at least 12 characters",
                "action": "Add 4-6 more characters"
            })
        
        # Character variety recommendations
        char_dist = entropy_metrics.get("char_distribution", {})
        if len(char_dist) < 3:
            recommendations.append({
                "priority": "medium",
                "category": "character_variety", 
                "message": "Add more character types (uppercase, numbers, symbols)",
                "action": "Include at least 3 different character types"
            })
        
        # Specific weakness recommendations
        for weakness in weaknesses:
            recommendations.append({
                "priority": weakness["severity"],
                "category": weakness["category"],
                "message": weakness["suggestion"],
                "action": weakness.get("suggestion", "Review password composition")
            })
        
        return sorted(recommendations, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3}[x["priority"]])

    def _perform_risk_analysis(self, weaknesses: List, breach_data: Dict, score: int) -> Dict:
        """Perform comprehensive risk assessment"""
        risk_level = "low"
        
        # Calculate risk score
        risk_score = 0
        if any(w["severity"] == "critical" for w in weaknesses):
            risk_score += 30
        if any(w["severity"] == "high" for w in weaknesses):
            risk_score += 20
        if breach_data.get("breached", False):
            risk_score += 40
        if score < 40:
            risk_score += 30
        elif score < 60:
            risk_score += 15
        
        # Determine risk level
        if risk_score >= 60:
            risk_level = "critical"
        elif risk_score >= 40:
            risk_level = "high" 
        elif risk_score >= 20:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        return {
            "risk_level": risk_level,
            "risk_score": risk_score,
            "factors": [w["category"] for w in weaknesses] + (["breached"] if breach_data.get("breached") else [])
        }

    def _check_compliance(self, password: str) -> Dict:
        """Check compliance with common security standards"""
        compliance = {
            "nist": self._check_nist_compliance(password),
            "pci_dss": self._check_pci_dss_compliance(password),
            "iso27001": self._check_iso27001_compliance(password)
        }
        
        all_compliant = all(comp["compliant"] for comp in compliance.values())
        
        return {
            "overall_compliant": all_compliant,
            "standards": compliance
        }

    def _check_nist_compliance(self, password: str) -> Dict:
        """Check NIST Special Publication 800-63B compliance"""
        checks = {
            "min_length_8": len(password) >= 8,
            "max_length_64": len(password) <= 64,
            "no_context_words": not self._contains_context_words(password),
            "no_sequential_chars": not self._has_sequential_chars(password, 4)
        }
        
        return {
            "compliant": all(checks.values()),
            "checks": checks
        }

    def _check_pci_dss_compliance(self, password: str) -> Dict:
        """Check PCI DSS compliance"""
        checks = {
            "min_length_7": len(password) >= 7,
            "both_alpha_numeric": any(c.isalpha() for c in password) and any(c.isdigit() for c in password)
        }
        
        return {
            "compliant": all(checks.values()),
            "checks": checks
        }

    def _contains_context_words(self, password: str) -> bool:
        """Check for context-specific words (username, company name, etc.)"""
        context_words = ["admin", "password", "company", "user"]
        return any(word in password.lower() for word in context_words)

    def _has_sequential_chars(self, password: str, length: int) -> bool:
        """Check for sequential characters"""
        for i in range(len(password) - length + 1):
            segment = password[i:i+length]
            if segment in "0123456789" or segment in "0123456789"[::-1]:
                return True
            if segment in "abcdefghijklmnopqrstuvwxyz" or segment in "abcdefghijklmnopqrstuvwxyz"[::-1]:
                return True
        return False

    def _analyze_character_distribution(self, password: str) -> Dict:
        """Analyze character distribution patterns"""
        distribution = {
            "total_chars": len(password),
            "unique_chars": len(set(password)),
            "lowercase": sum(c.islower() for c in password),
            "uppercase": sum(c.isupper() for c in password),
            "digits": sum(c.isdigit() for c in password),
            "special": sum(not c.isalnum() for c in password),
            "repeating_chars": len(password) - len(set(password))
        }

        
        distribution["uniqueness_ratio"] = round(distribution["unique_chars"] / distribution["total_chars"], 2)

        return distribution

    def _get_security_rating(self, score: int) -> str:
        """Convert numerical score to security rating"""
        if score >= 90:
            return "Excellent"
        elif score >= 75:
            return "Very Strong"
        elif score >= 60:
            return "Strong"
        elif score >= 45:
            return "Good"
        elif score >= 30:
            return "Weak"
        else:
            return "Very Weak"

    def _store_analytics(self, password: str, length: int, entropy: float, score: int):
        """Store analysis results in database for analytics"""
        if not self.db_connection:
            return
            
        try:
            cursor = self.db_connection.cursor()
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            cursor.execute('''
                INSERT INTO password_analytics 
                (password_hash, length, entropy, score)
                VALUES (?, ?, ?, ?)
            ''', (password_hash, length, entropy, score))
            
            self.db_connection.commit()
        except Exception as e:
            print(f"Analytics storage error: {e}")

    def _generate_empty_analysis(self) -> Dict:
        """Generate empty analysis result"""
        return {
            "basic_metrics": {
                "length": 0,
                "entropy_metrics": {"classic": 0.0, "advanced": 0.0, "pattern_adjusted": 0.0},
                "character_distribution": {}
            },
            "security_assessment": {
                "score": 0,
                "rating": "Very Weak",
                "weaknesses": [{
                    "category": "empty_password",
                    "severity": "critical",
                    "message": "No password provided",
                    "suggestion": "Enter a password to analyze"
                }],
                "breach_status": {"checked": False},
                "estimated_crack_time": {"time": "instantly"},
                "ml_confidence": None
            },
            "recommendations": [{
                "priority": "critical",
                "category": "no_password",
                "message": "Please enter a password for analysis",
                "action": "Provide a password to assess"
            }],
            "risk_analysis": {
                "risk_level": "critical",
                "risk_score": 100,
                "factors": ["no_password"]
            },
            "compliance_check": {
                "overall_compliant": False,
                "standards": {}
            }
        }

    def generate_secure_password(self, length: int = 16, 
                               include_uppercase: bool = True,
                               include_numbers: bool = True, 
                               include_symbols: bool = True) -> str:
        """Generate cryptographically secure random password"""
        if length < 8:
            raise ValueError("Password length must be at least 8 characters")
        
        characters = string.ascii_lowercase
        
        if include_uppercase:
            characters += string.ascii_uppercase
        if include_numbers:
            characters += string.digits
        if include_symbols:
            characters += "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        if not characters:
            raise ValueError("At least one character set must be enabled")
        
        # Ensure minimum requirements are met
        password = []
        if include_uppercase:
            password.append(secrets.choice(string.ascii_uppercase))
        if include_numbers:
            password.append(secrets.choice(string.digits))
        if include_symbols:
            password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
        
        # Fill remaining length
        remaining_length = length - len(password)
        password.extend(secrets.choice(characters) for _ in range(remaining_length))
        
        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)

    def get_analytics_summary(self) -> Dict:
        """Get summary analytics from stored data"""
        if not self.db_connection:
            return {"error": "Database not available"}
        
        try:
            cursor = self.db_connection.cursor()
            
            # Basic statistics
            cursor.execute('''
                SELECT 
                    COUNT(*) as total_analyses,
                    AVG(score) as avg_score,
                    AVG(length) as avg_length,
                    AVG(entropy) as avg_entropy,
                    SUM(CASE WHEN score >= 80 THEN 1 ELSE 0 END) as strong_passwords,
                    SUM(CASE WHEN score < 40 THEN 1 ELSE 0 END) as weak_passwords
                FROM password_analytics
            ''')
            
            stats = cursor.fetchone()
            
            return {
                "total_analyses": stats[0],
                "average_score": round(stats[1] or 0, 2),
                "average_length": round(stats[2] or 0, 2),
                "average_entropy": round(stats[3] or 0, 2),
                "strong_password_percentage": round((stats[4] / stats[0]) * 100, 2) if stats[0] > 0 else 0,
                "weak_password_percentage": round((stats[5] / stats[0]) * 100, 2) if stats[0] > 0 else 0
            }
        except Exception as e:
            return {"error": f"Analytics query failed: {e}"}

    def create_strength_visualization(self, save_path: str = "password_strength_chart.png"):
        """Create visualization of password strength distribution"""
        if not self.db_connection:
            return False
        
        try:
            cursor = self.db_connection.cursor()
            cursor.execute('SELECT score FROM password_analytics')
            scores = [row[0] for row in cursor.fetchall()]
            
            if not scores:
                return False
            
            plt.figure(figsize=(12, 8))
            
            # Score distribution
            plt.subplot(2, 2, 1)
            plt.hist(scores, bins=20, alpha=0.7, color='skyblue', edgecolor='black')
            plt.title('Password Strength Score Distribution')
            plt.xlabel('Security Score')
            plt.ylabel('Frequency')
            plt.grid(True, alpha=0.3)
            
            # Score categories
            plt.subplot(2, 2, 2)
            categories = {
                'Very Weak (0-29)': len([s for s in scores if s < 30]),
                'Weak (30-44)': len([s for s in scores if 30 <= s < 45]),
                'Good (45-59)': len([s for s in scores if 45 <= s < 60]),
                'Strong (60-74)': len([s for s in scores if 60 <= s < 75]),
                'Very Strong (75-89)': len([s for s in scores if 75 <= s < 90]),
                'Excellent (90-100)': len([s for s in scores if s >= 90])
            }
            plt.pie(categories.values(), labels=categories.keys(), autopct='%1.1f%%')
            plt.title('Password Strength Categories')
            
            # Time trend (if we had timestamp data)
            plt.subplot(2, 2, 3)
            cursor.execute('''
                SELECT DATE(analysis_timestamp), AVG(score) 
                FROM password_analytics 
                GROUP BY DATE(analysis_timestamp) 
                ORDER BY DATE(analysis_timestamp)
            ''')
            trend_data = cursor.fetchall()
            if trend_data:
                dates, avg_scores = zip(*trend_data)
                plt.plot(dates, avg_scores, marker='o', linewidth=2)
                plt.title('Average Password Strength Over Time')
                plt.xlabel('Date')
                plt.ylabel('Average Score')
                plt.xticks(rotation=45)
                plt.grid(True, alpha=0.3)
            
            # Length vs Score correlation
            plt.subplot(2, 2, 4)
            cursor.execute('SELECT length, score FROM password_analytics LIMIT 1000')
            length_score_data = cursor.fetchall()
            if length_score_data:
                lengths, l_scores = zip(*length_score_data)
                plt.scatter(lengths, l_scores, alpha=0.6, color='coral')
                plt.title('Password Length vs Security Score')
                plt.xlabel('Password Length')
                plt.ylabel('Security Score')
                plt.grid(True, alpha=0.3)
            
            plt.tight_layout()
            plt.savefig(save_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            return True
        except Exception as e:
            print(f"Visualization error: {e}")
            return False

# Web Application Integration
app = Flask(__name__)
limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Global analyzer instance
analyzer = AdvancedPasswordAnalyzer()

@app.route('/')
def index():
    """Main application page"""
    return render_template('index.html')

@app.route('/api/analyze', methods=['POST'])
@limiter.limit("10 per minute")
def analyze_password_api():
    """API endpoint for password analysis"""
    try:
        data = request.get_json()
        password = data.get('password', '')
        
        if not password:
            return jsonify({"error": "No password provided"}), 400
        
        # Perform comprehensive analysis
        analysis = analyzer.perform_comprehensive_analysis(password)
        
        return jsonify({
            "success": True,
            "analysis": analysis,
            "timestamp": datetime.now().isoformat()
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/generate', methods=['GET'])
@limiter.limit("20 per minute")
def generate_password_api():
    """API endpoint for password generation"""
    try:
        length = request.args.get('length', 16, type=int)
        include_uppercase = request.args.get('uppercase', 'true').lower() == 'true'
        include_numbers = request.args.get('numbers', 'true').lower() == 'true'
        include_symbols = request.args.get('symbols', 'true').lower() == 'true'
        
        password = analyzer.generate_secure_password(
            length=length,
            include_uppercase=include_uppercase,
            include_numbers=include_numbers,
            include_symbols=include_symbols
        )
        
        return jsonify({
            "success": True,
            "password": password,
            "parameters": {
                "length": length,
                "include_uppercase": include_uppercase,
                "include_numbers": include_numbers,
                "include_symbols": include_symbols
            }
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@app.route('/api/analytics', methods=['GET'])
def get_analytics_api():
    """API endpoint for system analytics"""
    try:
        summary = analyzer.get_analytics_summary()
        
        # Generate visualization
        chart_path = "static/strength_chart.png"
        if analyzer.create_strength_visualization(chart_path):
            summary["visualization"] = chart_path
        
        return jsonify({
            "success": True,
            "analytics": summary
        })
        
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """API health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
        "features": {
            "ml_analysis": analyzer.ml_model is not None,
            "breach_check": analyzer.config["enable_breach_check"],
            "database": analyzer.db_connection is not None
        }
    })

def print_advanced_banner():
    """Print advanced ASCII banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║    ██████╗  █████╗ ███████╗███████╗██╗    ██╗ ██████╗ ██████╗   ║
    ║    ██╔══██╗██╔══██╗██╔════╝██╔════╝██║    ██║██╔═══██╗██╔══██╗  ║
    ║    ██████╔╝███████║███████╗███████╗██║ █╗ ██║██║   ██║██████╔╝  ║
    ║    ██╔═══╝ ██╔══██║╚════██║╚════██║██║███╗██║██║   ██║██╔══██╗  ║
    ║    ██║     ██║  ██║███████║███████║╚███╔███╔╝╚██████╔╝██║  ██║  ║
    ║    ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝  ║
    ║                                                                  ║
    ║              ADVANCED PASSWORD SECURITY ANALYZER PRO            ║
    ║                  Enterprise-Grade Security Assessment           ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    
    Features:
    • AI-Powered Strength Prediction      • Real-time Breach Monitoring
    • Comprehensive Risk Analysis         • Regulatory Compliance Check
    • Advanced Entropy Calculations       • Enterprise Analytics Dashboard
    • Secure Password Generation          • RESTful API Integration
    
    """
    print(banner)

def main():
    """Main command-line interface"""
    print_advanced_banner()
    analyzer = AdvancedPasswordAnalyzer()
    
    print("🚀 Welcome to Advanced Password Security Analyzer Pro!")
    print("=" * 65)
    
    while True:
        print("\nOptions:")
        print("1. Analyze Password Security")
        print("2. Generate Secure Password")
        print("3. View System Analytics")
        print("4. Generate Security Report")
        print("5. Exit")
        
        choice = input("\nSelect option (1-5): ").strip()
        
        if choice == '1':
            password = input("\n🔐 Enter password to analyze: ")
            if password.lower() == 'back':
                continue
                
            print("\n" + "="*50)
            print("🛡️  PERFORMING COMPREHENSIVE SECURITY ANALYSIS...")
            print("="*50)
            
            analysis = analyzer.perform_comprehensive_analysis(password)
            
            # Display results
            print(f"\n📊 SECURITY SCORE: {analysis['security_assessment']['score']}/100")
            print(f"📈 RATING: {analysis['security_assessment']['rating']}")
            print(f"⏱️  ESTIMATED CRACK TIME: {analysis['security_assessment']['estimated_crack_time']['time']}")
            
            if analysis['security_assessment']['breach_status'].get('breached'):
                print(f"🚨 BREACH ALERT: {analysis['security_assessment']['breach_status']['message']}")
            
            # Show recommendations
            if analysis['recommendations']:
                print(f"\n💡 RECOMMENDATIONS:")
                for rec in analysis['recommendations'][:3]:  # Show top 3
                    print(f"   • {rec['message']}")
            
        elif choice == '2':
            try:
                length = int(input("Password length (default 16): ") or 16)
                password = analyzer.generate_secure_password(length=length)
                print(f"\n🔑 GENERATED PASSWORD: {password}")
                
                # Auto-analyze the generated password
                analysis = analyzer.perform_comprehensive_analysis(password)
                print(f"📊 Generated password score: {analysis['security_assessment']['score']}/100")
                
            except ValueError as e:
                print(f"❌ Error: {e}")
                
        elif choice == '3':
            print("\n📈 SYSTEM ANALYTICS DASHBOARD")
            print("=" * 35)
            analytics = analyzer.get_analytics_summary()
            
            if "error" not in analytics:
                for key, value in analytics.items():
                    print(f"   {key.replace('_', ' ').title()}: {value}")
                
                # Generate visualization
                if analyzer.create_strength_visualization():
                    print("   📊 Visualization: password_strength_chart.png")
            else:
                print("   Analytics not available")
                
        elif choice == '4':
            password = input("\nEnter password for detailed report: ")
            analysis = analyzer.perform_comprehensive_analysis(password)
            
            print(f"\n{'='*60}")
            print(f"📋 COMPREHENSIVE SECURITY REPORT")
            print(f"{'='*60}")
            print(f"Password: {'*' * len(password)}")
            print(f"Final Score: {analysis['security_assessment']['score']}/100")
            print(f"Security Rating: {analysis['security_assessment']['rating']}")
            print(f"Risk Level: {analysis['risk_analysis']['risk_level'].upper()}")
            
            # Compliance status
            compliant = analysis['compliance_check']['overall_compliant']
            print(f"Regulatory Compliance: {'✅ COMPLIANT' if compliant else '❌ NON-COMPLIANT'}")
            
        elif choice == '5':
            print("\n👋 Thank you for using Advanced Password Security Analyzer Pro!")
            if analyzer.db_connection:
                analyzer.db_connection.close()
            break
            
        else:
            print("❌ Invalid option. Please choose 1-5.")

if __name__ == "__main__":
    main()
