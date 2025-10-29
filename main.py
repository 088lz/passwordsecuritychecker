#!/usr/bin/env python3
"""
Password Security Analyzer Pro
A comprehensive and stable password security assessment tool
"""

import re
import math
import hashlib
import secrets
import string
import sqlite3
from datetime import datetime
import os
import sys

class PasswordAnalyzer:
    def __init__(self):
        self.common_passwords = self._load_common_passwords()
        self.db_connection = self._init_database()
    
    def _load_common_passwords(self):
        """Load common passwords database"""
        return {
            "123456", "password", "12345678", "qwerty", "123456789",
            "12345", "1234", "111111", "1234567", "dragon", "123123",
            "baseball", "abc123", "football", "monkey", "letmein",
            "shadow", "master", "666666", "qwertyuiop", "123321",
            "mustang", "1234567890", "michael", "superman", "password1",
            "trustno1", "welcome", "sunshine", "princess", "admin"
        }
    
    def _init_database(self):
        """Initialize SQLite database for analytics"""
        try:
            conn = sqlite3.connect('password_analytics.db', check_same_thread=False)
            cursor = conn.cursor()
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
            conn.commit()
            return conn
        except Exception as e:
            print(f"Database warning: {e}")
            return None
    
    def calculate_entropy(self, password):
        """Calculate password entropy in bits"""
        if not password:
            return 0.0
        
        char_sets = {
            'lower': 26,    # a-z
            'upper': 26,    # A-Z
            'digits': 10,   # 0-9
            'special': 33   # !@#$%^&*() etc.
        }
        
        pool_size = 0
        if re.search(r'[a-z]', password):
            pool_size += char_sets['lower']
        if re.search(r'[A-Z]', password):
            pool_size += char_sets['upper']
        if re.search(r'[0-9]', password):
            pool_size += char_sets['digits']
        if re.search(r'[^a-zA-Z0-9]', password):
            pool_size += char_sets['special']
        
        if pool_size == 0:
            return 0.0
        
        entropy = len(password) * math.log2(pool_size)
        return round(entropy, 2)
    
    def check_weak_patterns(self, password):
        """Identify common weak patterns"""
        weaknesses = []
        
        # Common password check
        if password.lower() in self.common_passwords:
            weaknesses.append("Common password found in database")
        
        # Sequential characters
        sequences = ["123456", "654321", "abcdef", "qwerty", "asdfgh"]
        for seq in sequences:
            if seq in password.lower():
                weaknesses.append("Sequential character pattern detected")
                break
        
        # Repeated characters
        if re.search(r'(.)\1{3,}', password):
            weaknesses.append("Too many repeated characters")
        
        # Only numbers
        if password.isdigit():
            weaknesses.append("Contains only numbers")
        
        # Only letters
        if password.isalpha():
            weaknesses.append("Contains only letters")
        
        # Short password
        if len(password) < 8:
            weaknesses.append("Password is too short (minimum 8 characters)")
        
        # No character variety
        char_types = 0
        if re.search(r'[a-z]', password): char_types += 1
        if re.search(r'[A-Z]', password): char_types += 1
        if re.search(r'[0-9]', password): char_types += 1
        if re.search(r'[^a-zA-Z0-9]', password): char_types += 1
        
        if char_types < 3:
            weaknesses.append("Insufficient character variety")
        
        return weaknesses
    
    def check_password_breaches(self, password):
        """Check password against Have I Been Pwned database"""
        try:
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1_hash[:5], sha1_hash[5:]
            
            import requests
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for hash_suffix, count in hashes:
                    if hash_suffix == suffix:
                        return {"breached": True, "count": int(count), "message": f"Found in {count} breaches"}
                
                return {"breached": False, "count": 0, "message": "No breaches found"}
            else:
                return {"breached": False, "count": 0, "message": "Unable to check breaches"}
                
        except ImportError:
            return {"breached": False, "count": 0, "message": "Requests library not available"}
        except Exception as e:
            return {"breached": False, "count": 0, "message": f"Breach check failed: {str(e)}"}
    
    def estimate_crack_time(self, entropy):
        """Estimate time required to crack password"""
        if entropy <= 0:
            return "instantly"
        
        # Assume 1 billion hashes per second
        hashes_per_second = 10**9
        possible_combinations = 2 ** entropy
        seconds = possible_combinations / hashes_per_second
        
        if seconds < 60:
            return "seconds"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            return f"{minutes} minute{'s' if minutes > 1 else ''}"
        elif seconds < 86400:
            hours = int(seconds / 3600)
            return f"{hours} hour{'s' if hours > 1 else ''}"
        elif seconds < 31536000:  # 1 year
            days = int(seconds / 86400)
            return f"{days} day{'s' if days > 1 else ''}"
        else:
            years = int(seconds / 31536000)
            if years > 1000:
                return "centuries"
            return f"{years} year{'s' if years > 1 else ''}"
    
    def calculate_security_score(self, password, entropy, weaknesses, breach_data):
        """Calculate comprehensive security score (0-100)"""
        score = 50  # Base score
        
        # Length scoring
        length = len(password)
        if length >= 16:
            score += 20
        elif length >= 12:
            score += 15
        elif length >= 8:
            score += 10
        else:
            score -= 10
        
        # Entropy scoring
        if entropy >= 80:
            score += 25
        elif entropy >= 60:
            score += 20
        elif entropy >= 40:
            score += 10
        elif entropy < 20:
            score -= 15
        
        # Character variety bonus
        char_types = 0
        if re.search(r'[a-z]', password): char_types += 1
        if re.search(r'[A-Z]', password): char_types += 1
        if re.search(r'[0-9]', password): char_types += 1
        if re.search(r'[^a-zA-Z0-9]', password): char_types += 1
        score += (char_types - 1) * 5
        
        # Weakness penalties
        score -= len(weaknesses) * 8
        
        # Breach penalty
        if breach_data.get("breached", False):
            score -= 30
        
        return max(0, min(100, score))
    
    def analyze_password(self, password):
        """Comprehensive password security analysis"""
        if not password:
            return self._generate_empty_analysis()
        
        # Basic metrics
        length = len(password)
        entropy = self.calculate_entropy(password)
        weaknesses = self.check_weak_patterns(password)
        breach_data = self.check_password_breaches(password)
        crack_time = self.estimate_crack_time(entropy)
        
        # Security scoring
        score = self.calculate_security_score(password, entropy, weaknesses, breach_data)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(score, weaknesses, length, entropy)
        
        # Store analytics
        self._store_analytics(password, length, entropy, score)
        
        return {
            "basic_metrics": {
                "length": length,
                "entropy": entropy,
                "character_variety": self._analyze_character_variety(password)
            },
            "security_assessment": {
                "score": score,
                "rating": self._get_security_rating(score),
                "weaknesses": weaknesses,
                "breach_status": breach_data,
                "estimated_crack_time": crack_time
            },
            "recommendations": recommendations
        }
    
    def _analyze_character_variety(self, password):
        """Analyze character type distribution"""
        return {
            "lowercase": len(re.findall(r'[a-z]', password)),
            "uppercase": len(re.findall(r'[A-Z]', password)),
            "digits": len(re.findall(r'[0-9]', password)),
            "special": len(re.findall(r'[^a-zA-Z0-9]', password)),
            "unique_chars": len(set(password))
        }
    
    def _get_security_rating(self, score):
        """Convert score to security rating"""
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
    
    def _generate_recommendations(self, score, weaknesses, length, entropy):
        """Generate security recommendations"""
        recommendations = []
        
        if score < 40:
            recommendations.append({
                "priority": "critical",
                "message": "Immediate password change recommended",
                "suggestion": "Use the password generator to create a strong password"
            })
        
        if length < 12:
            recommendations.append({
                "priority": "high",
                "message": "Increase password length",
                "suggestion": "Aim for at least 12 characters"
            })
        
        if entropy < 60:
            recommendations.append({
                "priority": "medium",
                "message": "Improve password complexity",
                "suggestion": "Use more character types (uppercase, numbers, symbols)"
            })
        
        # Add specific weakness recommendations
        for weakness in weaknesses[:3]:  # Limit to top 3
            recommendations.append({
                "priority": "medium",
                "message": weakness,
                "suggestion": "Review password composition"
            })
        
        return recommendations
    
    def _store_analytics(self, password, length, entropy, score):
        """Store analysis results in database"""
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
        except Exception:
            pass  # Silent fail for analytics
    
    def _generate_empty_analysis(self):
        """Generate analysis result for empty password"""
        return {
            "basic_metrics": {
                "length": 0,
                "entropy": 0.0,
                "character_variety": {}
            },
            "security_assessment": {
                "score": 0,
                "rating": "Very Weak",
                "weaknesses": ["No password provided"],
                "breach_status": {"message": "Not checked"},
                "estimated_crack_time": "instantly"
            },
            "recommendations": [{
                "priority": "critical",
                "message": "Please enter a password",
                "suggestion": "Provide a password to analyze"
            }]
        }
    
    def generate_secure_password(self, length=16, include_uppercase=True, include_numbers=True, include_symbols=True):
        """Generate cryptographically secure password"""
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
        
        # Ensure minimum requirements
        password = []
        if include_uppercase:
            password.append(secrets.choice(string.ascii_uppercase))
        if include_numbers:
            password.append(secrets.choice(string.digits))
        if include_symbols:
            password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))
        
        # Fill remaining length
        remaining = length - len(password)
        password.extend(secrets.choice(characters) for _ in range(remaining))
        
        # Shuffle for randomness
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    def get_analytics_summary(self):
        """Get analytics summary from database"""
        if not self.db_connection:
            return {"error": "Database not available"}
        
        try:
            cursor = self.db_connection.cursor()
            cursor.execute('''
                SELECT 
                    COUNT(*) as total,
                    AVG(score) as avg_score,
                    AVG(length) as avg_length,
                    AVG(entropy) as avg_entropy
                FROM password_analytics
            ''')
            result = cursor.fetchone()
            
            return {
                "total_analyses": result[0],
                "average_score": round(result[1] or 0, 2),
                "average_length": round(result[2] or 0, 2),
                "average_entropy": round(result[3] or 0, 2)
            }
        except Exception:
            return {"error": "Failed to fetch analytics"}

def print_banner():
    """Print application banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║              PASSWORD SECURITY ANALYZER PRO             ║
    ║               Comprehensive Security Assessment          ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(banner)

def main():
    """Main command-line interface"""
    print_banner()
    analyzer = PasswordAnalyzer()
    
    print("🚀 Welcome to Password Security Analyzer Pro!")
    print("=" * 55)
    
    while True:
        print("\nOptions:")
        print("1. 🔐 Analyze Password Security")
        print("2. 🔑 Generate Secure Password")
        print("3. 📊 View Analytics Summary")
        print("4. ❌ Exit")
        
        try:
            choice = input("\nSelect option (1-4): ").strip()
            
            if choice == '1':
                password = input("\nEnter password to analyze: ")
                if password.lower() == 'back':
                    continue
                
                print("\n" + "="*50)
                print("🛡️  ANALYZING PASSWORD SECURITY...")
                print("="*50)
                
                result = analyzer.analyze_password(password)
                
                # Display results
                print(f"\n📊 SECURITY SCORE: {result['security_assessment']['score']}/100")
                print(f"📈 RATING: {result['security_assessment']['rating']}")
                print(f"⏱️  CRACK TIME: {result['security_assessment']['estimated_crack_time']}")
                print(f"🔢 LENGTH: {result['basic_metrics']['length']} characters")
                print(f"🎯 ENTROPY: {result['basic_metrics']['entropy']} bits")
                
                # Breach status
                breach_status = result['security_assessment']['breach_status']
                if breach_status.get('breached'):
                    print(f"🚨 BREACH ALERT: {breach_status['message']}")
                else:
                    print(f"✅ {breach_status['message']}")
                
                # Weaknesses
                if result['security_assessment']['weaknesses']:
                    print(f"\n❌ WEAKNESSES FOUND:")
                    for weakness in result['security_assessment']['weaknesses'][:3]:
                        print(f"   • {weakness}")
                
                # Recommendations
                if result['recommendations']:
                    print(f"\n💡 RECOMMENDATIONS:")
                    for rec in result['recommendations'][:3]:
                        print(f"   • {rec['message']}")
                
            elif choice == '2':
                try:
                    length = int(input("Password length (default 16): ") or 16)
                    if length < 8:
                        print("❌ Minimum length is 8 characters")
                        continue
                    
                    password = analyzer.generate_secure_password(length=length)
                    print(f"\n🔑 GENERATED PASSWORD: {password}")
                    
                    # Auto-analyze generated password
                    analysis = analyzer.analyze_password(password)
                    print(f"📊 Security score: {analysis['security_assessment']['score']}/100")
                    
                except ValueError:
                    print("❌ Please enter a valid number")
                    
            elif choice == '3':
                print("\n📈 ANALYTICS DASHBOARD")
                print("=" * 30)
                analytics = analyzer.get_analytics_summary()
                
                if "error" not in analytics:
                    for key, value in analytics.items():
                        formatted_key = ' '.join(word.capitalize() for word in key.split('_'))
                        print(f"   {formatted_key}: {value}")
                else:
                    print("   Analytics not available")
                    
            elif choice == '4':
                print("\n👋 Thank you for using Password Security Analyzer Pro!")
                if analyzer.db_connection:
                    analyzer.db_connection.close()
                break
                
            else:
                print("❌ Invalid option. Please choose 1-4.")
                
        except KeyboardInterrupt:
            print("\n\n👋 Goodbye!")
            if analyzer.db_connection:
                analyzer.db_connection.close()
            break
        except Exception as e:
            print(f"❌ An error occurred: {e}")

if __name__ == "__main__":
    main()
