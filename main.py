#!/usr/bin/env python3
"""
Advanced Password Strength Tester
A comprehensive tool for analyzing password security
"""

import re
import math
import requests
import hashlib
from datetime import datetime

class PasswordTester:
    def __init__(self):
        self.common_passwords = self.load_common_passwords()
        
    def load_common_passwords(self):
        """Load common passwords from internal database"""
        common = [
            "123456", "password", "12345678", "qwerty", "123456789",
            "12345", "1234", "111111", "1234567", "dragon",
            "123123", "baseball", "abc123", "football", "monkey",
            "letmein", "shadow", "master", "666666", "qwertyuiop",
            "123321", "mustang", "1234567890", "michael", "superman"
        ]
        return set(common)

    def calculate_entropy(self, password):
        """Calculate password entropy in bits"""
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
            return 0
            
        entropy = len(password) * math.log2(pool_size)
        return round(entropy, 2)

    def check_weak_patterns(self, password):
        """Check for common weak patterns"""
        weaknesses = []
        
        # Common password check
        if password.lower() in self.common_passwords:
            weaknesses.append("Common password found in database")
            
        # Sequential characters
        sequences = [
            "123456", "654321", "abcdef", "qwerty", "asdfgh", "zxcvbn"
        ]
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
            weaknesses.append("Password is too short (min 8 characters)")
            
        # Common substitutions (l33t speak)
        leet_patterns = [
            r'[a@4]', r'[e3]', r'[i1!]', r'[o0]', r'[s5$]'
        ]
        return weaknesses

    def check_pwned(self, password):
        """Check password against Have I Been Pwned database"""
        try:
            # Calculate SHA1 hash
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1_hash[:5], sha1_hash[5:]
            
            # Query API
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                hashes = response.text.split('\n')
                for h in hashes:
                    if suffix in h:
                        count = int(h.split(':')[1])
                        return True, count
            return False, 0
            
        except Exception:
            return None, 0  # API unavailable

    def estimate_crack_time(self, entropy):
        """Estimate time to crack password"""
        # Assumptions: 10^9 hashes per second
        hashes_per_second = 10**9
        possible_combinations = 2 ** entropy
        
        seconds = possible_combinations / hashes_per_second
        
        # Convert to human readable
        if seconds < 60:
            return "instantly"
        elif seconds < 3600:
            return f"{int(seconds/60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds/3600)} hours"
        elif seconds < 31536000:
            return f"{int(seconds/86400)} days"
        else:
            years = seconds / 31536000
            if years > 1000000:
                return "millions of years"
            return f"{int(years)} years"

    def generate_report(self, password):
        """Generate comprehensive security report"""
        print(f"\n🔐 Password Analysis Report: {'*' * len(password)}")
        print(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Basic analysis
        length = len(password)
        entropy = self.calculate_entropy(password)
        weaknesses = self.check_weak_patterns(password)
        crack_time = self.estimate_crack_time(entropy)
        
        print(f"\n📊 Basic Information:")
        print(f"   Length: {length} characters")
        print(f"   Entropy: {entropy} bits")
        print(f"   Estimated crack time: {crack_time}")
        
        # Strength indicators
        print(f"\n✅ Strength Indicators:")
        if length >= 12:
            print("   ✓ Long password (12+ characters)")
        if entropy >= 80:
            print("   ✓ High entropy")
        if re.search(r'[a-z]', password) and re.search(r'[A-Z]', password):
            print("   ✓ Mixed case letters")
        if re.search(r'[0-9]', password):
            print("   ✓ Contains numbers")
        if re.search(r'[^a-zA-Z0-9]', password):
            print("   ✓ Contains special characters")
            
        # Weaknesses
        if weaknesses:
            print(f"\n❌ Weaknesses Found:")
            for weakness in weaknesses:
                print(f"   {weakness}")
        else:
            print(f"\n✅ No major weaknesses found")
            
        # Pwned check
        print(f"\n🌐 Data Breach Check:")
        pwned, count = self.check_pwned(password)
        if pwned is None:
            print("   ⚠️ Could not reach breach database")
        elif pwned:
            print(f"   🚨 PASSWORD FOUND IN {count} DATA BREACHES!")
        else:
            print("   ✅ Password not found in known breaches")
            
        # Security score
        score = self.calculate_security_score(password, entropy, weaknesses, pwned)
        print(f"\n🎯 SECURITY SCORE: {score}/100")
        
        return score

    def calculate_security_score(self, password, entropy, weaknesses, pwned):
        """Calculate security score 0-100"""
        score = 50  # Base score
        
        # Length points
        length = len(password)
        if length >= 16:
            score += 20
        elif length >= 12:
            score += 15
        elif length >= 8:
            score += 10
        else:
            score -= 10
            
        # Entropy points
        if entropy >= 100:
            score += 20
        elif entropy >= 80:
            score += 15
        elif entropy >= 60:
            score += 10
        elif entropy < 40:
            score -= 15
            
        # Weakness penalties
        score -= len(weaknesses) * 10
        
        # Pwned penalty
        if pwned:
            score -= 30
            
        # Ensure bounds
        return max(0, min(100, score))

    def generate_strong_password(self, length=16):
        """Generate a strong password suggestion"""
        import random
        import string
        
        characters = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(random.choice(characters) for _ in range(length))
        return password

def print_banner():
    """Print awesome ASCII banner"""
    banner = """
                                              █▓▓▓▓▓██▓▓██                                          
                                             █▓▓▓▓▓█████▓▓█                                         
                                             ▓████████████                                          
                                             ▓▓▓▓▓████████                                          
                                            ▓▓██▓▓█▓█▓▓██▓                                          
                                          ▓▓▓████▓▓█▓▓▓▓▓█▓▓                                        
                                          █████████████▓█████                                       
                                          ▓▓▓█████████████▓▒                                        
                                         ███████▓███████████▓                                       
                                         ████████████████████                                       
                                          ▓▓██████████████▓▓                                        
                                          ▓▓█▓█▓███████████▓                                        
                                          ▓▓█▓▓▓▒▓▓▓▓▓▓▓▓▓▓▓                                        
                                          ▓▓█▓▓▒▒▒▒▒▓▓▓▓▓▓▓▓                                        
                                          ▓▓█▓▒▒▒▒▒▓▒▒▒▓▓▓▓▓                                        
                                   ▒▒▒▒   ▓███▓▒▓▒▒▒▒▒▒▒▓▓▓▓                                        
                                ▒▒▒░▒▓▒▓█████████████▓▓▒▒▓▓▓                                        
                              ▓▒▓▒▓▓▒▒▒▓███████████████▓▓▓▓▓                                        
                            ▒▒▓▓▒▒▒▒▒▒▒█████████████████▓▓▓▓▒                                       
                            ▒▒▓▒▓▒░░▓▒░▓█████████████████▓▓▓▓▒▒                                     
                            ▒▒▒▓▒░▒▓▓▓▓██████████████████▓▓▓▓▓▓▓▒                                   
                            ▓▒▒▒░▓▒▒▒▓█  ▓██▓▓▓▓█████████▓▓▓██▓▓▒▒                                  
                            ▓▒▓▒▒▒▒▒▓   ▓▓█▓▓▓▓▓▓▓▓▓▓▓████▓█████▒▓▓                                 
                            ▒▓▒▓▓▓▓█    ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓██████████▓▒▓                                
                             █▓▓▓▓      ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓████████▓▓▓▒▓                               
                                        ▓▓▓▓▓▓▓██▓▓█████▓▓█████▓▓▒▒▒▒                               
                                    ▓▒▒▒▓▓▓▓██████████████████▓█▒▒▒▒▓                               
                                ▓▓█▓▒▓▓▓▓▓███████████████▓█▓▓▒▒▓▒▒▒▓▓                               
                            ▓▒▓▓▓█▓▓▓▓▓▓▓▓▓▓▓▒▓▓▓▓▓▒▓▓█▓▓█▓▒▒▒▒▓▒▓▓▒                                
                           ▒▒▒▓▓▓▓▓▒▒▒▒▒▒▒▒▒▓▓▓▓▓▒▒▒▒▒▒▒░▒░▒▒▒▓▓▓▓▓▓▒                               
                           ▓▓▒▓▒█▒▓▓▓▓▒▒▒▒▒▒▒░▒▒▒▓▒▒░▒▒▒▒▒▒▓█▓▓▓▓▓▓█▓▓▓                             
                           ▒▒▒▓▒▒▒▒▓▒▓▓▓▓▓▒▓▒▓▒▓▓▒▓█▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓█▓▓                             
                            ▓▓▒▒▓▓▓▓▓▓▓▓██▓▓▓▓▓▓▓▓▓▓█▓▓▓▓▓█▓▓▒▒▒▓▓▓▓▓█▓▓                            
                              ▓▓█████████████▓▓▓▓▓▓▓▒▒░░░░░▒▒▒▒▒▒▓▓▓▓█▓▓                            
                              ▓▓▓██▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░▒▒▒▒▒▒▒▒▓▓▓▓▓▓                            
                              ▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▓▓▒▓▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▓▓                            
                              ▓▓▓▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▓▓▓▒▒▒▒▒▒▒▓▒                            
                              ▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▒▒▒██▓██▒▒▒▒▒▒▒▓▒▓▒▒▒                          
                              ▓▓▓▒▒▒▒▒▒▒▓▓▓███████▒██▓█▒▒▒█▓▓▒▓█▒▒▒▓▒▓▒▒▓▓▒                         
                              ▒▓▒▒▒▒▓▓▓▓█▒▒▒▒▓▓▒▓██▓▒▒▒▓██▒▒▒▒▒▒▓▓▒▒▒▓▒▒█▓▓▒                        
                              ▒▓▒▒▓▓▓▓▓██▒▒█▓▓██▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒█▓▓▒▒                       
                            ▓▓▒▓▒▓▓▓██▓▒▒▓█▒▓▒▒▒▒▒▒▒▒▒▒█▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒█▓▓▒▓▒                      
                           ▓██▒▓▒▓▓███▒▓▓▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▓▒▓▒░▒▒▒▒▒▒▒██▓▒▒▒                      
                          ▓▓██▓▓▓▓▓██▒▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▓░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓██▓▓▒▒                      
                         ▒▓▓███▓▓▓▓▓█▒▒▓█▒▒▒█▓▒▒█▒▓█▒▒▒▒▒▒▒▒▒▒▓█▒▒▓█▒▒▒▓██▓▒▒▓                      
                         ▒▓▓▓███▓▓▓██▒▓▒▒▒▒▒█▒▒▒▒▒██▒█▒█▓▒█▒▓█▒█▒▒▓▓▒▒▓▓█▓▒▒▒▓                      
                        ▒▒▒▓▓████▓▓▓▓▒▒▒▒▒▒▒█▒▒▒▒▒██▒█▒▒▒▒█▒██▒██▒▒▒▒▓▒██▓▒▒▒▓                      
                         ▓▒▒▒▓▓████▓▓▓▒▒▓▒▒▒▒▓▓█▒▒██▒▒█▒▒▒▒▒▒▒▒▓▒▒▒▒▒▓▓█▓▓▒▒▓▒                      
                         ▒▓▒▒▓▓▓███▓▓▓▓▒█▓█░▒▒▒▒▒░▒▒▓▓▒████▓▒▒▒░▒▒▒▓▓▓██▓▒▒▓▒                       
                          ▒▒▒▓▒▓▓▓██▓█▓▓▒▒▒██▒▒▒▒▒▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒███▓▒▒▒▒▒                        
                           ▒▒▒▒▓▒▓▓▓▓█▓▓▓▒▒█▒▒░▓▒▓▒▒▓█▒▓▓▒▓░▒▒▓▓▓▒▓▓█▓▒▒▓▓▓                         
                            ▒▓▓▒▒▒▓▒▓▓▓██▓█▒▒▒▓█▓▓▓▒▒▓▓▓▒▓▒▓▒▓▒▒▓██▓▓▒▒▒▒▓▒                         
                           ▒▒▒▓▓▒▒▒▒▒▒▒▒▓▓▓▓██▓▓█▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒██▓▓▓▒▒▒▒▒▒▒                        
                          ▒▓▓▓▒▒▒▓▒▓▒▒▒▒▒▒▒▒▓▓▓▓▓█████▓▓▓▓▓▓▓▓▓▒▓▒▓▒▓▒▒▒▒▒▓▓▒                       
                          ▓▓▓▓▓▓▒▒▒▓▓▒▒▒▒▒▒▒▓▒▒▓▒▒▒▒▒▒▓▒▓▒▒░▒▒▓█▒▓▒▓▒▓▒▒▓▓█▓▒                       
                          ▓▓▓▓▓▓▓▓▓▒▒▓▓▓▓▓▓▓▓▒▒▓▓▓▒▓▓▓▓▒▒▒▓▓▓▒▒▓▓▒▓▓▒▒▓▓▓▓▓▒▒                       
                          ▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓█▓▓▓▓▓▓▓▓▓▒▓▓▓▓▓▓▓▓█▓▓▓▓▓▓▓▓▓▓▓▒▒▒                       
                          ▒▓▒▓▓▓▓▓▓▓▓▓▓██████████▓██▓█▓█▓▓▓▓▓█▓▓▓▓▓▓▓▓▓▓▓▒▒▒                        
                           ▒▒▒▓▓▓▓▓▓▓▓▓███████████████████████████▓▓▓▓▓▓▒▒▒                         
                            ▒▓▓▓▓▓▓▓▓▓▓███████████▒▒▒▒▒▒▒▓▓▓█▓▓▓▒▒▒▓▒▓▓▒▒▒                          
                             ▒▒▓▓▓▓▓▓▓▓████▒▒▓▒▒▓▓█▓▒▓▓▓▓▓█▓▓▓▓▓▓▒▓▓▒▒▓▒▒                           
                               ▓▓▓▓▓▓▓▓███▒▓▓▓▓▓▒▒▓▓▓▒▒▒▒▓▒▒▒▒▒▒▒▒▒▓▓▒▒▒                            
                                ▓▓▓▓▓▓▓▓▓▒▓▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▒▒▒                             
                                ▓▓▓▓▓▓▓▓▓█▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▓▓▒▒                              
                                ▓▓▓▓▓█▓█████▒▓▒▓▓▓▓▓▒▓▒▓▓▓▓▓▒▓▒▒▓▓▓▒▓▓                              
                                ▓▓▓▓███▓▓███████▓▒▒▓▓▓▓▓▓▒▒▓▓▓▓▓▓▓▓▓▓▓                              
                                ▓█▓▓██████████████████████████████▓▓▓▓                              
                                ▓███▓█████████████████████████████▓▓▓▓                              
                                 ███████████████████████████████████▓▓                              
                                  █████████████████████████████████▓▓                               
                                   ████████████████████████████████▓                                
                                     ████████████████████████████▓                                  
                                         ████████████████████▓
    
    🔐 ADVANCED PASSWORD STRENGTH TESTER 🔐
    """
    print(banner)

def main():
    tester = PasswordTester()
    print_banner()
    
    print("🚀 WELCOME TO ADVANCED PASSWORD TESTER!")
    print("=" * 55)
    
    while True:
        password = input("\n🔐 Enter password to test (or 'q' to quit): ")
        
        if password.lower() == 'q':
            print("👋 Goodbye!")
            break
            
        if not password:
            print("⚠️ Please enter a password!")
            continue
            
        # Generate report
        score = tester.generate_report(password)
        
        # Recommendations
        print(f"\n💡 RECOMMENDATIONS:")
        if score >= 80:
            print("   🎉 Excellent! This password is very secure.")
        elif score >= 60:
            print("   👍 Good, but could be improved.")
        elif score >= 40:
            print("   ⚠️ Medium strength - consider strengthening.")
        else:
            print("   🚨 Weak - change this password immediately!")
            
        # Offer to generate strong password
        if score < 60:
            generate = input("\nGenerate a strong password? (y/n): ")
            if generate.lower() == 'y':
                strong_pass = tester.generate_strong_password()
                print(f"💡 Suggested strong password: {strong_pass}")
                print("   (Copy this to a password manager)")
            
        print("=" * 55)

if __name__ == "__main__":
    main()
