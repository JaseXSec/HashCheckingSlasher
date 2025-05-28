#!/usr/bin/env python3

import argparse
import hashlib
import re
import requests
import sys
import getpass
from typing import Tuple, Dict

class PasswordChecker:
    def __init__(self):
        self.MIN_LENGTH = 12
        self.HIBP_API_URL = "https://api.pwnedpasswords.com/range/{}"
        
    def check_strength(self, password: str) -> Tuple[int, Dict[str, bool]]:
        """
        Check password strength based on various criteria.
        Returns a tuple of (score, criteria_dict).
        """
        criteria = {
            "length": len(password) >= self.MIN_LENGTH,
            "uppercase": bool(re.search(r'[A-Z]', password)),
            "lowercase": bool(re.search(r'[a-z]', password)),
            "numbers": bool(re.search(r'\d', password)),
            "symbols": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        }
        
        score = sum(criteria.values())
        return score, criteria

    def calculate_entropy(self, password: str) -> float:
        """
        Calculate password entropy as a measure of randomness.
        Higher entropy indicates a more random (potentially stronger) password.
        """
        char_set_size = 0
        if re.search(r'[A-Z]', password): char_set_size += 26
        if re.search(r'[a-z]', password): char_set_size += 26
        if re.search(r'\d', password): char_set_size += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): char_set_size += 32
        
        entropy = len(password) * (char_set_size.bit_length() if char_set_size > 0 else 0)
        return entropy

    def check_hibp(self, password: str) -> Tuple[bool, int]:
        """
        Check if password has been exposed in data breaches using HaveIBeenPwned API.
        Returns a tuple of (is_pwned, times_found).
        """
        # Generate SHA-1 hash of the password
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        hash_prefix = sha1_hash[:5]
        hash_suffix = sha1_hash[5:]
        
        try:
            response = requests.get(self.HIBP_API_URL.format(hash_prefix))
            response.raise_for_status()
            
            # Check if the hash suffix appears in the response
            for line in response.text.splitlines():
                if line.split(':')[0] == hash_suffix:
                    return True, int(line.split(':')[1])
            
            return False, 0
            
        except requests.RequestException as e:
            print(f"Error checking HaveIBeenPwned API: {e}", file=sys.stderr)
            return False, 0

def main():
    parser = argparse.ArgumentParser(
        description="Check password strength and breach exposure",
        epilog="Note: This tool is for educational purposes. Use with caution in production environments."
    )
    
    # Get password securely using getpass
    try:
        password = getpass.getpass("Enter password to check: ")
    except (KeyboardInterrupt, EOFError):
        print("\nOperation cancelled by user", file=sys.stderr)
        sys.exit(1)

    if not password:
        print("Error: Password cannot be empty", file=sys.stderr)
        sys.exit(1)

    checker = PasswordChecker()
    
    # Check password strength
    strength_score, criteria = checker.check_strength(password)
    entropy = checker.calculate_entropy(password)
    
    # Check for breaches
    is_pwned, times_found = checker.check_hibp(password)
    
    # Print results
    print("\n=== Password Strength Analysis ===")
    print(f"Strength Score: {strength_score}/5")
    print("\nCriteria Met:")
    for criterion, is_met in criteria.items():
        print(f"✓ {criterion.capitalize()}" if is_met else f"✗ {criterion.capitalize()}")
    
    print(f"\nPassword Entropy: {entropy:.2f} bits")
    
    print("\n=== Breach Check ===")
    if is_pwned:
        print(f"⚠️  WARNING: This password was found in {times_found:,} data breaches!")
        print("It is strongly recommended to choose a different password.")
    else:
        print("✓ Good news! This password hasn't been found in any known data breaches.")

if __name__ == "__main__":
    main() 