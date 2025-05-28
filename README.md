<p align="center">
  <img src="images/Hash_Slinging_Slasher.webp" alt="HashCheckingSlasher Logo" width="200"/>
</p>

# HashCheckingSlasher

A command-line tool to check password strength and verify if it has been exposed in data breaches using the HaveIBeenPwned API.

This tool is intended for educational and testing purposes only. While it implements secure practices for API communication, please exercise caution when using it with real passwords.

## Features

- Password strength checking (length, complexity, character types)
- Data breach verification using HaveIBeenPwned API
- Secure password handling using `getpass`
- Detailed strength scoring

## Security Considerations

This tool implements several security best practices:
- Uses secure password input via `getpass` to prevent password exposure
- Implements k-Anonymity model when checking against HaveIBeenPwned API
- Never stores or logs passwords
- Only the first 5 characters of the password hash are transmitted over the network

However, please note:
- This is primarily an educational tool
- For production use cases, consider using established password management solutions
- Never use this tool with sensitive/production passwords
- The tool cannot guarantee complete security of the password being checked

## Installation

1. Clone this repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Simply run the script and follow the secure password prompt:

```bash
python hash_checker.py
```

The tool will securely prompt you for a password and provide:
- Password strength analysis
- Criteria compliance check
- Entropy calculation
- Data breach exposure check

## How It Works

1. Password input is handled securely using Python's `getpass` module
2. The password is evaluated against multiple strength criteria
3. A SHA-1 hash is generated for the HaveIBeenPwned API check
4. Only the first 5 characters of the hash are sent to the API (k-Anonymity model)
5. Results are displayed with clear recommendations

## Security Implementation

The tool uses several security measures:
- No command-line arguments for password input
- No password storage or logging
- Secure API communication using k-Anonymity
- Clear security warnings and usage guidelines
