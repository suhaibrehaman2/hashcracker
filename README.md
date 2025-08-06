# hashcracker
(HASHCRACKER)  which can crack md5 sha1 hashes



python code for hashcracker


import hashlib
import argparse
import logging
from datetime import datetime
import re
import os

# Configure logging for forensic audit trail
logging.basicConfig(
    filename=f"forensic_cracker_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def validate_hash(hash_str, hash_type):
    """Validate the format of the input hash."""
    hash_patterns = {
        "md5": r"^[0-9a-fA-F]{32}$",
        "sha1": r"^[0-9a-fA-F]{40}$"
    }
    pattern = hash_patterns.get(hash_type.lower())
    if not pattern or not re.match(pattern, hash_str):
        return False
    return True

def hash_password(password, hash_type):
    """Compute the hash of a password using the specified algorithm."""
    password = password.encode('utf-8')
    if hash_type.lower() == "md5":
        return hashlib.md5(password).hexdigest()
    elif hash_type.lower() == "sha1":
        return hashlib.sha1(password).hexdigest()
    else:
        raise ValueError(f"Unsupported hash type: {hash_type}")

def dictionary_attack(target_hash, hash_type, wordlist_path):
    """Perform a dictionary attack to crack the hash."""
    if not os.path.exists(wordlist_path):
        logging.error(f"Wordlist file not found: {wordlist_path}")
        return {"hash": target_hash, "status": "error", "message": f"Wordlist file not found: {wordlist_path}"}
    
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                password = line.strip()
                if not password:
                    continue
                computed_hash = hash_password(password, hash_type)
                logging.info(f"Attempting password: {password} (Hash: {computed_hash})")
                if computed_hash == target_hash.lower():
                    return {
                        "hash": target_hash,
                        "hash_type": hash_type,
                        "password": password,
                        "status": "success",
                        "message": f"Password found: {password}"
                    }
        return {
            "hash": target_hash,
            "hash_type": hash_type,
            "status": "failed",
            "message": "Password not found in wordlist."
        }
    except Exception as e:
        logging.error(f"Error during dictionary attack: {str(e)}")
        return {"hash": target_hash, "status": "error", "message": f"Error: {str(e)}"}

def generate_report(result):
    """Generate a forensic report from the cracking attempt."""
    report = "=== Forensic Password Cracker Report ===\n"
    report += f"Hash: {result['hash']}\n"
    report += f"Hash Type: {result.get('hash_type', 'Unknown')}\n"
    report += f"Status: {result['status'].capitalize()}\n"
    report += f"Message: {result['message']}\n"
    if result['status'] == "success":
        report += f"Cracked Password: {result['password']}\n"
    report += "=== End of Report ===\n"
    return report

def main():
    parser = argparse.ArgumentParser(description="Password Cracker for Forensic Investigations")
    parser.add_argument("hash", help="Target hash to crack (MD5 or SHA-1)")
    parser.add_argument("hash_type", choices=["md5", "sha1"], help="Hash type (md5 or sha1)")
    parser.add_argument("wordlist", help="Path to wordlist file")
    
    args = parser.parse_args()
    
    print("=== Forensic Password Cracker ===")
    print(f"Target Hash: {args.hash}")
    print(f"Hash Type: {args.hash_type.upper()}")
    print(f"Wordlist: {args.wordlist}")
    print("WARNING: Use this tool only with legal authorization for forensic purposes.")
    
    logging.info(f"Starting cracking attempt for hash: {args.hash} ({args.hash_type})")
    
    # Validate hash format
    if not validate_hash(args.hash, args.hash_type):
        print(f"Error: Invalid {args.hash_type} hash format.")
        logging.error(f"Invalid hash format: {args.hash} for {args.hash_type}")
        return
    
    # Perform dictionary attack
    result = dictionary_attack(args.hash, args.hash_type, args.wordlist)
    
    # Generate and display report
    report = generate_report(result)
    print(report)
    logging.info(f"Cracking result: {result['message']}")
    
    # Save report to file
    report_filename = f"cracker_report_{args.hash[:8]}.txt"
    with open(report_filename, "w") as f:
        f.write(report)
    print(f"Report saved to: {report_filename}")

if __name__ == "__main__":



OUTPUT:(1)

 C:/Users/user/.vscode/.venv/Scripts/python.exe c:/Users/user/.vscode/.vscode/passwordcrack.py  4bfe46a79d38aba1480cd5d9466beb9111895bf2 sha1 "C:\Users\user\Downloads\rockyou.txt"
=== Forensic Password Cracker ===
Target Hash: 4bfe46a79d38aba1480cd5d9466beb9111895bf2
Hash Type: SHA1
Wordlist: C:\Users\user\Downloads\rockyou.txt
WARNING: Use this tool only with legal authorization for forensic purposes.
=== Forensic Password Cracker Report ===
Hash: 4bfe46a79d38aba1480cd5d9466beb9111895bf2
Hash Type: sha1
Status: Success
Message: Password found: how are you
Cracked Password: how are you
=== End of Report ===

OUTPUT:(2)

 C:/Users/user/.vscode/.venv/Scripts/python.exe c:/Users/user/.vscode/.vscode/passwordcrack.py  0dd3f606e61470fcef288671aa15b2e3 md5 "C:\Users\user\Downloads\rockyou.txt"
=== Forensic Password Cracker ===
Target Hash:0dd3f606e61470fcef288671aa15b2e3
Hash Type: MD5
Wordlist: C:\Users\user\Downloads\rockyou.txt
WARNING: Use this tool only with legal authorization for forensic purposes.
=== Forensic Password Cracker Report ===
Hash: 0dd3f606e61470fcef288671aa15b2e3
Hash Type: md5
Status: Success
Message: Password found: doing well
Cracked Password: doing well
=== End of Report ===






    main()
