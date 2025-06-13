#!/usr/bin/env python3
"""
Simple Hash Cracker
Author: Hein Htet Zaw
Date: May 2025
Description: Fast multi-threaded hash cracker for security assessments
"""
import hashlib
import sys
import threading
import itertools
import string
from datetime import datetime
import argparse
from queue import Queue
import time

# ASCII Banner
print(r"""
 _   _           _       _____                _             
| | | |         | |     /  __ \              | |            
| |_| | __ _ ___| |__   | /  \/_ __ __ _  ___| | _____ _ __ 
|  _  |/ _` / __| '_ \  | |   | '__/ _` |/ __| |/ / _ \ '__|
| | | | (_| \__ \ | | | | \__/\ | | (_| | (__|   <  __/ |   
\_| |_/\__,_|___/_| |_|  \____/_|  \__,_|\___|_|\_\___|_|   
                                                           
                 Security Assessment Tool v1.0
                 Educational Use Only - Get Permission!
""")

# Global variables
q = Queue()
found_password = None
attempts = 0
start_time = None
stop_threads = False

def hash_password(password, algorithm):
    """Hash a password with specified algorithm"""
    if algorithm == 'md5':
        return hashlib.md5(password.encode()).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(password.encode()).hexdigest()
    elif algorithm == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == 'sha512':
        return hashlib.sha512(password.encode()).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}")

def crack_hash(target_hash, algorithm):
    """Worker function to crack hash"""
    global found_password, attempts, stop_threads
    
    while not stop_threads and found_password is None:
        try:
            password = q.get(timeout=1)
            attempts += 1
            
            # Hash the password
            hashed = hash_password(password, algorithm)
            
            # Check if it matches
            if hashed == target_hash:
                found_password = password
                stop_threads = True
                elapsed = time.time() - start_time
                print(f"\n[+] PASSWORD FOUND: {password}")
                print(f"[+] Attempts: {attempts:,}")
                print(f"[+] Time: {elapsed:.2f} seconds")
                print(f"[+] Rate: {attempts/elapsed:.0f} attempts/sec")
                break
            
            # Progress indicator
            if attempts % 10000 == 0:
                elapsed = time.time() - start_time
                rate = attempts / elapsed if elapsed > 0 else 0
                print(f"[*] Tried {attempts:,} passwords ({rate:.0f}/sec)...", end='\r')
                
            q.task_done()
            
        except:
            break

def dictionary_attack(target_hash, algorithm, wordlist_file, threads):
    """Perform dictionary attack"""
    global start_time, stop_threads
    
    print(f"[*] Starting dictionary attack")
    print(f"[*] Algorithm: {algorithm.upper()}")
    print(f"[*] Target: {target_hash}")
    print(f"[*] Wordlist: {wordlist_file}")
    print(f"[*] Threads: {threads}")
    print(f"[*] Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    start_time = time.time()
    
    # Create thread pool
    for _ in range(threads):
        t = threading.Thread(target=crack_hash, args=(target_hash, algorithm))
        t.daemon = True
        t.start()
    
    # Load wordlist
    try:
        with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                if stop_threads:
                    break
                password = line.strip()
                if password:
                    q.put(password)
                    
                    # Also try common variations
                    variations = [
                        password.capitalize(),
                        password.upper(),
                        password + '123',
                        password + '1',
                        password + '!',
                        '123' + password
                    ]
                    
                    for var in variations:
                        if not stop_threads:
                            q.put(var)
        
        # Wait for completion
        q.join()
        
    except FileNotFoundError:
        print(f"[-] Wordlist file '{wordlist_file}' not found")
        return False
    except Exception as e:
        print(f"[-] Error reading wordlist: {e}")
        return False
    
    return found_password is not None

def brute_force_attack(target_hash, algorithm, max_length, charset, threads):
    """Perform brute force attack"""
    global start_time, stop_threads
    
    charsets = {
        'digits': string.digits,
        'lower': string.ascii_lowercase,
        'upper': string.ascii_uppercase,
        'letters': string.ascii_letters,
        'alphanum': string.ascii_letters + string.digits,
        'all': string.ascii_letters + string.digits + string.punctuation
    }
    
    if charset not in charsets:
        print(f"[-] Invalid charset: {charset}")
        return False
    
    chars = charsets[charset]
    
    print(f"[*] Starting brute force attack")
    print(f"[*] Algorithm: {algorithm.upper()}")
    print(f"[*] Target: {target_hash}")
    print(f"[*] Max length: {max_length}")
    print(f"[*] Charset: {charset} ({len(chars)} characters)")
    print(f"[*] Threads: {threads}")
    print(f"[*] Start time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    start_time = time.time()
    
    # Create thread pool
    for _ in range(threads):
        t = threading.Thread(target=crack_hash, args=(target_hash, algorithm))
        t.daemon = True
        t.start()
    
    # Generate passwords
    for length in range(1, max_length + 1):
        if stop_threads:
            break
            
        print(f"[*] Trying length {length}...")
        
        for combination in itertools.product(chars, repeat=length):
            if stop_threads:
                break
            password = ''.join(combination)
            q.put(password)
    
    # Wait for completion
    q.join()
    
    return found_password is not None

def create_sample_wordlist():
    """Create a sample wordlist for testing"""
    wordlist = [
        'password', 'admin', 'login', 'test', 'guest', 'root', 'user',
        'welcome', 'hello', 'world', 'python', 'security', 'hash',
        '123456', 'qwerty', 'abc123', 'letmein', 'monkey', 'dragon',
        'sunshine', 'master', 'shadow', 'football', 'jesus', 'ninja',
        'password123', 'admin123', 'root123', 'test123', 'guest123'
    ]
    
    with open('wordlist.txt', 'w') as f:
        for word in wordlist:
            f.write(word + '\n')
    
    print("[+] Created sample wordlist: wordlist.txt")

def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description="Simple hash cracker")
    parser.add_argument("hash", help="Hash to crack")
    parser.add_argument("-a", "--algorithm", choices=['md5', 'sha1', 'sha256', 'sha512'],
                       default='md5', help="Hash algorithm (default: md5)")
    parser.add_argument("-m", "--method", choices=['dictionary', 'brute'],
                       default='dictionary', help="Attack method (default: dictionary)")
    parser.add_argument("-w", "--wordlist", default='wordlist.txt',
                       help="Wordlist file (default: wordlist.txt)")
    parser.add_argument("-l", "--length", type=int, default=4,
                       help="Max length for brute force (default: 4)")
    parser.add_argument("-c", "--charset", choices=['digits', 'lower', 'upper', 'letters', 'alphanum', 'all'],
                       default='lower', help="Charset for brute force (default: lower)")
    parser.add_argument("-t", "--threads", type=int, default=50,
                       help="Number of threads (default: 50)")
    parser.add_argument("--create-wordlist", action='store_true',
                       help="Create sample wordlist and exit")
    parser.add_argument("--test", help="Generate hash for testing")
    
    args = parser.parse_args()
    
    # Handle special options
    if args.create_wordlist:
        create_sample_wordlist()
        return
    
    if args.test:
        test_hash = hash_password(args.test, args.algorithm)
        print(f"[+] Password: {args.test}")
        print(f"[+] Algorithm: {args.algorithm.upper()}")
        print(f"[+] Hash: {test_hash}")
        return
    
    # Ethical warning
    print("[!] EDUCATIONAL USE ONLY")
    print("[!] Only crack hashes you created or have permission to test")
    response = input("[?] Do you have authorization to crack this hash? (y/N): ")
    if response.lower() != 'y':
        print("[-] Operation cancelled")
        return
    
    # Validate hash format
    expected_lengths = {'md5': 32, 'sha1': 40, 'sha256': 64, 'sha512': 128}
    if len(args.hash) != expected_lengths[args.algorithm]:
        print(f"[-] Invalid {args.algorithm.upper()} hash length")
        return
    
    # Perform attack
    success = False
    
    if args.method == 'dictionary':
        success = dictionary_attack(args.hash, args.algorithm, args.wordlist, args.threads)
    elif args.method == 'brute':
        success = brute_force_attack(args.hash, args.algorithm, args.length, args.charset, args.threads)
    
    # Final result
    if not success and found_password is None:
        elapsed = time.time() - start_time if start_time else 0
        print(f"\n[-] Password not found")
        print(f"[-] Attempts: {attempts:,}")
        print(f"[-] Time: {elapsed:.2f} seconds")
        print(f"[-] Try different method or parameters")
    
    print(f"[*] End time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user")
        stop_threads = True
        if attempts > 0 and start_time:
            elapsed = time.time() - start_time
            rate = attempts / elapsed if elapsed > 0 else 0
            print(f"[*] Attempted {attempts:,} passwords in {elapsed:.2f} seconds ({rate:.0f}/sec)")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)
