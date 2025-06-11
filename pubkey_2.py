#!/usr/bin/env python3
"""
Extract RSA components from SSH public key files manually without external dependencies.
"""

import base64
import struct


def extract_rsa_components_manual(public_key_file):
    """
    Extract RSA components manually by parsing SSH public key format.
    
    Args:
        public_key_file: Path to the SSH public key file
    
    Returns:
        tuple: (exponent, modulus) as integers
    """
    with open(public_key_file, 'r') as f:
        content = f.read().strip()
    
    # SSH public key format: "ssh-rsa <base64_data> [comment]"
    parts = content.split()
    if len(parts) < 2:
        raise ValueError("Invalid SSH public key format")
    
    key_type = parts[0]
    if key_type != "ssh-rsa":
        raise ValueError(f"Expected ssh-rsa key type, got {key_type}")
    
    # Decode the base64 data
    key_data = base64.b64decode(parts[1])
    
    # Parse the SSH public key format
    offset = 0
    
    def read_ssh_string(data, offset):
        """Read a length-prefixed string from SSH key data."""
        if offset + 4 > len(data):
            raise ValueError(f"Cannot read length at offset {offset}")
        
        length = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        
        if offset + length > len(data):
            raise ValueError(f"Cannot read {length} bytes at offset {offset}")
        
        return data[offset:offset+length], offset + length
    
    # Read key type (should be "ssh-rsa")
    key_type_bytes, offset = read_ssh_string(key_data, offset)
    if key_type_bytes.decode() != "ssh-rsa":
        raise ValueError(f"Invalid key type in data: {key_type_bytes.decode()}")
    
    # Read exponent (e)
    e_bytes, offset = read_ssh_string(key_data, offset)
    
    # Read modulus (n)
    n_bytes, offset = read_ssh_string(key_data, offset)
    
    # Convert bytes to integers (big-endian)
    e = int.from_bytes(e_bytes, 'big')
    n = int.from_bytes(n_bytes, 'big')
    
    return e, n


def extract_rsa_components_from_string(public_key_string):
    """
    Extract RSA components from an SSH public key string directly.
    
    Args:
        public_key_string: SSH public key as a string
    
    Returns:
        tuple: (exponent, modulus) as integers
    """
    content = public_key_string.strip()
    
    # SSH public key format: "ssh-rsa <base64_data> [comment]"
    parts = content.split()
    if len(parts) < 2:
        raise ValueError("Invalid SSH public key format")
    
    key_type = parts[0]
    if key_type != "ssh-rsa":
        raise ValueError(f"Expected ssh-rsa key type, got {key_type}")
    
    # Decode the base64 data
    key_data = base64.b64decode(parts[1])
    
    # Parse the SSH public key format
    offset = 0
    
    def read_ssh_string(data, offset):
        """Read a length-prefixed string from SSH key data."""
        if offset + 4 > len(data):
            raise ValueError(f"Cannot read length at offset {offset}")
        
        length = struct.unpack('>I', data[offset:offset+4])[0]
        offset += 4
        
        if offset + length > len(data):
            raise ValueError(f"Cannot read {length} bytes at offset {offset}")
        
        return data[offset:offset+length], offset + length
    
    # Read key type (should be "ssh-rsa")
    key_type_bytes, offset = read_ssh_string(key_data, offset)
    if key_type_bytes.decode() != "ssh-rsa":
        raise ValueError(f"Invalid key type in data: {key_type_bytes.decode()}")
    
    # Read exponent (e)
    e_bytes, offset = read_ssh_string(key_data, offset)
    
    # Read modulus (n)
    n_bytes, offset = read_ssh_string(key_data, offset)
    
    # Convert bytes to integers (big-endian)
    e = int.from_bytes(e_bytes, 'big')
    n = int.from_bytes(n_bytes, 'big')
    
    return e, n


def format_key_info(e, n):
    """Format key information for display."""
    bit_length = n.bit_length()
    return {
        'exponent': e,
        'modulus': n,
        'bit_length': bit_length,
        'hex_exponent': hex(e),
        'hex_modulus': hex(n)
    }


# Usage example
if __name__ == "__main__":
    public_key_file = "/Users/mihirsinghal/.ssh/id_rsa_test.pub"
    
    try:
        # Method 1: From file
        e, n = extract_rsa_components_manual(public_key_file)
        
        info = format_key_info(e, n)
        
        print("RSA Public Key Components:")
        print(f"Exponent (e): {info['exponent']}")
        print(f"Exponent (hex): {info['hex_exponent']}")
        print(f"Modulus (n): {info['modulus']}")
        print(f"Modulus (hex): {info['hex_modulus']}")
        print(f"Modulus bit length: {info['bit_length']}")
        
        # Verify common exponent values
        if e == 65537:
            print("✓ Using standard RSA exponent 65537 (0x10001)")
        elif e == 3:
            print("⚠ Using small exponent 3 (less secure)")
        else:
            print(f"• Using custom exponent {e}")
            
    except FileNotFoundError:
        print(f"Error: Public key file not found: {public_key_file}")
        print("\nYou can also use the function directly with a key string:")
        print("e, n = extract_rsa_components_from_string('ssh-rsa AAAAB3NzaC1yc2E...')")
    except Exception as ex:
        print(f"Error: {ex}")