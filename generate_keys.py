#!/usr/bin/env python3
"""Generate AES256-GCM encryption key and Ed25519 signing key pair."""

import base64
import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_aes256_gcm_key() -> bytes:
    """Generate a 256-bit (32-byte) AES-GCM key."""
    return AESGCM.generate_key(bit_length=256)


def generate_ed25519_keypair():
    """Generate Ed25519 private and public keys."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def save_key_to_file(filename: str, data: bytes, description: str):
    """Save key data to a file with base64 encoding for readability."""
    encoded = base64.b64encode(data).decode('utf-8')
    with open(filename, 'w') as f:
        f.write(f"# {description}\n")
        f.write(f"{encoded}\n")
    print(f"Saved: {filename}")


def save_raw_key(filename: str, data: bytes, description: str):
    """Save key data as raw binary (for tools expecting raw bytes)."""
    with open(filename, 'wb') as f:
        f.write(data)
    print(f"Saved: {filename} ({description})")


def save_ed25519_keys(private_key, public_key, private_file: str, public_file: str):
    """Save Ed25519 keys in PEM format."""
    # Serialize private key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    with open(private_file, 'wb') as f:
        f.write(private_pem)
    print(f"Saved: {private_file}")
    
    with open(public_file, 'wb') as f:
        f.write(public_pem)
    print(f"Saved: {public_file}")


def main():
    # Create output directory
    output_dir = "generated_keys"
    os.makedirs(output_dir, exist_ok=True)
    
    print("Generating cryptographic keys...\n")
    
    # Generate AES256-GCM key
    aes_key = generate_aes256_gcm_key()

    # Save base64 version for human readability
    aes_key_path = os.path.join(output_dir, "aes256_gcm.key")
    save_key_to_file(aes_key_path, aes_key, "AES256-GCM Encryption Key (32 bytes, base64 encoded)")

    # Save raw binary version for zeta tool
    aes_raw_path = os.path.join(output_dir, "aes256_gcm.bin")
    save_raw_key(aes_raw_path, aes_key, "AES256-GCM raw 32-byte binary key")
    
    # Generate Ed25519 key pair
    ed_private, ed_public = generate_ed25519_keypair()
    ed_private_path = os.path.join(output_dir, "ed25519_private.pem")
    ed_public_path = os.path.join(output_dir, "ed25519_public.pem")
    save_ed25519_keys(ed_private, ed_public, ed_private_path, ed_public_path)
    
    # Also save raw Ed25519 private key (seed) for reference
    ed_private_raw = ed_private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    )
    ed_raw_path = os.path.join(output_dir, "ed25519_private.raw")
    save_key_to_file(ed_raw_path, ed_private_raw, "Ed25519 Private Key (raw 32 bytes, base64 encoded)")
    
    ed_public_raw = ed_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    ed_pub_raw_path = os.path.join(output_dir, "ed25519_public.raw")
    save_key_to_file(ed_pub_raw_path, ed_public_raw, "Ed25519 Public Key (raw 32 bytes, base64 encoded)")
    
    print(f"\nAll keys saved to '{output_dir}/' directory")
    print("\nKey Summary:")
    print(f"  - AES256-GCM Key: {len(aes_key)} bytes")
    print(f"  - Ed25519 Private Key: {len(ed_private_raw)} bytes")
    print(f"  - Ed25519 Public Key: {len(ed_public_raw)} bytes")
    print("\nFor zeta tool, use: --key-file generated_keys/aes256_gcm.bin")


if __name__ == "__main__":
    main()
