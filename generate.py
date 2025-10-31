#!/usr/bin/env python3
"""
Generate Kerberos keys (AES256, AES128)
from a plaintext password, username, and realm.

Requires: pip install impacket
"""

import sys
from hashlib import new as hashlib_new
import binascii

try:
    from impacket.krb5.crypto import _enctype_table
except Exception as e:
    raise SystemExit("Impacket is required. Install with: pip install impacket") from e

# Map human names to Kerberos enctype numeric values
ENCTYPE_NAME_TO_NUM = {
    'aes256-cts-hmac-sha1-96': 18,   # AES256-CTS-HMAC-SHA1-96
    'aes128-cts-hmac-sha1-96': 17,   # AES128-CTS-HMAC-SHA1-96
    # add others if you need them
}

def generate_kerberos_hashes(username: str, realm: str, password: str):
    # The salt used by AD = uppercase realm + username (no separator)
    salt = realm.upper() + username

    print(f"[*] Username : {username}")
    print(f"[*] Realm    : {realm}")
    print(f"[*] Salt     : {salt}")
    print(f"[*] Password : {password}\n")

    enc_types = [
        'aes256-cts-hmac-sha1-96',
        'aes128-cts-hmac-sha1-96',
    ]

    # If the table uses numeric keys, use the numeric mapping
    for enctype_name in enc_types:
        if enctype_name in _enctype_table:
            # some impacket versions may have string keys — try direct first
            etype_key = enctype_name
        else:
            # fallback to numeric mapping
            etype_num = ENCTYPE_NAME_TO_NUM.get(enctype_name)
            if etype_num is None or etype_num not in _enctype_table:
                print(f"[!] Enctype {enctype_name} not found in _enctype_table (tried numeric {etype_num}).")
                print_available_enctypes()
                continue
            etype_key = etype_num

        try:
            key = _enctype_table[etype_key].string_to_key(password, salt, None)
            print(f"{enctype_name:<25}: {key.contents.hex()}")
        except Exception as e:
            print(f"[!] Error deriving {enctype_name}: {e}")




def print_available_enctypes():
    print("\n[debug] Available keys in _enctype_table:")
    try:
        keys = list(_enctype_table.keys())
        print(keys)
    except Exception:
        print("  <couldn't list keys>")
    print("If none of the expected enctypes are present, check your impacket version.\n")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Generate Kerberos hashes from password")
    parser.add_argument("-u", "--username", required=True, help="Username (e.g., alabala)")
    parser.add_argument("-r", "--realm", required=True, help="Realm / domain (e.g., DOMAIN.BG)")
    parser.add_argument("-p", "--password", required=True, help="Plaintext password")
    args = parser.parse_args()

    generate_kerberos_hashes(args.username, args.realm, args.password)
