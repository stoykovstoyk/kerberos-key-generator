#!/usr/bin/env python3
"""
Generate AES keys (AES256, AES128) + optional DES-CBC-MD5 + LM & NT hashes and print NTDS-style line.

Requires:
    pip install impacket

Usage examples:
    python gen_all_hashes.py --account "domain.bg\\alabala" --realm DOMAIN.BG --password "YourPassword123!" --rid 14496
    python gen_all_hashes.py --username alabala --realm DOMAIN.BG --password "YourPassword123!" --empty-lm
"""

import argparse
import binascii
import sys

# impacket imports
try:
    from impacket.krb5.crypto import _enctype_table
    from impacket.ntlm import compute_lmhash, compute_nthash
except Exception as e:
    raise SystemExit("Impacket is required. Install with: pip install impacket") from e

# mapping human names -> numeric enctype values (Kerberos standard)
ENCTYPE_NAME_TO_NUM = {
    'aes256-cts-hmac-sha1-96': 18,
    'aes128-cts-hmac-sha1-96': 17,
    'des-cbc-md5': 3,
}

EMPTY_LM_HEX = "aad3b435b51404eeaad3b435b51404ee"

def pretty_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode()

def normalize_account_and_realm(account: str, username: str, realm: str):
    """
    Return tuple (display_account, username_only, realm)
    - account may be like "domain.bg\\alabala" or "alabala@domain.bg" or just "alabala"
    - username and realm are fallback if account is not provided
    """
    username_only = username
    display_account = None
    if account:
        acct = account
        # domain\user
        if '\\' in acct:
            dom, user = acct.split('\\', 1)
            username_only = user if not username_only else username_only
            display_account = acct
            if not realm:
                realm = dom
        # user@domain
        elif '@' in acct:
            user, dom = acct.split('@', 1)
            username_only = user if not username_only else username_only
            display_account = acct
            if not realm:
                realm = dom
        else:
            # just user
            username_only = acct if not username_only else username_only
            display_account = username_only
    else:
        # no account provided: build a display_account if realm present
        if realm and username_only:
            display_account = f"{realm}\\{username_only}"
        elif username_only:
            display_account = username_only
        else:
            display_account = None

    return display_account, username_only, realm

def generate_all(username: str, realm: str, password: str, rid: int = 14496, include_des: bool = False, display_account: str = None, force_empty_lm: bool = False):
    # use username_only for salt (realm.upper() + username)
    if not username:
        raise ValueError("username required")

    if not realm:
        salt = username  # fallback - empty-ish salt
    else:
        salt = realm.upper() + username

    print(f"[*] Username (user only) : {username}")
    print(f"[*] Realm                : {realm or '<not provided>'}")
    print(f"[*] Salt used for AES    : {salt}")
    print(f"[*] Password             : {password}\n")

    # AES keys
    for name in ('aes256-cts-hmac-sha1-96','aes128-cts-hmac-sha1-96'):
        etype_num = ENCTYPE_NAME_TO_NUM.get(name)
        if etype_num not in _enctype_table:
            print(f"[!] Enctype {name} (num {etype_num}) not present in _enctype_table; skipping")
            continue
        try:
            key = _enctype_table[etype_num].string_to_key(password, salt, None)
            print(f"{name:<25}: {pretty_hex(key.contents)}")
        except Exception as e:
            print(f"[!] Error deriving {name}: {e}")

    # optional DES-CBC-MD5
    if include_des:
        name = 'des-cbc-md5'
        etype_num = ENCTYPE_NAME_TO_NUM.get(name)
        if etype_num in _enctype_table:
            try:
                key = _enctype_table[etype_num].string_to_key(password, salt, None)
                print(f"{name:<25}: {pretty_hex(key.contents)}")
            except Exception as e:
                print(f"[!] Error deriving {name}: {e}")
        else:
            print("[!] des-cbc-md5 enctype not present in this impacket build; skipping")

    # LM and NT using impacket helpers -> ensure bytes -> hexlify
    if force_empty_lm:
        lm_hex = EMPTY_LM_HEX
    else:
        lm_bytes = compute_lmhash(password)
        # compute_lmhash may return bytes or hex-string depending on impacket version; normalize
        if isinstance(lm_bytes, str):
            lm_hex = lm_bytes
        else:
            lm_hex = binascii.hexlify(lm_bytes).decode()

    nt_bytes = compute_nthash(password)
    if isinstance(nt_bytes, str):
        nt_hex = nt_bytes
    else:
        nt_hex = binascii.hexlify(nt_bytes).decode()

    print("\n[+] LM/NT hashes:")
    print(f"{'lm (hex)':<12}: {lm_hex}")
    print(f"{'nt (hex)':<12}: {nt_hex}")

    # Construct NTDS-style line.
    left_field = display_account if display_account else username
    print("\n[+] NTDS-style hash line:")
    print(f"{left_field}:{rid}:{lm_hex}:{nt_hex}:::")

def main():
    parser = argparse.ArgumentParser(description="Generate AES, optional DES, LM & NT hashes and NTDS-style line")
    parser.add_argument("--account", help=r'Account like "domain.bg\\alabala" or "alabala@domain.bg" (optional)')
    parser.add_argument("-u","--username", help="Username (e.g., alabala). Used if --account not given or to override.")
    parser.add_argument("-r","--realm", help="Realm / domain (e.g., DOMAIN.BG). If not provided and --account contains domain, it will be inferred.")
    parser.add_argument("-p","--password", required=True, help="Plaintext password")
    parser.add_argument("--rid", type=int, default=14496, help="User RID to include in NTDS line (default 14496)")
    parser.add_argument("--include-des", action="store_true", help="Also compute des-cbc-md5 key (if impacket supports it)")
    parser.add_argument("--empty-lm", action="store_true", help="Force the LM hex to the empty/disabled LM constant (aad3b435...) to match modern AD dumps")
    args = parser.parse_args()

    display_account, username_only, realm = normalize_account_and_realm(args.account, args.username, args.realm)

    if not username_only:
        print("Error: username is required (either via --account or --username).", file=sys.stderr)
        sys.exit(2)

    try:
        generate_all(username_only, realm, args.password, rid=args.rid, include_des=args.include_des, display_account=display_account, force_empty_lm=args.empty_lm)
    except Exception as e:
        print("Fatal error:", e, file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
