
import hashlib
from typing import Optional, Dict
# Sample malware signatures (SHA-256 hashes)
MALWARE_SIGNATURES: Dict[str, str] = {
     "84c82835a5d21bbcf75a61706d8ab5491c9d5e3c47d2f5e6d67b348fe7bde39d": "WannaCry Ransomware",
    "71b6a493388e7d0b40c83ce903bc6b04e621f9eb76d04a89d14026c2a1f4ca48": "NotPetya Wiper",
    "b97d64b8cfe6f53ef3fd5cc92b75e9c2a90a3eec92d78e4d32e939ac8360f2d5": "Emotet Trojan",
    "5b6c733ef6ec8b58b238aa129f5e33e653b4b71c10a1ee290b6b104d5bcd0c77": "Agent Tesla Spyware",
    "a62153e15a0db9b3e775c65c25ef2cd67e306fb0b3be9937f3f0599db08cc3c1": "FormBook Infostealer",
    "9efab804a8c2d58ab69d82e5edc622a3d0c44c174ce19554bc238d7aa8b5d4e3": "Locky Ransomware",
    "fe1b1f2203da202b2c9cc78feae389ef6371f9a72790b53c05c8eb6a2b922825": "Zeus Banking Trojan",
    "b8b5dfb9424aaefb0b85ed358c503a9a47696dfcfef38e7d5878a1e2b2d0bffa": "Dridex Trojan",
    "f03e1d735060f5bfb26d238d2033d74bb812c19d89cf6b0dc26c6f4b4a2ef4f2": "TrickBot Banking Trojan",
    "0a6c9d98e5b7e2dc9aabc8a1653b3a9f2fcb0d4227b0a2ef89fc3d081292db94": "RAT NjRAT",
    "ae7d8a57929ed87bc6a7d3b35db0f7f2baf5ef5c1be474e7ea63e5f12f3f6be2": "Remcos RAT",
    "c9a022c7f78f9f6f41dbd1476ce6a51b39263e1a3f79ee372ec413b1f3e0113e": "DarkComet RAT",
    "d47d11cd2a4eec3e48d301f0b6f214f4871c8a843e38e1f24cf43bdf34d2ba66": "RedLine Stealer",
    "66a3ecb18471d59e401ecae6cb4e6f8a348b1e0b3b99e4b0c64b32c593b6bb27": "XMRig Cryptominer",
    "e3b0c44298fc1c149afbf4c8996fb924": "Sample Malware A",
    "5d41402abc4b2a76b9719d911017c592": "Sample Malware B",

}
def calculate_file_hash(file_path: str) -> Optional[str]:
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"Error calculating hash for {file_path}: {str(e)}")
        return None

def is_known_malware(file_hash: str) -> tuple[bool, Optional[str]]:
    if file_hash in MALWARE_SIGNATURES:
        return True, MALWARE_SIGNATURES[file_hash]
    return False, None

def update_signature_database(new_signatures: Dict[str, str]) -> None:
    MALWARE_SIGNATURES.update(new_signatures) 