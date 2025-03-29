#!/bin/bash
# Step 1: Create and Activate Virtual Environment
echo "🔧 Setting up virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate  # Linux/macOS
# For Windows, comment the above and uncomment below:
# venv\Scripts\activate

# Step 2: Install Python Dependencies
echo "📦 Installing Python dependencies..."
pip install mnemonic bip32utils ecdsa bech32 requests cosmospy > /dev/null 2>&1
echo "✅ Dependencies installed."

# Step 3: Execute the Python Script with Prompts
echo "🚀 Running IBC monitor script..."
python3 - << 'EOF'
import json
import requests
import time
import random
import os
from mnemonic import Mnemonic
from bip32utils import BIP32Key
from hashlib import sha256
import ecdsa
import bech32
from cosmospy import Transaction
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Prompt for Wallet Input
print("Wallet Options:")
print("1. Generate a new wallet (mnemonic will be displayed)")
print("2. Use an existing private key")
while True:
    wallet_choice = input("Enter your choice (1 or 2): ").strip()
    if wallet_choice in ["1", "2"]:
        break
    print("❌ Invalid choice. Please enter 1 or 2.")

if wallet_choice == "1":
    def generate_wallet():
        mnemo = Mnemonic("english")
        mnemonic = mnemo.generate(strength=256)
        seed = mnemo.to_seed(mnemonic)
        master_key = BIP32Key.fromEntropy(seed)
        derived_key = master_key.ChildKey(44 + 0x80000000) \
                                .ChildKey(118 + 0x80000000) \
                                .ChildKey(0 + 0x80000000) \
                                .ChildKey(0) \
                                .ChildKey(0)
        privkey = derived_key.PrivateKey()
        sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        pubkey = b'\x02' + vk.to_string()[:32]
        def get_address(pubkey, prefix):
            sha = sha256(pubkey).digest()
            ripemd = sha256(sha).digest()[:20]
            return bech32.bech32_encode(prefix, bech32.convertbits(ripemd, 8, 5))
        stride_address = get_address(pubkey, "stride")
        union_address = get_address(pubkey, "union")
        print(f"Mnemonic: {mnemonic}")
        print(f"Stride Address: {stride_address}")
        print(f"Union Address: {union_address}")
        return privkey, mnemonic, stride_address, union_address

    priv_key, mnemonic_phrase, stride_addr, union_addr = generate_wallet()
    print("⚠️ Save this mnemonic securely! It will be used to derive your addresses.")
    WALLET_INPUT = mnemonic_phrase
elif wallet_choice == "2":
    while True:
        priv_key_input = input("Enter your private key (hex, 64 characters): ").strip()
        if not priv_key_input:
            print("❌ Private key cannot be empty. Try again.")
            continue
        if len(priv_key_input) != 64 or not all(c in "0123456789abcdefABCDEF" for c in priv_key_input):
            print("❌ Invalid private key: must be a 64-character hexadecimal string. Try again.")
            continue
        try:
            bytes.fromhex(priv_key_input)
            break
        except ValueError:
            print("❌ Invalid hex format. Try again.")
    WALLET_INPUT = priv_key_input
    print("✅ Private key accepted.")

# Prompt for Telegram Configuration
TELEGRAM_BOT_TOKEN = input("Enter your Telegram Bot Token: ").strip()
TELEGRAM_CHAT_ID = input("Enter your Telegram Chat ID: ").strip()
print("✅ Telegram configuration accepted.")

# Define RPC Endpoints and Token Configuration
RPCS = {
    "stride": "https://stride.testnet-1.stridenet.co/api",
    "union": "https://rest.testnet-9.union.build/"
}

TOKENS = {
    "stride": {"symbol": "STRD", "denom": "ustrd", "chain_id": "stride-internal-1"},
    "union": {"symbol": "UNO", "denom": "uuno", "chain_id": "union-testnet-9"}
}
MIN_TRANSFER_AMOUNT = 0.001
TIMEOUT_HEIGHT_DELTA = 1000

# Dynamically fetch IBC channels
def fetch_ibc_channels():
    ibc_channels = {}
    for source_chain, dest_chain in [("union", "stride"), ("stride", "union")]:
        rest_url = RPCS[source_chain].replace("rpc", "rest") if "rpc" in RPCS[source_chain] else RPCS[source_chain]
        try:
            response = requests.get(f"{rest_url}/ibc/core/channel/v1/channels", timeout=10)
            if response.status_code == 200:
                channels = response.json().get("channels", [])
                for channel in channels:
                    if channel["counterparty"]["chain_id"] == TOKENS[dest_chain]["chain_id"]:
                        ibc_channels[f"{source_chain}_to_{dest_chain}"] = channel["channel_id"]
                        break
                else:
                    print(f"⚠️ No channel found from {source_chain} to {dest_chain}")
            else:
                print(f"❌ Failed to fetch channels from {source_chain}: {response.text}")
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching IBC channels from {source_chain}: {e}")
    return ibc_channels

IBC_CHANNELS = fetch_ibc_channels()
if not IBC_CHANNELS:
    print("⚠️ Using fallback placeholder channels. Verify manually if transfers fail.")
    IBC_CHANNELS = {
        "union_to_stride": "channel-50",
        "stride_to_union": "channel-103"
    }

def send_telegram_message(message):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = {"chat_id": TELEGRAM_CHAT_ID, "text": message}
    try:
        requests.post(url, json=data, timeout=5)
        print(f"📩 Telegram: {message}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to send Telegram alert: {e}")

def derive_addresses(input_data):
    try:
        if " " in input_data.strip():
            mnemo = Mnemonic("english")
            if not mnemo.check(input_data):
                raise ValueError("Invalid mnemonic")
            seed = mnemo.to_seed(input_data)
            master_key = BIP32Key.fromEntropy(seed)
            derived_key = master_key.ChildKey(44 + 0x80000000) \
                                    .ChildKey(118 + 0x80000000) \
                                    .ChildKey(0 + 0x80000000) \
                                    .ChildKey(0) \
                                    .ChildKey(0)
            priv_key = derived_key.PrivateKey()
            sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
            vk = sk.verifying_key
            pubkey = b'\x02' + vk.to_string()[:32]
        else:
            priv_key = bytes.fromhex(input_data)
            sk = ecdsa.SigningKey.from_string(priv_key, curve=ecdsa.SECP256k1)
            vk = sk.verifying_key
            pubkey = b'\x02' + vk.to_string()[:32]
        
        def get_address(pubkey, prefix):
            sha = sha256(pubkey).digest()
            ripemd = sha256(sha).digest()[:20]
            return bech32.bech32_encode(prefix, bech32.convertbits(ripemd, 8, 5))
        
        stride_address = get_address(pubkey, "stride")
        union_address = get_address(pubkey, "union")
        print(f"Derived Stride Address: {stride_address}")
        print(f"Derived Union Address: {union_address}")
        return priv_key, stride_address, union_address
    except Exception as e:
        send_telegram_message(f"❌ Error deriving addresses: {e}")
        exit(1)

def get_balance(chain, address):
    rest_url = RPCS[chain].replace("rpc
