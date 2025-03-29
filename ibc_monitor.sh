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

# Step 3: Execute the Python Script
echo "🚀 Running IBC monitor script..."
exec "$VIRTUAL_ENV/bin/python3" - << 'EOF'
import json
import configparser
import requests
import time
import random
import os
from mnemonic import Mnemonic
from bip32utils import BIP32Key
from hashlib import sha256
import ecdsa
import bech32
from cosmospy import Transaction, BIP32DerivationError
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Prompt for Wallet Input
WALLET_FILE = "wallet.json"
print("Wallet Options:")
print("1. Generate a new wallet (mnemonic will be displayed)")
print("2. Use an existing private key")
wallet_choice = input("Enter your choice (1 or 2): ").strip()

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
    with open(WALLET_FILE, "w") as f:
        json.dump({"mnemonic": mnemonic_phrase}, f)
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
    with open(WALLET_FILE, "w") as f:
        json.dump({"private_key": priv_key_input}, f)
    print(f"✅ Private key saved to {WALLET_FILE}")
else:
    raise ValueError("Invalid choice. Please select 1 or 2.")

with open(WALLET_FILE, "r") as f:
    wallet_data = json.load(f)
WALLET_INPUT = wallet_data.get("private_key") or wallet_data.get("mnemonic")

# Prompt for Config if Missing
CONFIG_FILE = "config.file"
if not os.path.exists(CONFIG_FILE):
    telegram_bot_token = input("Enter your Telegram Bot Token: ")
    telegram_chat_id = input("Enter your Telegram Chat ID: ")
    config = configparser.ConfigParser()
    config["RPC"] = {
        "stride": "https://stride.testnet-1.stridenet.co/api",
        "union": "https://rest.testnet-9.union.build/"
    }
    config["Telegram"] = {
        "bot_token": telegram_bot_token,
        "chat_id": telegram_chat_id
    }
    with open(CONFIG_FILE, "w") as f:
        config.write(f)
    print(f"✅ Config saved to {CONFIG_FILE}")

config = configparser.ConfigParser()
config.read(CONFIG_FILE)

RPCS = {
    "stride": config["RPC"]["stride"],
    "union": config["RPC"]["union"]
}
TELEGRAM_BOT_TOKEN = config["Telegram"]["bot_token"]
TELEGRAM_CHAT_ID = config["Telegram"]["chat_id"]

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
            def get_address(pubkey, prefix):
                sha = sha256(pubkey).digest()
                ripemd = sha256(sha).digest()[:20]
                return bech32.bech32_encode(prefix, bech32.convertbits(ripemd, 8, 5))
            stride_address = get_address(pubkey, "stride")
            union_address = get_address(pubkey, "union")
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
    rest_url = RPCS[chain].replace("rpc", "rest") if "rpc" in RPCS[chain] else RPCS[chain]
    denom = TOKENS[chain]["denom"]
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    try:
        response = session.get(f"{rest_url}/cosmos/bank/v1beta1/balances/{address}", timeout=10)
        if response.status_code == 200:
            balances = response.json().get("balances", [])
            for balance in balances:
                if balance["denom"] == denom:
                    return float(balance["amount"]) / 1_000_000
        return 0.0
    except requests.exceptions.RequestException as e:
        send_telegram_message(f"❌ Failed to fetch balance for {chain}: {e}")
        return 0.0

def get_account_details(address, chain):
    rest_url = RPCS[chain].replace("rpc", "rest") if "rpc" in RPCS[chain] else RPCS[chain]
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    try:
        response = session.get(f"{rest_url}/cosmos/auth/v1beta1/accounts/{address}", timeout=10)
        if response.status_code == 200:
            data = response.json()["account"]
            return int(data["account_number"]), int(data["sequence"])
        return 0, 0
    except requests.exceptions.RequestException as e:
        send_telegram_message(f"❌ Failed to fetch account details for {chain}: {e}")
        return 0, 0

def estimate_gas(chain, tx_json, historical_factor=1.2):
    rest_url = RPCS[chain].replace("rpc", "rest") if "rpc" in RPCS[chain] else RPCS[chain]
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    try:
        sim_tx = {"tx": json.loads(tx_json)}
        response = session.post(f"{rest_url}/cosmos/tx/v1beta1/simulate", json=sim_tx, timeout=10)
        if response.status_code == 200:
            gas_used = int(response.json()["gas_info"]["gas_used"])
            return int(gas_used * historical_factor)
        return 200000
    except requests.exceptions.RequestException as e:
        send_telegram_message(f"❌ Failed to estimate gas for {chain}: {e}")
        return 200000

def check_mempool(chain, tx_hash):
    rest_url = RPCS[chain].replace("rpc", "rest") if "rpc" in RPCS[chain] else RPCS[chain]
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    try:
        response = session.get(f"{rest_url}/cosmos/tx/v1beta1/txs?events=tx.hash={tx_hash}", timeout=10)
        if response.status_code == 200 and response.json()["txs"]:
            return True  # Transaction found in mempool or already confirmed
        return False
    except requests.exceptions.RequestException as e:
        send_telegram_message(f"❌ Error checking mempool for {chain}: {e}")
        return False

def monitor_transaction(chain, tx_hash):
    rest_url = RPCS[chain].replace("rpc", "rest") if "rpc" in RPCS[chain] else RPCS[chain]
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    max_attempts = 10
    for attempt in range(max_attempts):
        if check_mempool(chain, tx_hash):
            send_telegram_message(f"🕒 Transaction {tx_hash} detected in {chain} mempool (attempt {attempt+1}/{max_attempts})")
        try:
            response = session.get(f"{rest_url}/cosmos/tx/v1beta1/txs/{tx_hash}", timeout=10)
            if response.status_code == 200:
                tx_response = response.json()["tx_response"]
                if tx_response["code"] == 0:
                    send_telegram_message(f"✅ Transaction {tx_hash} included in block {tx_response['height']} on {chain}")
                    return True, "Success"
                send_telegram_message(f"❌ Transaction {tx_hash} failed with code {tx_response['code']}: {tx_response['raw_log']}")
                return False, f"Failed with code {tx_response['code']}"
            time.sleep(2 * (attempt + 1))
        except requests.exceptions.RequestException:
            time.sleep(2 * (attempt + 1))
    send_telegram_message(f"❌ Transaction {tx_hash} timed out after {max_attempts} attempts on {chain}")
    return False, "Timeout waiting for transaction confirmation"

def perform_ibc_transfer(priv_key, source_chain, source_addr, dest_chain, dest_addr, sequence_tracker):
    source_balance = get_balance(source_chain, source_addr)
    if source_balance < MIN_TRANSFER_AMOUNT:
        send_telegram_message(f"❌ Not enough {TOKENS[source_chain]['symbol']} ({source_balance}) to transfer from {source_chain}.")
        return False, sequence_tracker

    amount = int(MIN_TRANSFER_AMOUNT * 1_000_000)
    rest_url = RPCS[source_chain].replace("rpc", "rest") if "rpc" in RPCS[source_chain] else RPCS[source_chain]
    
    max_retries = 3
    for attempt in range(max_retries):
        latest_block = requests.get(f"{rest_url}/cosmos/base/tendermint/v1beta1/blocks/latest").json()
        revision_number = int(latest_block["block"]["header"]["chain_id"].split("-")[-1])
        latest_height = int(latest_block["block"]["header"]["height"])
        timeout_height = {
            "revision_number": revision_number,
            "revision_height": latest_height + TIMEOUT_HEIGHT_DELTA
        }
        timeout_timestamp = str((int(time.time()) + 600) * 1_000_000_000)

        channel_key = f"{source_chain}_to_{dest_chain}"
        ibc_msg = {
            "@type": "/ibc.applications.transfer.v1.MsgTransfer",
            "source_port": "transfer",
            "source_channel": IBC_CHANNELS[channel_key],
            "token": {"denom": TOKENS[source_chain]["denom"], "amount": str(amount)},
            "sender": source_addr,
            "receiver": dest_addr,
            "timeout_height": timeout_height,
            "timeout_timestamp": timeout_timestamp
        }

        account_num, sequence = get_account_details(source_addr, source_chain)
        sequence = max(sequence, sequence_tracker.get(source_addr, sequence))
        send_telegram_message(f"🛠️ Preparing transfer {source_chain} -> {dest_chain} with sequence {sequence} (attempt {attempt+1}/{max_retries})")

        tx = Transaction(
            privkey=priv_key,
            account_num=account_num,
            sequence=sequence,
            fee=0,
            gas=0,
            chain_id=TOKENS[source_chain]["chain_id"]
        )
        tx.add_msg(json.dumps(ibc_msg))
        
        tx_json = tx.get_json()
        gas = estimate_gas(source_chain, tx_json)
        fee_amount = int(gas * 0.025)
        tx.fee = fee_amount
        tx.gas = gas

        signed_tx = tx.get_signed()
        broadcast_payload = {
            "tx_bytes": signed_tx["tx_bytes"],
            "mode": "BROADCAST_MODE_SYNC"
        }
        try:
            response = requests.post(f"{rest_url}/cosmos/tx/v1beta1/txs", json=broadcast_payload, timeout=10)
            if response.status_code == 200:
                tx_response = response.json()["tx_response"]
                tx_hash = tx_response["txhash"]
                send_telegram_message(f"✅ Transaction {tx_hash} broadcasted from {source_chain} -> {dest_chain}")
                success, status = monitor_transaction(source_chain, tx_hash)
                if success:
                    sequence_tracker[source_addr] = sequence + 1
                    return True, sequence_tracker
                elif "sequence" in status.lower():
                    send_telegram_message(f"🔄 Sequence mismatch detected for {tx_hash}. Retrying with updated sequence.")
                    continue
                else:
                    send_telegram_message(f"❌ Transfer failed: {status}")
                    return False, sequence_tracker
            else:
                error_msg = response.json().get("error", response.text)
                send_telegram_message(f"❌ Broadcast failed: {error_msg}. Retrying...")
                time.sleep(2 ** attempt)
        except requests.exceptions.RequestException as e:
            send_telegram_message(f"❌ Broadcast error {source_chain} -> {dest_chain}: {e}. Retrying...")
            time.sleep(2 ** attempt)
    send_telegram_message(f"❌ Transfer {source_chain} -> {dest_chain} failed after {max_retries} retries")
    return False, sequence_tracker

if __name__ == "__main__":
    print("⚠️ Note: IBC channels fetched dynamically. Check Telegram logs if transfers fail.")
    if wallet_choice == "1":
        STRIDE_ADDRESS = stride_addr
        UNION_ADDRESS = union_addr
    else:
        priv_key, STRIDE_ADDRESS, UNION_ADDRESS = derive_addresses(WALLET_INPUT)

    sequence_tracker = {}
    while True:
        union_balance = get_balance("union", UNION_ADDRESS)
        stride_balance = get_balance("stride", STRIDE_ADDRESS)
        balance_msg = f"💰 Balances:\n  Union: {union_balance} UNO\n  Stride: {stride_balance} STRD"
        send_telegram_message(balance_msg)
        print(balance_msg)

        try:
            num_transactions = int(input("Enter the number of transactions to perform: "))
        except ValueError:
            send_telegram_message("❌ Invalid number of transactions. Defaulting to 1.")
            num_transactions = 1

        last_failed_union_to_stride = False
        for i in range(num_transactions):
            if last_failed_union_to_stride:
                source_chain, dest_chain = "stride", "union"
                source_addr, dest_addr = STRIDE_ADDRESS, UNION_ADDRESS
                last_failed_union_to_stride = False
            else:
                direction = random.choice([("union", "stride"), ("stride", "union")])
                source_chain, dest_chain = direction
                source_addr = UNION_ADDRESS if source_chain == "union" else STRIDE_ADDRESS
                dest_addr = STRIDE_ADDRESS if dest_chain == "stride" else UNION_ADDRESS

            send_telegram_message(f"🔄 Attempting transfer {i+1}/{num_transactions}: {source_chain} -> {dest_chain}")
            success, sequence_tracker = perform_ibc_transfer(priv_key, source_chain, source_addr, dest_chain, dest_addr, sequence_tracker)
            
            if not success and source_chain == "union":
                union_balance = get_balance("union", UNION_ADDRESS)
                if union_balance < MIN_TRANSFER_AMOUNT:
                    last_failed_union_to_stride = True
                    send_telegram_message("🔄 Union -> Stride failed due to low balance. Next will be Stride -> Union.")
            delay = random.uniform(5, 10)
            print(f"⏳ Waiting {delay:.2f} seconds before next transfer...")
            time.sleep(delay)
        print("⏳ Waiting 30-60 seconds before next run...")
        time.sleep(random.uniform(30, 60))
EOF
