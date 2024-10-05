from Cryptodome.Hash import SHA256
from flask_login import current_user
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import *
from uuid import uuid4
import logging
import json
import os
import requests
import hashlib
from datetime import datetime
from urllib.parse import urlparse
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import sqlalchemy as sa
from app.models import User, db

node_identifier = str(uuid4()).replace('-', '')

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class Blockchain(object):
    logger.debug("Blockchain initialized.")
    def __init__(self):
        logger.debug("Initializing blockchain parameters.")
        self.pending_transactions = []
        self.difficulty = 2
        self.miner_rewards = 10
        self.block_size = 5
        self.nodes = set()
        self.chain = []
        self.smart_contracts = {}
        self.marketplace_listings = []
        self.fixed_supply = 1000
        self.circulating_supply = 0
        self.create_genesis_block()
        logger.info("Blockchain initialized.")

    def create_genesis_block(self):
        logger.debug("Creating genesis block.")
        genesis_block = Block([], datetime.now().strftime("%m/%d/%Y, %H:%M:%S"), 0)
        genesis_block.prev = "None"
        genesis_block.hash = genesis_block.calculate_hash()
        self.chain.append(genesis_block)
        logger.info("Genesis block created.")

    def get_balance(self, person):
        logger.debug(f"Calculating confirmed balance for {person}.")
        balance = 0
        # Traverse the blockchain to sum confirmed transactions
        for block in self.chain:
            logger.debug(f"Processing block {block.index}")
            for tx in block.transactions:
                if tx.sender == person:
                    logger.debug(f"Subtracting {tx.amt} from {person} balance (Sender)")
                    balance -= tx.amt
                elif tx.receiver == person:
                    logger.debug(f"Adding {tx.amt} to {person} balance (Receiver)")
                    balance += tx.amt
        logger.info(f"Confirmed balance for {person}: {balance}")
        return balance

    def available_balance(self, person):
        logger.debug(f"Calculating available balance for {person}.")
        balance = self.get_balance(person)
        # Only subtract amounts from pending transactions where the person is the sender
        for tx in self.pending_transactions:
            if tx.sender == person:
                balance -= tx.amt
        logger.info(f"Available balance for {person}: {balance}")
        return balance

    def create_contract(self, contract_id, contract_data, creator):
        logger.debug(f"Creating contract with ID {contract_id}.")
        if contract_id in self.smart_contracts:
            logger.error(f"Contract ID {contract_id} already exists.")
            return False

        try:
            # Parse the contract data safely
            parsed_data = json.loads(contract_data)
            logger.debug(f"Parsed contract data: {parsed_data}")

            # Create the contract and add it to smart_contracts
            contract = SmartContract(contract_id, parsed_data, creator)
            self.smart_contracts[contract_id] = contract
            logger.info(f"Smart contract created with ID: {contract_id}")

            # Do not execute the contract upon creation
            # Execution should be triggered explicitly and separately
            logger.debug(f"Contract {contract_id} added to smart_contracts. Awaiting execution.")

            return True

        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON format for contract data: {e}")
            return False

    def execute_contract(self, contract_id):
        logger.debug(f"Attempting to execute contract with ID {contract_id}.")
        if contract_id not in self.smart_contracts:
            logger.error(f"Contract ID {contract_id} not found.")
            return 'execution_failed'
        contract = self.smart_contracts[contract_id]

        # Capture the feedback from the contract execution
        result = contract.execute()

        if result == 'executed_condition_met':
            logger.info(f"Executed contract ID: {contract_id} with condition met.")
            return 'executed_condition_met'
        elif result == 'executed_condition_not_met':
            logger.warning(f"Executed contract ID: {contract_id} but condition not met.")
            return 'executed_condition_not_met'
        elif result == 'marketplace_listed':
            logger.info(f"Listed item for marketplace contract ID {contract_id}.")
            return 'marketplace_listed'
        elif result == 'already_executed':
            logger.info(f"Contract with ID {contract_id} was already executed.")
            return 'already_executed'
        else:
            # Log more details on why it failed
            logger.error(f"Failed to execute contract ID: {contract_id}. Result: {result}")
            return 'execution_failed'

    def evaluate_condition(self, condition, sender, receiver, contract_metadata=None):
        logger.debug(f"Evaluating condition for sender: {sender}, receiver: {receiver}. Condition: {condition}")

        # Log balances before evaluating the condition
        sender_balance = self.available_balance(sender)
        receiver_balance = self.available_balance(receiver)
        logger.debug(f"Sender balance: {sender_balance}, Receiver balance: {receiver_balance}")

        context = {
            "sender_balance": sender_balance,
            "receiver_balance": receiver_balance,
            "block_time": datetime.now().timestamp(),  # Example of block time
            **(contract_metadata or {})
        }
        try:
            result = ConditionParser.evaluate_condition(condition, context)
            logger.info(f"Condition evaluated to: {result}")
            return result
        except Exception as e:
            logger.error(f"Condition evaluation error: {e}. Condition: '{condition}'")
            return False

    def list_item_in_marketplace(self, contract_id, item_name, price):
        logger.debug(f"Listing item in marketplace. Contract ID: {contract_id}, Item: {item_name}, Price: {price}")
        listing = {
            'contract_id': contract_id,
            'item_name': item_name,
            'price': price,
            'status': 'available',
            'seller': self.smart_contracts[contract_id].creator
        }
        self.marketplace_listings.append(listing)
        logger.info(f"Item {item_name} listed for {price} coins in the marketplace.")

    def purchase_item(self, contract_id, buyer):
        logger.debug(f"Purchasing item from contract ID: {contract_id} by buyer: {buyer}")
        contract = self.get_contract(contract_id)
        if not contract:
            logger.error(f"Contract with ID {contract_id} not found.")
            return False

        contract_data = contract.contract_data
        if contract_data.get('type') != 'marketplace':
            logger.error("Invalid contract type for purchase.")
            return False

        item_name = contract_data['rules'][0]['item_name']
        price = int(contract_data['rules'][0]['price'])
        seller = contract.creator

        if contract_data.get('status') == 'sold':
            logger.error(f"Item {item_name} is already sold.")
            return False

        if self.available_balance(buyer) < price:
            logger.warning(f"Buyer {buyer} has insufficient balance to purchase {item_name}.")
            return False

        try:
            private_key_buyer = self.load_keys(buyer)[0]
            public_key_buyer = RSA.import_key(self.load_keys(buyer)[1])
        except Exception as e:
            logger.error(f"Error loading keys for {buyer}: {e}")
            return False

        transaction = Transaction(sender=buyer, receiver=seller, amt=price)
        if not transaction.sign_transaction(RSA.import_key(private_key_buyer), public_key_buyer):
            logger.error(f"Transaction signing failed for buyer {buyer}.")
            return False

        if transaction.is_valid_transaction():
            self.pending_transactions.append(transaction)
            logger.info(f"Transaction added: {buyer} purchased {item_name} for {price} coins from {seller}.")
        else:
            logger.error("Invalid transaction during item purchase.")
            return False

        contract_data['status'] = 'sold'
        self.save_purchased_item(buyer, item_name, price, seller)
        return True

    def save_purchased_item(self, buyer, item_name, price, seller):
        logger.debug(f"Saving purchased item. Buyer: {buyer}, Item: {item_name}, Price: {price}, Seller: {seller}")
        user_directory = os.path.join("users", buyer)
        os.makedirs(user_directory, exist_ok=True)

        file_path = os.path.join(user_directory, "purchased_items.txt")
        with open(file_path, 'a') as file:
            file.write(f"Item: {item_name}, Price: {price} coins, Seller: {seller}\n")
        logger.info(f"Saved purchased item '{item_name}' to {file_path}")

    def add_conditional_transaction(self, sender, receiver, amount, private_key_string, condition=None):
        logger.debug(f"Adding conditional transaction. Sender: {sender}, Receiver: {receiver}, Amount: {amount}, Condition: {condition}")
        if self.available_balance(sender) < amount:
            logger.error(f"Insufficient funds for transaction. Sender balance: {self.available_balance(sender)}, Amount: {amount}")
            return False

        if condition:
            try:
                if not self.evaluate_condition(condition, sender, receiver):
                    logger.warning(f"Condition not met for transaction from {sender} to {receiver}.")
                    return False
            except Exception as e:
                logger.error(f"Error evaluating condition: {e}")
                return False

        try:
            private_key = RSA.import_key(private_key_string)
            public_key = self.load_keys(sender)[1]
            sender_public_key = RSA.import_key(public_key)
        except Exception as e:
            logger.error(f"Key loading/signing error: {e}")
            return False

        transaction = Transaction(sender, receiver, amount)
        if not transaction.sign_transaction(private_key, sender_public_key):
            logger.error("Transaction signing failed.")
            return False

        if transaction.is_valid_transaction():
            self.pending_transactions.append(transaction)
            logger.info("Conditional transaction added.")
            return True
        else:
            logger.error("Transaction invalid after signing.")
            return False

    def add_transaction(self, sender, receiver, amt, private_key_string):
        logger.debug(f"Adding transaction. Sender: {sender}, Receiver: {receiver}, Amount: {amt}")

        # 1. Validate transaction amount
        if amt <= 0:
            logger.error("Transaction amount must be positive.")
            return False

        # 2. Check sender's available balance
        if self.available_balance(sender) < amt:
            logger.error(
                f"Insufficient funds for transaction. Sender balance: {self.available_balance(sender)}, Amount: {amt}")
            return False

        try:
            # 3. Import sender's private key for signing
            private_key = RSA.import_key(private_key_string)

            # 4. Retrieve sender's public key from database or storage
            public_key = self.load_keys(sender)[1]
            sender_public_key = RSA.import_key(public_key)

            # 5. Verify the key pair consistency
            if private_key.publickey().export_key() != sender_public_key.export_key():
                logger.error("The provided private key does not match the stored public key.")
                return False
            else:
                logger.debug("Private key matches the stored public key.")

        except Exception as e:
            logger.error(f"Key loading/signing error: {e}")
            return False

        # 6. Create transaction and sign it
        transaction = Transaction(sender, receiver, amt)

        # Sign the transaction before adding it to the mempool
        if not transaction.sign_transaction(private_key, sender_public_key):
            logger.error("Transaction signing failed.")
            return False

        # 7. Validate transaction's signature and content before adding to mempool
        if transaction.is_valid_transaction():
            # Check for double-spend possibility
            if any(tx.sender == sender and tx.amt == amt and tx.time == transaction.time for tx in
                   self.pending_transactions):
                logger.warning("Potential double-spend detected for this transaction.")
                return False

            # Add transaction to pending pool
            self.pending_transactions.append(transaction)
            logger.info("Transaction securely added to pending transactions.")
            return True
        else:
            logger.error("Transaction is invalid after signing.")
            return False

    def mine_pending_transactions(self, miner):
        logger.debug(f"Mining pending transactions. Miner: {miner}")

        # Check for remaining supply for miner rewards
        if self.get_remaining_supply() <= 0:
            logger.warning("No remaining supply for miner rewards.")
            return False

        # Validate transactions before adding them to a new block
        valid_transactions = [tx for tx in self.pending_transactions if tx.is_valid_transaction()]
        logger.info(f"Valid transactions: {len(valid_transactions)} out of {len(self.pending_transactions)}")

        # Create a new block with valid transactions
        new_block = Block(valid_transactions[:self.block_size], datetime.now().strftime("%m/%d/%Y, %H:%M:%S"),
                          len(self.chain))
        new_block.prev = self.get_last_block().hash
        new_block.mine_block(self.difficulty)
        self.chain.append(new_block)

        logger.info(f"Block mined: {new_block.index} with transactions: {[tx.hash for tx in new_block.transactions]}")

        # Calculate remaining supply and miner reward
        remaining_supply = self.get_remaining_supply()
        miner_reward = min(self.miner_rewards, remaining_supply)

        # Clear mined transactions from pending transactions
        self.pending_transactions = self.pending_transactions[self.block_size:]

        # Add reward transaction for miner
        if miner_reward > 0:
            reward_transaction = Transaction("System", miner, miner_reward)
            # Immediately add the reward to the pending transactions to be added to the next block
            self.pending_transactions.append(reward_transaction)
            self.circulating_supply += miner_reward
            logger.info(f"Miner rewarded with {miner_reward} coins.")

        logger.info("Mining completed. Block added to the chain.")
        return True


    def register_node(self, address):
        logger.debug(f"Registering node: {address}")
        parsed_url = urlparse(address)
        if not parsed_url.netloc:
            logger.error(f"Invalid node address: {address}")
            return False

        if parsed_url.netloc in self.nodes:
            logger.warning(f"Node {parsed_url.netloc} is already registered.")
            return False

        self.nodes.add(parsed_url.netloc)
        logger.info(f"Registered node: {parsed_url.netloc}")
        return True

    def resolve_conflicts(self):
        logger.debug("Resolving conflicts in blockchain nodes.")
        neighbors = self.nodes
        new_chain = None
        max_length = len(self.chain)

        for node in neighbors:
            try:
                response = requests.get(f'http://{node}/chain', timeout=5)
                if response.status_code == 200:
                    length = response.json()['length']
                    chain = response.json()['chain']
                    if length > max_length and self.is_valid_chain(chain):
                        max_length = length
                        new_chain = chain
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to connect to node {node}: {e}")

        if new_chain:
            self.chain = self.chainJSONdecode(new_chain)
            logger.info("Replaced chain with a longer valid chain.")
            return True

        logger.info("Current chain remains authoritative.")
        return False

    def chainJSONencode(self):
        logger.debug("Encoding blockchain to JSON format.")
        blockArrJSON = []
        for block in self.chain:
            blockJSON = {
                'hash': block.hash,
                'index': block.index,
                'prev': block.prev,
                'time': block.time,
                'nonse': block.nonse,
                'transactions': []
            }
            for transaction in block.transactions:
                tJSON = {
                    'time': transaction.time,
                    'sender': transaction.sender,
                    'receiver': transaction.receiver,
                    'amt': transaction.amt,
                    'hash': transaction.hash
                }
                blockJSON['transactions'].append(tJSON)
            blockArrJSON.append(blockJSON)
        logger.info("Blockchain encoded to JSON format.")
        return blockArrJSON

    def chainJSONdecode(self, chainJSON):
        logger.debug("Decoding JSON to blockchain format.")
        chain = []
        for blockJSON in chainJSON:
            tArr = []
            for tJSON in blockJSON['transactions']:
                transaction = Transaction(tJSON['sender'], tJSON['receiver'], tJSON['amt'])
                transaction.time = tJSON['time']
                transaction.hash = tJSON['hash']
                tArr.append(transaction)

            block = Block(tArr, blockJSON['time'], blockJSON['index'])
            block.hash = blockJSON['hash']
            block.prev = blockJSON['prev']
            block.nonse = blockJSON['nonse']
            chain.append(block)
        logger.info("Blockchain decoded from JSON format.")
        return chain

    def get_remaining_supply(self):
        remaining_supply = max(self.fixed_supply - self.circulating_supply, 0)
        logger.debug(f"Remaining supply: {remaining_supply}")
        return remaining_supply

    def get_last_block(self):
        logger.debug("Retrieving last block in the chain.")
        return self.chain[-1]

    def get_contract(self, contract_id):
        logger.debug(f"Retrieving contract with ID: {contract_id}")
        contract = self.smart_contracts.get(contract_id, None)
        if contract is None:
            logger.error(f"Contract ID {contract_id} not found in smart_contracts.")
        else:
            logger.info(f"Contract ID {contract_id} retrieved successfully.")
        return contract

    def is_valid_chain(self, chain):
        logger.debug("Validating the entire blockchain.")
        for i in range(1, len(chain)):
            b1 = chain[i - 1]
            b2 = chain[i]
            if not b2.has_valid_transactions():
                logger.warning("Invalid transaction found in chain.")
                return False
            if b2.hash != b2.calculate_hash():
                logger.warning("Hash mismatch found in chain.")
                return False
            if b2.prev != b1.hash:
                logger.warning("Previous hash mismatch found in chain.")
                return False
        logger.info("Blockchain is valid.")
        return True

    def load_keys(self, username):
        logger.debug(f"Loading keys for user: {username}")
        private_key_path = os.path.join("keys", username, "private_key.pem")
        public_key_path = os.path.join("keys", username, "public_key.pem")


        with open(private_key_path, 'rb') as private_file:
            private_key_string = private_file.read()

        with open(public_key_path, 'rb') as public_file:
            public_key_string = public_file.read()

        logger.info(f"Keys loaded for {username}")
        return private_key_string, public_key_string

    def generateKeys(self, username):
        # Generate RSA key pair
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        # Create user directory for keys
        keys_directory = "keys"
        user_key_dir = os.path.join(keys_directory, username)
        os.makedirs(user_key_dir, exist_ok=True)

        # Write keys to files
        with open(os.path.join(user_key_dir, "private_key.pem"), "wb") as file_out:
            file_out.write(private_key)
        with open(os.path.join(user_key_dir, "public_key.pem"), "wb") as file_out:
            file_out.write(public_key)

        return public_key.decode('ASCII')


class SmartContract:
    def __init__(self, contract_id, contract_data, creator):
        logger.debug(f"Initializing smart contract. ID: {contract_id}, Creator: {creator}")
        self.contract_id = contract_id
        self.contract_data = contract_data
        self.creator = creator
        self.is_executed = False  # Ensure it is not executed upon creation

    def execute(self):
        logger.debug(f"Executing smart contract. ID: {self.contract_id}")
        if self.is_executed:
            logger.warning(f"Contract {self.contract_id} is already executed.")
            return 'already_executed'

        rules = self.contract_data.get('rules', [])
        for rule in rules:
            action = rule.get('action')

            # Execute 'list_item' action for a marketplace contract
            if action == 'list_item' and self.contract_data.get('type') == 'marketplace':
                item_name = rule.get('item_name')
                price = int(rule.get('price'))
                blockchainObj.list_item_in_marketplace(self.contract_id, item_name, price)
                logger.info(f"Listed item {item_name} for price {price}.")
                self.is_executed = True
                return 'marketplace_listed'

            # Execute 'transfer' action for a conditional transaction
            elif action == 'transfer' and self.contract_data.get('type') == 'conditional_transaction':
                amount = int(rule.get('amount'))
                to_address = rule.get('to')
                condition = rule.get('condition')
                contract_metadata = self.contract_data.get('metadata', {})
                sender = self.creator

                # Check if the condition is met
                if blockchainObj.evaluate_condition(condition, sender, to_address, contract_metadata):
                    blockchainObj.add_conditional_transaction(sender, to_address, amount,
                                                                  blockchainObj.load_keys(sender)[0], condition)
                    logger.info(f"Executed conditional transfer of {amount} from {sender} to {to_address}.")
                    self.is_executed = True
                    return 'executed_condition_met'  # Updated to match `Blockchain.execute_contract`
                else:
                    logger.warning(f"Condition not met for conditional transfer.")
                    return 'executed_condition_not_met'  # Updated to match `Blockchain.execute_contract`
            else:
                logger.error(f"Unknown action type in rule: {action}")
                return 'unknown_action'

        self.is_executed = True
        logger.info(f"Executed contract with ID {self.contract_id}.")
        return 'executed'



class Block(object):
    def __init__(self, transactions, time, index):
        logger.debug(f"Initializing block. Index: {index}")
        self.index = index
        self.transactions = transactions
        self.time = time
        self.prev = ''
        self.nonse = 0
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        logger.debug("Calculating hash for block.")
        hashTransactions = "".join(transaction.hash for transaction in self.transactions)
        hashString = f"{self.time}{hashTransactions}{self.prev}{self.nonse}"
        hashEncoded = json.dumps(hashString, sort_keys=True).encode()
        return hashlib.sha256(hashEncoded).hexdigest()

    def mine_block(self, difficulty):
        logger.debug(f"Mining block. Difficulty: {difficulty}")
        hashPuzzle = '0' * difficulty
        while self.hash[:difficulty] != hashPuzzle:
            self.nonse += 1
            self.hash = self.calculate_hash()
        logger.info("Block mined with nonce: %d", self.nonse)
        return True

    def has_valid_transactions(self):
        logger.debug("Validating transactions in block.")
        for transaction in self.transactions:
            if not transaction.is_valid_transaction():
                logger.warning("Invalid transaction found in block.")
                return False
        return True


class Transaction(object):
    def __init__(self, sender, receiver, amt):
        logger.debug(f"Initializing transaction. Sender: {sender}, Receiver: {receiver}, Amount: {amt}")
        self.sender = sender
        self.receiver = receiver
        self.amt = amt
        self.signature = None
        self.time = datetime.now().strftime("%m/%d/%Y, %H:%M:%S")
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        logger.debug("Calculating hash for transaction.")
        hashString = f"{self.sender}{self.receiver}{self.amt}{self.time}"
        hashEncoded = json.dumps(hashString, sort_keys=True).encode()
        return hashlib.sha256(hashEncoded).hexdigest()

    def is_valid_transaction(self):
        logger.debug("Validating transaction.")

        # 1. Check that the transaction hash matches the recalculated hash
        if self.hash != self.calculate_hash():
            logger.warning("Transaction hash mismatch!")
            return False

        # 2. Ensure that the transaction is not from the same sender to the receiver
        if self.sender == self.receiver:
            logger.warning("Transaction sender and receiver are the same!")
            return False

        # 3. Check for the 'System' sender to allow miner rewards
        if self.sender == "System":
            return True

        # 4. Verify that the transaction has a valid signature
        if not self.signature or len(self.signature) == 0:
            logger.warning("Transaction has no signature!")
            return False

        # 5. Check if the receiver exists
        receiver_user = db.session.scalar(sa.select(User).where(User.username == self.receiver))
        if not receiver_user:
            logger.error(f"Receiver {self.receiver} does not exist.")
            return False

        # Signature verification
        transaction_hash = SHA256.new(self.hash.encode())
        try:
            # Retrieve sender's public key from the database or key storage
            user = db.session.scalar(sa.select(User).where(User.username == self.sender))
            stored_public_key = RSA.import_key(user.key)

            # Debug logs for the keys involved in verification
            logger.debug(f"Sender: {self.sender}")
            logger.debug(f"Public key from database: {user.key}")
            logger.debug(f"Transaction hash: {self.hash}")
            logger.debug(f"Signature: {self.signature.hex()}")

            # Verify the signature using the sender's public key
            pkcs1_15.new(stored_public_key).verify(transaction_hash, self.signature)
            logger.info("Transaction signature is valid.")
        except (ValueError, TypeError) as e:
            logger.error(f"Invalid transaction signature. Error: {e}")
            return False

        return True

    def sign_transaction(self, private_key, sender_public_key):
        logger.debug("Signing transaction.")

        # 1. Check if the hash is still valid before signing
        if self.hash != self.calculate_hash():
            logger.warning("Transaction tampered; signing failed.")
            return False

        # 2. Ensure the private key belongs to the sender by matching public keys
        if str(private_key.publickey().export_key()) != str(sender_public_key.export_key()):
            logger.warning("Transaction attempt to sign from another wallet.")
            return False

        # 3. Sign the transaction hash
        transaction_hash = SHA256.new(self.hash.encode())
        try:
            signature = pkcs1_15.new(private_key).sign(transaction_hash)
            self.signature = signature
            logger.info("Transaction signed successfully.")
            return True
        except ValueError as e:
            logger.error(f"Error signing transaction: {e}")
            return False

class ConditionParser:
    @staticmethod
    def evaluate_condition(condition, context):
        """
        Safely evaluate a contract condition string against the provided context.
        Supports basic arithmetic and comparison operations.
        """
        try:
            # Tokenize the condition and validate
            condition = ConditionParser.tokenize_condition(condition)

            # Replace context keys with actual values from the context dictionary
            for key, value in context.items():
                condition = condition.replace(key, str(value))

            # Safely evaluate the condition
            return eval(condition, {"__builtins__": None}, {})
        except Exception as e:
            logger.error(f"Condition evaluation error: {e}. Condition: '{condition}'")
            return False

    @staticmethod
    def tokenize_condition(condition):
        """
        Tokenizes and validates the condition string.
        Supports basic arithmetic and comparison operators.
        """
        allowed_characters = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_><=.!&|+-*/() ")
        if not all(char in allowed_characters for char in condition):
            raise ValueError("Invalid characters in condition")

        # Check that the condition is safe to evaluate
        return condition

blockchainObj = Blockchain()
