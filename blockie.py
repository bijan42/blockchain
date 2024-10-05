import hashlib
import json
from datetime import datetime


class Blockie:

    # This function is created
    # to create the very first
    # block and set its hash to "0"
    def __init__(self):
        with open('chain_data.json', 'r') as file:
            self.chain = json.load(file)
        #self.chain = []
        #self.create_block(proof=1, previous_hash='Genesis')
        #with open('chain_data.json', 'w') as file:
            #json.dump(self.chain, file, indent=4)

        # This function is created
    # to add further blocks
    # into the chain
    def create_block(self, proof, previous_hash):
        block = ({'message': 'yo',
                  'index': len(self.chain) + 1,
                  'timestamp': str(datetime.now()),
                  'proof': proof,
                  'previous_hash': previous_hash

                  }
                )

        self.chain.append(block)
        with open('chain_data.json', 'w') as file:
            json.dump(self.chain, file, indent=4)
        return block

    # This function is created
    # to display the previous block
    def get_previous_block(self):
        return self.chain[-1]

    # This is the function for proof of work
    # and used to successfully mine the block
    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False

        while check_proof is False:
            hash_operation = hashlib.sha256(
                str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:2] == '00':
                check_proof = True
            else:
                new_proof += 1

        return new_proof

    def hash(self, block):
        encoded_block = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def chain_valid(self, chain):
        previous_block = chain[0]
        block_index = 1

        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False

            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(
                str(proof**2 - previous_proof**2).encode()).hexdigest()

            if hash_operation[:2] != '00':
                return False
            previous_block = block
            block_index += 1

        return True

blockie = Blockie()