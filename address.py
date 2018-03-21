import web3
import ethereum as eth 
import rlp, utils

class Address:

    def __init__(self, address, transaction):
        self.address = address
        self.transaction = transaction

    @property
    def owner_address(self):
        return utils.add_0x_prefix(eth.utils.sha3(
                    self.owner_public_key)[12:].hex())

    @property
    def owner_public_key(self):
        return self.transaction.pubkey

    def encrypt(self, message):
        return utils.encrypt(self.owner_public_key, eth.utils.str_to_bytes(message))

class PersonalAddress(Address):

    def __init__(self, address, out_transaction):
        Address.__init__(self, address, out_transaction)
        assert bool(self.transaction.to)
        assert utils.add_0x_prefix(self.transaction.sender.hex()) \
                == address.lower()
        assert self.owner_address == address.lower()

class ContractAddress(Address):

    def __init__(self, address, creation_transaction):
        Address.__init__(self, address, creation_transaction)
        assert not self.transaction.to
        assert utils.add_0x_prefix(eth.utils.mk_contract_address(
                self.transaction.sender,
                self.transaction.nonce).hex()) == address.lower()