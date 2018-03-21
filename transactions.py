
import ethereum as eth 
import ethereum.transactions
import rlp 

class Transaction(ethereum.transactions.Transaction):

    @property
    def pubkey(self):
        if self.r == 0 and self.s == 0:
            raise eth.transactions.InvalidTransaction(
                "No signature!")
        if self.v in (27, 28):
            vee = self.v
            sighash = eth.utils.sha3(rlp.encode(self, 
                            eth.transactions.UnsignedTransaction))
        elif self.v >= 37:
            vee = self.v - self.network_id * 2 - 8
            assert vee in (27, 28)
            rlpdata = rlp.encode(rlp.infer_sedes(self).serialize(self)[
                                    :-3] + [self.network_id, '', ''])
            sighash = eth.utils.sha3(rlpdata)
        else:
            raise eth.transactions.InvalidTransaction("Invalid V value")
        if self.r >= eth.transactions.secpk1n or \
            self.s >= eth.transactions.secpk1n or \
            self.r == 0 or self.s == 0:
            raise eth.transactions.InvalidTransaction("Invalid signature values!")
        pub = eth.utils.ecrecover_to_pub(sighash, vee, self.r, self.s)
        if pub == b'\x00' * 64:
            raise eth.transactions.InvalidTransaction(
                "Invalid signature (zero privkey cannot sign)")
        return pub