Ethereum RD Messenger in Python (by @drdr_zz).
========================================

This tool is used to:
* send a secret message to the owner of a personal or contract Ethereum address, encypted with its owner ECC public key,
* decrypt the message sent to the personal address or contract's owner.

### Motivation

When doing research in the field of Ethereum Smart Contract security I came across a problem in finding the owner of the vulnerable contracts. This is particularly important for publicly available smart contracts, where time plays a crucial role.

When you, as an ethical hacker, want to report the vulnerability you can either:
* exploit it illegally and start looking for the owner (we don't want to do that), or
* start looking for the owner and hope that noone exploits the vulnerability (we don't want to do that either).

I want to use this tool for Responsible Disclosure. I firstly leave the encrypted, unmodifiable and undeniable message (in the end it's blockchain) where to find the stolen Ether and then exploit the vulnerability.

### Usage

```
python eth-messenger.py [options]
```

### Options

* `-h, --help` - print a help message.
* `-l, --list` - list all accounts.
* `-e <address>, --encrypt=<address>` - encrypt message send to the owner of <address>.
* `-d <tx_hash>, --decrypt=<tx_hash>` - decrypt message sent in <tx_hash>.
* `-m <message>, --message=<message>` - specify the message to encrypt.
* `-s, --send` - send encrypted data.
* `-f <address>|<index>, --from=<address>|<index>` - specify your address to send transaction explicitly or with its index (see accounts list) [default: 0].
* `-p <tx_hash>, --sent-transaction=<tx_hash>` - specify the hash of any out transaction sent by address (use it when the the <address> is personal).
* `-c <tx_hash>, --creation-transaction=<tx_hash>` - specify the hash of transaction that created contract (use it when the the <address> is contract)
* `-t, --testnet` -  use ropsten network.
* `-i <path>, --ipcpath=<path>` - specify the path to `geth.ipc` file.

### Example

```
python eth-messenger.py -t -e 0x3b752fd232ed1a110af83c4d955c044251be0d23 -m "TEST" -s -f 0
```

Using the above command, the messenger will:
* encrypt the message `TEST` with the public key of the owner of `0x3b752fd232ed1a110af83c4d955c044251be0d23` address,
* send the transaction with encypted message from the first local account.


```
python eth-messenger.py -t -d 0xc490405c22e65008ec79bd80a532ffdfa1bdaa44e23bda034fea5569358cb130
```

Using the above command, the messenger will:
* read the address of the message receiver and encrypted message from `0xc490405c22e65008ec79bd80a532ffdfa1bdaa44e23bda034fea5569358cb130` transaction data,
* ask for the private key of the receiver,
* decrypt the message with the private key of the owner,
* print decrypted message.

### License 

See the LICENSE file.