from optparse import OptionParser
from getpass import getpass
from address import PersonalAddress, ContractAddress
from api import EtherScanAPI, ApiException, NoResultsException
from web3 import Web3, IPCProvider
import ethereum as eth
import utils

INFO_URL = b'git.io/vxcyg'

def info_bytes():
    return b' (' + INFO_URL + b')'

class NotSyncedException(Exception):
    pass

if __name__ == "__main__":
    parser = OptionParser(usage="usage: %prog [options]")
    parser.add_option("-l", "--list", dest="list",
                action="store_true", default=False,
                help="list all accounts")
    parser.add_option("-e", "--encrypt", dest="encrypt",
                metavar="address",
                help="encrypt message to <address>")
    parser.add_option("-d", "--decrypt", dest="decrypt",
                metavar="tx_hash",
                help="decrypt message sent in <tx_hash>")
    parser.add_option("-m", "--message", dest="message",
                help="message to encrypt")
    parser.add_option("-s", "--send", dest="send",
                action="store_true", default=False,
                help="send encrypted data")
    parser.add_option("-f", "--from", dest="send_from",
                metavar="address|number", default="0",
                help="send encrypted message from address specified explicitly "
                     "or with its number (see accounts list) [default: %default]")
    parser.add_option("-p", "--sent-transaction", dest="sent_transaction",
                metavar="hash",
                help="hash of any transaction sent by address "
                "(use it when the the address is personal)")
    parser.add_option("-c", "--creation-transaction", 
                metavar="hash",
                dest="creation_transaction",
                help="hash of transaction that created contract "
                "(use it when the the address is contract)")
    parser.add_option("-t", "--testnet", dest="testnet",
                action="store_true", default=False,
                help="use ropsten network")
    parser.add_option("-i", "--ipcpath", dest="ipcpath",
                default=None, metavar="path",
                help="path to geth.ipc")
    
    vars(parser.get_default_values())
    (options, args) = parser.parse_args()

    # Network
    print("Network: {}".format('testnet' if options.testnet else 'mainnet'))

    # Web3
    ipcpath = options.ipcpath if options.ipcpath is not None \
                else utils.get_default_ipc_path(testnet=options.testnet) 
    print('Using local geth IPC at {}.'.format(ipcpath))
    web3 = Web3(IPCProvider(ipc_path=ipcpath))

    # List accounts
    if options.list:
        print('Personal accounts list:')
        try:
            personal_accounts = web3.personal.listAccounts
            if len(personal_accounts) == 0:
                print(' - No accounts found.')
            else:
                for i in range(len(personal_accounts)):
                    print(' {}. {}'.format(i, personal_accounts[i]))
        except FileNotFoundError:
            print("Error: Local Web3 node not found. Did you forget to start it?")
            exit(2)
        exit()
    
    # API
    api = EtherScanAPI(testnet=options.testnet)

    if not options.encrypt and not options.decrypt: 
        print("Error: Please select either encrypt mode (-e) or decrypt mode (-e).")
        exit(1)

    if options.encrypt and options.decrypt:
        print("Error: Please select either encrypt mode (-e) or decrypt mode (-e), not both.")
        exit(1)

    # Encrypt and send message
    if options.encrypt:
        
        if not utils.is_hex_address(options.encrypt):
            print("Error: The address is incorrect. It must start "
                  "with 0x followed with 40 hex digits.")
            exit(1)
            
        message = options.message
        if not message:
            print("Error: Please specify message to encrypt (-m).")
            exit(1)

        address_hex = utils.to_checksum_address(options.encrypt)
        address = None
        if not options.sent_transaction and not options.creation_transaction:
            print("API: you did not specify neither sent not creation transaction. "
                    "Need to find it by myself via API.")  
            print("API: looking for address.")
            try:
                tx = api.get_address_first_transaction(address_hex)
                print("API: found first transaction {}.".format(tx['hash']))
                if not tx['to']:
                    print("Address: contract.")
                    transaction = web3.eth.getTransaction(tx['hash'])
                    if transaction is None:
                        print("Error: Transaction not found in local Web3 node. Is it synced?")
                        exit(2)
                    creation_transaction = utils.web3tx_to_ethtx(transaction)
                    address = ContractAddress(address_hex,
                                    creation_transaction=creation_transaction)
                else:
                    print("API: not contract, looking for out transaction.")
                    tx = api.get_address_out_transaction(options.encrypt)
                    print("API: found out transaction {}.".format(tx['hash']))
                    print("Address: personal.")
                    transaction = web3.eth.getTransaction(tx['hash'])
                    if transaction is None:
                        print("Error: Transaction not found in local Web3 node. Is it synced?")
                        exit(2)
                    out_transaction = utils.web3tx_to_ethtx(transaction)
                    address = PersonalAddress(address_hex, 
                                    out_transaction=out_transaction)
            except NoResultsException:
                print("API: no transaction found.")
                print("Error: Please specify either sent trasaction (-p) or "
                      "creation transaction (-c) flag.")
                exit(2)
            except ApiException:
                print("API: an error occured.")
                print("Error: Please specify either sent trasaction (-p) or "
                      "creation transaction (-c) flag.")
                exit(2)
            except FileNotFoundError:
                print("Error: Local Web3 node not found. Did you forget to start it?")
                exit(2)
                
        elif options.sent_transaction and options.creation_transaction:
            print("Error: Please specify either sent trasaction (-p) or "
                  "creation transaction (-c) flag, not both.")
            exit(1)

        elif options.sent_transaction:
            
            if not utils.is_transaction_hash(options.sent_transaction):
                print("Error: The out transaction hash (-p) is incorrect. "
                      "It must start with 0x followed with 64 hex digits.")
                exit(1)

            try:
                transaction =  web3.eth.getTransaction(options.sent_transaction)
                if transaction is None:
                    print("Error: Transaction not found in local Web3 node. Is it synced?")
                    exit(2)
                transaction = utils.web3tx_to_ethtx(transaction)
                address = PersonalAddress(address_hex, 
                                            out_transaction=transaction)
                print("Address: personal.")
            except FileNotFoundError:
                print("Error: Local Web3 node not found. Did you forget to start it?")
                exit(2)
            except AssertionError:
                print("Error: Transaction {} is not an out transaction "
                      "from personal address.".format(options.sent_transaction))

        elif options.creation_transaction:
            
            if not utils.is_transaction_hash(options.creation_transaction):
                print("Error: The creation transaction hash (-c) is incorrect. "
                      "It must start with 0x followed with 64 hex digits.")
                exit(1)

            try:
                transaction = web3.eth.getTransaction(options.creation_transaction)
                if transaction is None:
                    print("Error: Transaction not found in local Web3 node. Is it synced?")
                    exit(2)
                transaction = utils.web3tx_to_ethtx(transaction)
                address = ContractAddress(address_hex, 
                                            creation_transaction=transaction)
                print("Address: contract.")
            except FileNotFoundError:
                print("Error: Local Web3 node not found. Did you forget to start it?")
                exit(2)
            except AssertionError:
                print("Error: Transaction {} is not a creation "
                      "transaction.".format(options.sent_transaction))
        else:
            print("Error: Please specify either sent trasaction (-p) or creation transaction (-c) flag.")
            exit(1)

        encrypted_message = address.encrypt(message)
        print("Encrypted message: {}".format(utils.add_0x_prefix(utils.encode_hex(encrypted_message))))
        owner = utils.decode_hex(utils.remove_0x_prefix(address.owner_address))
        assert len(owner) == 20
        message_data = owner + encrypted_message + info_bytes()
        print("Message to send: {}".format(utils.add_0x_prefix(utils.encode_hex(message_data))))
        
        if options.send:
            print("Sending transaction to: {}".format(address_hex))
            sender_account = options.send_from
            if not utils.is_hex_address(sender_account):
                try:
                    sender_account = web3.personal.listAccounts[int(sender_account)]
                except ValueError:
                    print("Error: Invalid sender account. Should be your local Ethereum account "
                          "or its index number. See --list flag.")
                    exit(1)
                except IndexError:
                    print("Error: Invalid account index. See --list flag.")
                    exit(1)
            print('Using account {}'.format(sender_account))

            if web3.eth.getBalance(sender_account) <= 0:
                print("Error: No Ether balance on {} account. "
                      "Use another account or if your local node is not synced, "
                      "send above encrypted data "
                      "using MetaMask or other wallet.".format(sender_account))
                exit(2)

            account_pass = getpass('Password to unlock: ')

            try:
                if not web3.personal.unlockAccount(sender_account, account_pass):
                    print("Error: Invalid account password.")
                    exit(1)

                transaction = {'to': utils.to_checksum_address(address_hex), 
                               'from': sender_account, 'data': message_data,
                               'value': 0}
                web3.eth.sendTransaction(transaction)
                web3.personal.lockAccount(sender_account)
            except ValueError as e:
                print("Error: {}.".format(e.args[0]['message']))
                exit(1)
        
    else: # decrypt message
        
        if not utils.is_transaction_hash(options.decrypt):
                print("Error: The transaction hash (-d) is incorrect. "
                      "It must start with 0x followed with 64 hex digits.")
                exit(1)

        transaction = None
        try:
            transaction = web3.eth.getTransaction(options.decrypt)
            if transaction is None:
                print("Error: Transaction not found in local Web3 node. Is it synced?")
                exit(2)
            transaction = utils.web3tx_to_ethtx(transaction)
        except FileNotFoundError:
            print("API: Local Web3 node not found. Will use API.")
            transaction = api.get_raw_transaction(options.decrypt)
            transaction = utils.rawtx_to_ethtx(transaction)

        tx_data = transaction.data
        if tx_data.endswith(info_bytes()):
            tx_data = tx_data[:-len(info_bytes())]
        else:
            print("Warning: This message might not be sent with this tool.")

        owner = tx_data[:20]
        encrypted_message = tx_data[20:]

        if len(owner) != 20:
            print("Error: This transaction is not the encrypted message.")
            exit(1)

        owner_address = utils.add_0x_prefix(utils.encode_hex(owner))
        account_priv = getpass('Private key for {} account: '.format(owner_address))
        
        try:
            privkey = int(utils.remove_0x_prefix(account_priv), 16)
        except ValueError:
            print("Error: Private key is invalid. It should be a hex string. "
                  "You can copy it from MetaMask for example.")
            exit(1)
        message = utils.decrypt(privkey, encrypted_message)
        print("Message: {}".format(message.decode('utf-8')))
        