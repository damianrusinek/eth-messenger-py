import requests, json, re
from requests.exceptions import RequestException

class ApiException(Exception):
    pass

class NoResultsException(ApiException):
    pass

class EtherScanAPI:

    def __init__(self, testnet=False):
        self.API_URL = 'https://api.etherscan.io/api' if not testnet \
              else 'https://ropsten.etherscan.io/api'
        self.BASE_URL = 'https://etherscan.io' if not testnet \
              else 'https://ropsten.etherscan.io'

    def get_address_first_transaction(self, address):
        try:
            r = requests.get(self.API_URL, params={'module': 'account', 'action': 'txlist', 
                                        'address': address,
                                        'startblock': '0', 'page': '1',
                                        'offset': 1, 'sort': 'asc'})
            result = json.loads(r.text)
            if result['status'] != '1' or len(result['result']) < 1:
                raise NoResultsException()
            return result['result'][0]
        except RequestException:
            raise ApiException()

    def get_address_out_transaction(self, address):
        try:
            r = requests.get(self.API_URL, params={'module': 'account', 'action': 'txlist', 
                                        'address': address,
                                        'startblock': '0', 'page': '1',
                                        'offset': 20, 'sort': 'asc'})
            result = json.loads(r.text)
            if result['status'] != '1' or len(result['result']) < 1:
                raise NoResultsException()
            for tx in result['result']:
                if tx['from'] == address:
                    return tx
            raise NoResultsException()
        except RequestException:
            raise ApiException()


    def get_raw_transaction(self, txhash):
        try:
            r = requests.get(self.BASE_URL + '/getRawTx', params={'tx': txhash})
            html = r.text
            if 'Returned Raw Transaction Hex : ' not in html:
                raise ApiException()
            r = re.compile('Returned Raw Transaction Hex : [^0]+([x0-9a-fA-F]+)')
            found = r.findall(html)
            if len(found) == 0:
                raise ApiException()
            return found[0]
        except RequestException:
            raise ApiException()