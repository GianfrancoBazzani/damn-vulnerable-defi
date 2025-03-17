import base64
from eth_account import Account

data_1 = "4d 48 67 33 5a 44 45 31 59 6d 4a 68 4d 6a 5a 6a 4e 54 49 7a 4e 6a 67 7a 59 6d 5a 6a 4d 32 52 6a 4e 32 4e 6b 59 7a 56 6b 4d 57 49 34 59 54 49 33 4e 44 51 30 4e 44 63 31 4f 54 64 6a 5a 6a 52 6b 59 54 45 33 4d 44 56 6a 5a 6a 5a 6a 4f 54 6b 7a 4d 44 59 7a 4e 7a 51 30"
data_2 = "4d 48 67 32 4f 47 4a 6b 4d 44 49 77 59 57 51 78 4f 44 5a 69 4e 6a 51 33 59 54 59 35 4d 57 4d 32 59 54 56 6a 4d 47 4d 78 4e 54 49 35 5a 6a 49 78 5a 57 4e 6b 4d 44 6c 6b 59 32 4d 30 4e 54 49 30 4d 54 51 77 4d 6d 46 6a 4e 6a 42 69 59 54 4d 33 4e 32 4d 30 4d 54 55 35"


def decode(data):
    decoded_data = data.replace(" ", "")
    decoded_data = bytes.fromhex(decoded_data)
    decoded_data = base64.b64decode(decoded_data) 
    return decoded_data.decode('utf-8')

pk_1 = decode(data_1)
print("Private Key 1: " + f"{pk_1}" )
account = Account.from_key(bytes.fromhex(pk_1[2:]))
print("Private Key 1 as uint: " + f"{int(pk_1, 16)}" )
print("Address 1: " + f"{account.address}" )

pk_2 = decode(data_2)
print("Private Key 2: " + f"{pk_2}" )
account = Account.from_key(bytes.fromhex(pk_2[2:]))
print("Private Key 2 as uint: " + f"{int(pk_2, 16)}" )
print("Address 2: " + f"{account.address}" )