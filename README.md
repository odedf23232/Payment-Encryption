# PaymentEncryption
Payment encryption

## Requirements

- `python 3.6+`

## How to run

Run server with:
```shell
python server_main.py
```

Run client with:
```shell
python client_main.py
```

Generate schnorr keys:
```shell
python keys.py --schnorr
```

Generate schnorr keys:
```shell
python keys.py --blowfish
```

## TO DO

- demonstrate:
  - sniff communication to see it encrypted
    - open client and server
    - open sniffer (wireshark)
    - communicate and see the data transmissions
    - notice they are encrypted
  - try connecting with wrong keys and see it fail
    - run client with different keys from server
    - try to connect
    - see it fail
  - try to modify transmitted data and see it fail
    - generate encrypted message
    - modify it
    - try to decrypt and verify the data and see it fail
  
## Resources

- Schnorr signature
    - https://github.com/HarryR/solcrypto/blob/master/pysolcrypto/schnorr.py
    - https://github.com/vihu/schnorr-python/blob/master/naive.py
    - https://crypto.stackexchange.com/questions/58292/schnorr-signature-using-discrete-logarithm-problem-with-python-implementation
    - https://www.geeksforgeeks.org/schnorr-digital-signature/
    - https://www.deadalnix.me/2017/02/14/schnorr-signatures-for-dummies/
    - https://medium.com/bitbees/what-the-heck-is-schnorr-52ef5dba289f
    - https://www.youtube.com/watch?v=mV9hXEFUB6A
- Blowfish
  - https://gist.github.com/eigenein/a56ce4d572484a582e14
  - https://github.com/weswigham/blowfish/tree/master/src
  - https://www.geeksforgeeks.org/blowfish-algorithm-with-examples/
  