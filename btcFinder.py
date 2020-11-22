import os
import sys
import requests
import hashlib
from hashlib import sha256
from ecdsa import SigningKey, SECP256k1


class address:
    P = 2 ** 256 - 2 ** 32 - 2 ** 9 - 2 ** 8 - 2 ** 7 - 2 ** 6 - 2 ** 4 - 1
    G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
         0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
    B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    def ripemd160(x):
        d = hashlib.new("ripemd160")
        d.update(x)
        return d

    def point_add(p, q):
        xp, yp = p
        xq, yq = q

        if p == q:
            l = pow(2 * yp % address.P, address.P - 2, address.P) * (3 * xp * xp) % address.P
        else:
            l = pow(xq - xp, address.P - 2, address.P) * (yq - yp) % address.P

        xr = (l ** 2 - xp - xq) % address.P
        yr = (l * xp - l * xr - yp) % address.P

        return xr, yr

    def point_mul(p, d):
        n = p
        q = None

        for i in range(256):
            if d & (1 << i):
                if q is None:
                    q = n
                else:
                    q = address.point_add(q, n)

            n = address.point_add(n, n)

        return q

    def point_bytes(p):
        x, y = p

        return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")

    def b58_encode(d):
        out = ""
        p = 0
        x = 0

        while d[0] == 0:
            out += "1"
            d = d[1:]

        for i, v in enumerate(d[::-1]):
            x += v * (256 ** i)

        while x > 58 ** (p + 1):
            p += 1

        while p >= 0:
            a, x = divmod(x, 58 ** p)
            out += address.B58[a]
            p -= 1

        return out

    def make_address(privkey):
        q = address.point_mul(address.G, int.from_bytes(privkey, "big"))
        hash160 = address.ripemd160(sha256(address.point_bytes(q)).digest()).digest()
        addr = b"\x00" + hash160
        checksum = sha256(sha256(addr).digest()).digest()[:4]
        addr += checksum

        wif = b"\x80" + privkey
        checksum = sha256(sha256(wif).digest()).digest()[:4]
        wif += checksum
        addr = address.b58_encode(addr)
        wif = address.b58_encode(wif)

        return addr, wif


class save:
    def toFile(text):
        file = open("result.txt", "a+")
        file.write(text)
        file.close()


class check:
    def balance(address):
        try:
            request = requests.get("https://chain.api.btc.com/v3/address/" + address)
            response = request.json()
            balance = response['data']['balance']
            return balance
        except:
            return "Failed to establish a new connection"


print("=========================START BRUTE=========================")

i = 0
balance = float(0)

while True:

    i += 1
    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()
    addr, wif = address.make_address(sk.to_string())

    try:
        balance = float(check.balance(addr))
    except:
        print("Failed to establish a new connection")

    res = "Count: %s | Address: %s | privateKey: %s | Balance: %s \n" % (i, addr, wif, balance)
    if balance > 0:
        save.toFile(res)

    print(res)
