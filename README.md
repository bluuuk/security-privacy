<<<<<<< HEAD
# security-privacy

## Generate a Public/Private Key Pair
```
openssl genrsa -out private.pem 2048 
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```
=======
# Threat Model

- Passive Man in the Middle (MitM) Attacker
- Active Man in the Middle (MitM) Attacker

## Threats

- Reading confidential data
- Manipulating data
- Impersonating the other side

# Communication Scheme

All in all, we are tasked to recreate the _Transport Layer Security_ protocol that is used in everyday web-browing. Here are short overview over TLS 1.3:

![TLS 1.3 Handshake](https://www.wolfssl.com/wordpress/wp-content/uploads/2018/05/graphicB.png)

We can reduce the inital messages but keep the idea of the protocol:

![Our own protocol]()

# Removing integrity and authenticity

Totally stupid idea :(
>>>>>>> cc2e6a35e1338e4f28a3861df3e5c7080c27b7eb
