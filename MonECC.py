#!/usr/bin/env python3
import sys, base64, hashlib, random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

P, A, Gx, Gy = 101, 35, 2, 9

def inv(n): 
    return pow(n % P, P - 2, P)

def add(x1, y1, x2, y2):
    if x1 == x2 and y1 == y2:
        if y1 == 0: return None, None
        s = (3 * x1 * x1 + A) * inv(2 * y1) % P
    else:
        if x1 == x2: return None, None
        s = (y2 - y1) * inv(x2 - x1) % P
    x3 = (s * s - x1 - x2) % P
    y3 = (s * (x1 - x3) - y1) % P
    return x3, y3

def mult(k, x, y):
    rx, ry, bx, by = None, None, x, y
    while k:
        if k & 1:
            if rx is None: 
                rx, ry = bx, by
            elif bx is not None: 
                rx, ry = add(rx, ry, bx, by)
        if bx is not None:
            bx, by = add(bx, by, bx, by)
        k >>= 1
    return rx, ry

def derive_secret(k, x, y):
    sx, sy = mult(k, x, y)
    h1 = hashlib.sha256(str(sx).encode()).digest()
    h2 = hashlib.sha256(str(sy).encode()).digest()
    secret = h1 + h2
    return secret[:16], secret[16:32]

def keygen():
    qx, qy = None, None
    while qx is None:
        k = random.randint(1, 1000)
        qx, qy = mult(k, Gx, Gy)
    open('monECC.priv', 'w', encoding='utf-8').write(f'---begin monECC private key---\n{base64.b64encode(str(k).encode()).decode()}\n---end monECC key---\n')
    open('monECC.pub', 'w', encoding='utf-8').write(f'---begin monECC public key---\n{base64.b64encode(f"{qx};{qy}".encode()).decode()}\n---end monECC key---\n')
    print('Clés générées: monECC.priv et monECC.pub')

def crypt(pubfile, text):
    lines = open(pubfile, encoding='utf-8').readlines()
    if len(lines) < 2 or '---begin monECC public key---' not in lines[0]: 
        sys.exit('Erreur: clé publique invalide')
    qx, qy = map(int, base64.b64decode(lines[1]).decode().split(';'))
    
    kGx, kGy = None, None
    while kGx is None:
        k = random.randint(1, 1000)
        kGx, kGy = mult(k, Gx, Gy)
    
    iv, key = derive_secret(k, qx, qy)
    
    padder = padding.PKCS7(128).padder()
    padded = padder.update(text.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    
    print(f'{kGx};{kGy}:{base64.b64encode(ct).decode()}')

def decrypt(privfile, ciphertext):
    lines = open(privfile, encoding='utf-8').readlines()
    if len(lines) < 2 or '---begin monECC private key---' not in lines[0]: 
        sys.exit('Erreur: clé privée invalide')
    k = int(base64.b64decode(lines[1]).decode())
    
    header, ct_b64 = ciphertext.split(':', 1)
    kGx, kGy = map(int, header.split(';'))
    ct = base64.b64decode(ct_b64)
    
    iv, key = derive_secret(k, kGx, kGy)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    print((unpadder.update(padded) + unpadder.finalize()).decode())

def help():
    print("""Script monECC

Syntaxe :
    python monECC.py <commande> [<clé>] [<texte>]

Commandes :
    keygen   : Génère une paire de clés
    crypt    : Chiffre <texte> avec la clé publique <clé>
    decrypt  : Déchiffre <texte> avec la clé privée <clé>
    help     : Affiche cette aide""")

if __name__ == '__main__':
    if len(sys.argv) < 2 or sys.argv[1] in ('help', '-h', '--help'):
        help()
    elif sys.argv[1] == 'keygen':
        keygen()
    elif sys.argv[1] == 'crypt' and len(sys.argv) == 4:
        crypt(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == 'decrypt' and len(sys.argv) == 4:
        decrypt(sys.argv[2], sys.argv[3])
    else:
        print('Erreur : paramètres invalides')
        help()