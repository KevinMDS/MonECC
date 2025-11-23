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