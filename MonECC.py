#!/usr/bin/env python3
import sys, base64, hashlib, random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

P, A, Gx, Gy = 101, 35, 2, 9