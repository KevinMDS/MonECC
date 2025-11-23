# TP Chiffrement ECC - Cryptographie

## Nom 
Kévin MESQUITA DOS SANTOS

## Nom GITHUB
KevinMDS / Texinho99 (les deux comptes sont à moi)

## Description
Le programme permet de :
- Générer une clé privée `k` et une clé publique `Q = kP`
- Chiffrer un message pour une clé publique
- Déchiffrer un message pour une clé privé

## Installation
Installer Python 3 et la dépendance `cryptography` :

```
pip install cryptography
```

## Utilisation

### Générer une paire de clés

```
python monECC.py keygen
```

### Chiffrer un message

```
python monECC.py crypt monECC.pub "Vive le portugal"
```

### Déchiffrer un message

```
python monECC.py decrypt monECC.priv "message_chiffré"
```

### Afficher l'aide

```
python monECC.py help
```