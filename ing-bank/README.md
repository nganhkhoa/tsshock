# Proof of Concept Attack Threshold ECDSA

## Requirements

- python3
- sagemath
- rust toolchain

sagemath libraries required:

```
sagemath --pip install ecdsa aiohttp
```

## How to run this PoC

The PoC requires two components to run: the exploiter server, and the signers.

To run the exploiter server, use sagemath and run the below command. This will open a server at `localhost:1337`.

```
sage verichains/exploiter.py
```

The quick script `run.sh` generates a set of new keys/parties and actively sign with random party set. The script stops when there is a successful key recovered. By default, we set a TSS of (t/n) = (2/4), requires 3 to sign. Reader can freely chose different values for parameters (t/n) and please do note that the time to run will be longer.

```
./run.sh
```

Verichains
