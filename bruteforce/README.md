# Brute

In a stronk machine, you can run:

```
python3 crack.py --Pbit 32 --batch 16777216 --blocks 67108 --threads 256
```

The number registers used to brute is 255. Max registers per threads block is 64000. Which we can have 250.9 threads??? Anyway, a thread will run a batch of 16777216 (2^24) tries. So to make it efficient, we have 2^24 threads running (67108 * 256).
