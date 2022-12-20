import os
import subprocess as sp
from time import sleep

try:
    sp.check_call("killall -9 gg20_sm_manager", shell=True)
except:
    pass
sp.check_call(["touch share.json && rm share*"], shell=True)
p0 = sp.Popen(["cargo run --example gg20_sm_manager"], shell=True)
sleep(5)

p1 = sp.Popen(["cargo run --example gg20_keygen -- -t 1 -n 3 -i 1 --output share1.json"], shell=True)
sleep(1)
p2 = sp.Popen(["cargo run --example gg20_keygen -- -t 1 -n 3 -i 2 --output share2.json"], shell=True)
sleep(1)
p3 = sp.Popen(["cargo run --example gg20_keygen -- -t 1 -n 3 -i 3 --output share3.json"], shell=True)
sleep(1)

p1.wait()
p2.wait()
p3.wait()

try:
    sp.check_call("killall -9 gg20_sm_manager", shell=True)
except:
    pass
p0 = sp.Popen(["cargo run --example gg20_sm_manager"], shell=True)
sleep(5)

p1 = sp.Popen(["cargo run --example gg20_signing -- -p 1,3 -d \"hello\" -l share1.json"], shell=True)
sleep(1)
p2 = sp.Popen(["cargo run --example gg20_signing -- -p 1,3 -d \"hello\" -l share3.json"], shell=True)
sleep(1)

p1.wait()
p2.wait()
exit(0)
