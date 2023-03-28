cargo build --example keygen
cargo build --example sign

SIGN=target/debug/examples/sign
KEYGEN=target/debug/examples/keygen

t=2
n=4

rm -rf share*

echo "generating ($t/$n) parties"
$KEYGEN $t $n

while true
do
$SIGN $n $((t+1)) README.md
if python3 recover_check.py | grep -q 'recovered'; then
  break
fi
done

# call another time to print recovered privatekey
python3 recover_check.py
