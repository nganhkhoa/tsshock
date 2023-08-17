#!/bin/sh

# /gaiad init --chain-id localgaia local
# /gaiad add-genesis-account cosmos1cyyzpxplxdzkeea7kwsydadg87357qnalx9dqz 100000000uatom  # smoke contrib
# /gaiad add-genesis-account cosmos1phaxpevm5wecex2jyaqty2a4v02qj7qmhq3xz0 100000000uatom  # smoke master

mkdir -p /root/.gaia/data
cat >/root/.gaia/data/priv_validator_state.json <<EOF
{
  "height": "0",
  "round": 0,
  "step": 0
}
EOF

exec /entrypoint.sh
