#!/usr/bin/env bash

set -e

BUILD_DIR=./build
ENTRYPOINTS=$1
if [[ ! $ENTRYPOINTS ]]; then
  echo "no typescript file provided"
  exit 1
fi

mkdir -p $BUILD_DIR
rm -rf $BUILD_DIR/*

esbuild $ENTRYPOINTS \
  --log-level=warning \
  --outdir='./build' \
  --outbase=. \
  --sourcemap \
  --target='node16' \
  --platform='node' \
  --format='cjs'

node --enable-source-maps $BUILD_DIR/index.js
