#!/bin/bash

DIRS_TO_DELETE=(
  ".nuxt"
  ".wrangler"
  ".output"
  ".data"
  "dist"
  "node_modules"
  "wasm/pkg"
  "wasm/target"
)

for dir in "${DIRS_TO_DELETE[@]}"
do
  rm -rf $dir && echo "Removed $dir directory."
done