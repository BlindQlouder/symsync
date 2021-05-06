#!/bin/bash

echo "creating some folders and files and copying default_config.toml"

pc="pc1"

mkdir -p $pc/remote
mkdir -p $pc/local/.sync

cp ../default_config.toml $pc/local/.sync/config.toml

sed -i 's/drive push/echo fake_push/g' $pc/local/.sync/config.toml
sed -i 's/drive pull/echo fake_pull/g' $pc/local/.sync/config.toml


echo hello > $pc/local/hello.txt

weird_path="$pc/local/f1/g1/h1/k1/"
mkdir -p $weird_path

echo "running dd to create a random file"

dd if=/dev/random of=$weird_path/some_bytes.bin count=1 bs=4M


echo "create pc2"

pc="pc2"

mkdir -p $pc/remote
mkdir -p $pc/local/.sync

cp ../default_config.toml $pc/local/.sync/config.toml

sed -i 's/drive push/echo fake_push/g' $pc/local/.sync/config.toml
sed -i 's/drive pull/echo fake_pull/g' $pc/local/.sync/config.toml








