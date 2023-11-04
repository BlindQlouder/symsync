# Introduction

This repository contains the program symsync. It synchronizes folders on different machines over an untrusted server. For example two computers at work and at home being synchronized over google drive. 

The encryption is symmetric, using aes_256_cbc from the openssl crate. The key needs to be copied manually onto every computer that you want to sync. 

Why use a preshared key instead of a public-key-based key exchange? First: it's easier. Second: it is safe against the unlikely event that powerful quantum computers become available in the future. The public-key-exchange schemes like RSA, Diffie-Hellmann or elliptic curves will all become breakable in this scenario. Then, the big guys like google and the NSA will be able to read all the files you send over the internet today. Isn't this reason enough to justify the unconvenience of manually putting a key onto a USB stick and carrying it to all your computers? Of course it is. 

So, here is the outline of the scheme: On every machine there are two folders, remote and local. The remote folder contains the encrypted and signed files that can be copied to the untrusted server. The names of the files are hashed and their sizes are masked by a random amount of bytes. All information about the files are stored in an encrypted image-file, such that we only update files that have changed. The local folder contains the unencrypted files on which you work normally. Once you are done you run `symsync update`.

# Status of the code

I have been using this version for a few years now. However, there is little error handling. So no guarantee for your files. Please make a backup regularly. I am running it on Linux and have not attempted to run it on any other system. Also, it is one of my first rust projects... 

# Installation

## Prerequisites

- You need two command-line functions, push and pull, to synchronize the encrypted folder with the server. For example you could synchronize to google drive using [this command-line client](https://github.com/odeke-em/drive)(outdate: auth with google did not work for me any more) or rclone. Or `rsync` on your own server.   
- Rust is installed and this repo cloned


## Folders

- folder `local` which contains the files you want to sync. 
- folder `remote` which will contain the encrypted files to be synced with the remote server.

## Making it run

create folder and copy the config:

~~~~bash
mkdir $local/.sync                                          # this is the folder containing the config file and the clear image file
cp $repo/default_config.toml $local/.sync/config.toml       # you will have to modify the contents of this file!
~~~~

follow instructions inside config.toml to specify your personal push/pull command and copy your key 

add `export MYSYNCPATH=path_to_folder_local` to your .bashrc or similar

compile: 

~~~~bash
cd $repo
cargo build --release 
~~~~

The executable is `target/release/symsync`. You can copy it somewhere else. 

First you run `symsync blindpush` or `symsync blindpull`. Then `symsync update` to update changes you have made locally. 













