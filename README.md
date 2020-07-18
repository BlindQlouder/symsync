# Introduction

This repository contains the program symsync, written in Rust. It synchronizes folders on different machines over an untrusted server. The main point of this program is the use of symmetric encryption as opposed to public-private schemes used by PGP, owncloud, git, ....

Why using symmetric encryption? Just in case there will be quantum computers in the future. Current public-key encryption (like RSA, Diffie-Hellmann, Elliptic Curves) will be decryptable then. In that case, everybody who stores the traffic of today will likely read your files in the future. We are talking about the big players like google and the NSA.

The disadvantage of a symmetric scheme is that you cannot have a public key on some server that allows anybody (including you) to encrypt messages for you. A symmetric key must be preshared! For example, you can put it on a USB stick and copy it manually to all your computers. Note that this makes certain types of attacks more easy. If you are trying to protect your data from your wife or your boss, this might not be the right choice for you. However, it is perfectly fine against non-personalized attacks.

How? We just use aes_256_cbc from the openssl crate. That should be safe against all quantum computers.

Outline of the scheme: On every machine there are two folders, remote and local. The remote folder contains the encrypted and signed files that can be copied to the untrusted server. The names of the files are hashed and their sizes are masked by a random amount of bytes. All information about the files are stored in an encrypted image-file, such that we only update files that have changed. The local folder contains the unencrypted files on which you work normally. Ones you are done you run `symsync update`.

# Status of the code
I have been using this version for a while now. However, it is the first working version and there is little error handling. So no guarantee for your files. Please make a backup regularly. I am running it on Linux and have not attempted to run it on any other system.  Also, it is one of my first rust projects... 

# Installation

## Prerequisites

- You need two command-line functions, push and pull, to synchronize the encrypted folder with the server. For example you could synchronize to google drive using [this command-line client](https://github.com/odeke-em/drive). Other ways, for example using `rsync` on your own server, should also work but I have not tried it.  
- Rust is installed and this repo cloned into folder `repo`


## Folders

- folder `local` which contains the files you want to sync. 
- folder `remote` which will contain the encrypted files to be synced with the remote server.

## Making it run

~~~~bash
mkdir $local/.sync                                          # this is the folder containing the config file and the clear image file
cp $repo/default_config.toml $local/.sync/config.toml       # you will have to modify the contents of this file!
~~~~

follow instructions inside config.toml to specify your personal push/pull command and copy your key 

add `export MYSYNCPATH=path_to_folder_local` to your .bashrc or similar

~~~~bash
cd $repo
cargo run symsync 
~~~~

The executable is located in `$repo/target/debug/symsync`. You can copy it somewhere else. 

First you run `symsync blindpush` or `symsync blindpull`. Then `symsync update` to update changes you have made locally. 













