#!/bin/sh
######
# Script to automatically build malzoo-serverless
######

# build the package dependancies
sam build -u --skip-pull-image

# check if samconfig.toml file is present
if [ ! -f samconfig.toml ]; then
    echo "no samconfig.toml found, starting guided deploy"
    sam deploy -g
else
    echo "samconfig.toml found, proceeding to deploy"
    sam deploy
fi
