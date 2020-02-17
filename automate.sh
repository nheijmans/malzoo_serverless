#!/bin/sh
######
# Script to automatically build malzoo-serverless
######

STACKNAME=$1
DEPLOYBUCKET=$2
BUCKETNAME=$3

sam build -u --skip-pull-image
sam package --s3-bucket $DEPLOYBUCKET --output-template-file packaged.yaml
sam deploy --template-file packaged.yaml --stack-name $STACKNAME --parameter-overrides SamplesBucket=$BUCKETNAME --capabilities CAPABILITY_IAM
