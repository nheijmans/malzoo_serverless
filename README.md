# Malzoo Serverless
## Overview
Serverless implementation of the [Malzoo static file analyzer project](https://github.com/nheijmans/malzoo/)

The goal is to have a deployment-ready application template for mass static file analysis that everyone can use.
The architecture is kept simple and similar to the original Malzoo project, with a distributor and workers dedicated to a certain filetype.

![Malzoo Architecture](https://threat-hunting.ninja/images/malzoo_serverless_architecture_v2.png)

## Getting started
**Prerequisites**
- AWS SAM installed
- AWS CLI configured
- Role in AWS can create IAM roles
- ECR repository created
- Docker installed

## Preparation and deployment
1 First create a ECR repository in AWS in case you don't have that
```
aws ecr create-repository --repository-name malzoo \
--image-tag-mutability IMMUTABLE --image-scanning-configuration scanOnPush=true
```

2 To deploy the serverless stack in your own AWS account, clone this repository and enter the folder. In the repository folder, build Malzoo Serverless locally with SAM
```
sam build --use-container --skip-pull-image --parallel
```

3 Deploy the stack, use ```--guided``` on the first time. 
```
sam deploy --guided
```

## Using Malzoo Serverless
Now we have Malzoo deployed, lets submit a sample to it. You will need to know the AWS account number (ARN), because this is used in the S3 bucketname. 
**To submit a sample for analysis**, simply copy or move the binary to the buckets root. Check the buckets name or copy the command below and replace ```YOURAWSACCOUNTARN``` with your ARN.
```
aws s3 cp binary.exe s3://malzoo-serverless-v1-YOURAWSACCOUNTARN-malware
```

**To submit a sample for analysis with tag**, copy or move the binary to the bucket with a subfolder (the subfolder becomes the label/tag in the DB)
```
aws s3 cp binary.exe s3://malzoo-serverless-v1-YOURAWSACCOUNTARN-malware/case-123/
```

**To submit a folder of samples**, use the following example command
```
cd malware_folder/

# Submission without tag
aws s3 cp --recursive * s3://malzoo-serverless-v1-YOURAWSACCOUNTARN-malware/

# Submission with tag
aws s3 cp --recursive * s3://malzoo-serverless-v1-YOURAWSACCOUNTARN-malware/case-234/
```

Submissions can also be done obviously via other ways, as long as you copy the binary to analyze, to the S3 bucket. 

**Getting analysis results** is easy with the deployed API gateway, which you can find via the AWS console, or via the output when the stack is deployed with AWS SAM. With curl, getting a result is easy. Replace ```APIGWID```, ```REGION```, ```MD5HASH``` with the values that correlate with your environment and the sample you want to get the data from.
```
curl -X GET https://APIGWID.execute-api.REGION.amazonaws.com/analysis/results/MD5HASH 
```

### Credits
Thanks at @marekq for working together on the SAM deployment template!

### Contribute
If you have a cool feature build for one of the workers or a new worker, feel free to submit a PR! Please include a good description on what is been added and how it benefits the platform :) 
