import json
import boto3
from os import environ
import subprocess as sub

s3client    = boto3.client('s3')
sqsclient   = boto3.client('sqs')
sample_path = "/tmp/sample.bin" 

def lambda_handler(event, context):

    # get the file to the container
    s3path = event['Records'][0]['s3']['object']['key']
    s3client.download_file(environ['BucketName'], s3path, sample_path)

    # determine the filetype and based on that submit to the right queue
    filetype = file_id()
    if "PE32 executable" in filetype:
        print("distributor: submitting sample to exe_worker")
        response = sqsclient.send_message(
                QueueUrl=environ['ExecutableQ'],
                MessageBody=(s3path)
                )

    return {
        "statusCode": 200,
        "body": json.dumps(
            {"message": "success"}
        ),
    }

def file_id():
    p = sub.Popen(['file',sample_path],stdout=sub.PIPE,stderr=sub.PIPE)
    output, errors = p.communicate()

    return str(output,'utf-8').strip()
