import json
import boto3
import pefile
import datetime
from os import environ,path

# import layer
import hashtool

# set default variables and boto3 clients
s3client    = boto3.client('s3')
sqsclient   = boto3.client('sqs')
sample_path = "/tmp/sample.bin" 

def lambda_handler(event, context):
    for record in event['Records']:
        s3client.download_file(environ['BucketName'], record['body'], sample_path)
        result = analyze()
        print("exeworker results: {}".format(result))
        resp = sqsclient.delete_message(QueueUrl=environ['ExeQueueUrl'],
                ReceiptHandle=record['receiptHandle'])

    return {
        "statusCode": 200,
        "body": json.dumps(
            {"message": "success"}
        ),
    }

def analyze():
    pe =  pefile.PE(sample_path, fast_load=True)
    pe.full_load()
    #imports     = [ entry.dll for entry in pe.DIRECTORY_ENTRY_IMPORT ]
    compiletime = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp)

    sample_info = {
            'filetype'  : 'PE32 Executable',
            'filesize'  : path.getsize(sample_path),
            'md5'       : hashtool.get_md5(sample_path),
            'sha1'      : hashtool.get_sha1(sample_path),
            #'imp_dll'   : imports,
            'comp_time' : compiletime.strftime("%Y-%m-%d %H:%M:%S")    
            }

    return sample_info
    

