import json
import boto3
import datetime
from os                 import environ,path

# import layers
import hashtool
import toolkit

# set default variables and boto3 clients
s3client    = boto3.client('s3')
sqsclient   = boto3.client('sqs')
sample_path = "/tmp/sample.bin" 

def lambda_handler(event, context):
    for record in event['Records']:
        # remove the record from the queue
#        resp = sqsclient.delete_message(QueueUrl=environ['ExeQueueUrl'],
#                ReceiptHandle=record['receiptHandle'])

        # obtain the file from the s3 bucket
        s3client.download_file(environ['BucketName'], record['body'], sample_path)
        
        # get the analysis results
        result = analyze()

        # send results for storing in dynamodb
        print("otherworker results: {}".format(result))
        toolkit.store_results(result)

    return {
        "statusCode": 200,
        "body": json.dumps(
            {"message": "success"}
        ),
    }

def analyze():
    sample_info = {
            'filetype'  : {'S' : 'Other'},
            'filesize'  : {'N' : str(path.getsize(sample_path))},
            'md5'       : {'S' : str(hashtool.get_md5(sample_path))},
            'sha1'      : {'S' : str(hashtool.get_sha1(sample_path))}
            }

    return sample_info

def identify_sample(oid):
    indicators = oid.check()
    for i in indicators:
        if i.value == True:
            return {'id':i.id, 'id_name':i.name,'id_description':i.description}

def doc_has_macros(vba):
    if vba.detect_vba_macros():
        return True
    else:
        return False

def macro_extraction(vba):
    for (filename, stream_path, vba_filename, vba_code) in vba.extract_macros():
        macro_info = {
        'ole_stream'     : stream_path,
        'vba_filename'   : vba_filename,
        'vba_code'       : vba_code
        }

    return macro_info
