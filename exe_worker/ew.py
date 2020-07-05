import json
import boto3
import pefile
import datetime
from os import environ,path

# import layers
import hashtool
import toolkit

# set default variables and boto3 clients
s3client    = boto3.client('s3')
sqsclient   = boto3.client('sqs')
sample_path = "/tmp/sample.bin" 

def lambda_handler(event, context):
    for record in event['Records']:
        # obtain the file from the s3 bucket
        s3client.download_file(environ['BucketName'], record['body'], sample_path)
        
        # get the analysis results
        result = analyze()

        # send results for storing in dynamodb
        print("exeworker results: {}".format(result))
        toolkit.store_results(result)

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
            #'imp_dll'   : {'':  imports},
            'filetype'  : {'S' : 'PE32 Executable'},
            'filesize'  : {'N' : str(path.getsize(sample_path))},
            'md5'       : {'S' : str(hashtool.get_md5(sample_path))},
            'sha1'      : {'S' : str(hashtool.get_sha1(sample_path))},
            'comp_time' : {'N' : str(compiletime.timestamp())}
            }

    return sample_info
    

