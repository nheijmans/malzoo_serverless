import boto3
import yara
import os
from os import environ as env
from hashlib import md5 as md5sum

# set default variables and boto3 clients
s3client    = boto3.client('s3')
sqsclient   = boto3.client('sqs')
sample_path = "/tmp/sample.bin" 

def handler(event, context):

    for record in event['Records']:
        # obtain the file from the s3 bucket
        s3client.download_file(env['BucketName'], record['body'], sample_path)

    result = match()
    store_results(result)

    return "done!"

def match():
    rulefiles = os.listdir('/function/')
    
    i = 1
    rules_dict = {}
    for rule in rulefiles:
        if rule.endswith(".yara") or rule.endswith(".yar"):
            rules_dict['namespace'+str(i)] = "/function/{}".format(rule)
            i += 1
    
    rules = yara.compile(filepaths=rules_dict)
    matches = rules.match(sample_path)
    print(type(matches[0]))
    print(matches[0])
    list_matches = [str(m) for m in matches]
    print(list_matches)

    sample_info = {
            'yara'      : {'SS' : list_matches},
            'md5'       : {'S' : str(get_md5(sample_path))},
            }
    
    return sample_info 


def store_results(data):
    dynamoclient = boto3.resource('dynamodb', region_name=env['Region'])
    sampletable  = dynamoclient.Table(env['Table'])
    sampletable.update_item(
        Key={'md5':data['md5']['S']},
        UpdateExpression='SET yara_matches = :val1',
        ExpressionAttributeValues={':val1': data['yara']['SS']
            }
        )

    return

def get_md5(sample):
    """ Generate MD5 of the sample """
    with open(sample, 'rb') as f:
        md5_hash = md5sum(f.read()).hexdigest()

    return md5_hash