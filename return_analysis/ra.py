import json
import boto3
from os import environ as env

dynclient = boto3.client('dynamodb')
def lambda_handler(event, context):

    resp = dynclient.get_item(
            TableName=env['Table'],
            Key={
                'md5': {'S': event['pathParameters']['proxy']}
                }
        )
    
    return {
        "statusCode": 200,
        "body": json.dumps(resp['Item']),
    }
