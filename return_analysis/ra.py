import json
import boto3
from os import environ

def lambda_handler(event, context):
    print(event)

    return {
        "statusCode": 200,
        "body": json.dumps(
            {"message": "success"}
        ),
    }
