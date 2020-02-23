""" 
Toolkit layer for general purpose functions used across the application 
Currently used for:
    - Storing analysis results in DynamoDB

"""
import json
import boto3

from os import environ as env

ddbclient = boto3.client('dynamodb')

def store_results(data):
    ddbclient.put_item(
                TableName=env['Table'],
                Item=data
            )

    return
