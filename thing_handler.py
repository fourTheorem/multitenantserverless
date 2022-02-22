import json
import os
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
from aws_lambda_powertools import Logger, Tracer
from tenant_session import session_for_event

logger = Logger(service="things")
tracer = Tracer()

all_orgs = ['acme', 'tinycorp', 'bigcorp']
table_name = os.environ['TABLE_NAME']

@logger.inject_lambda_context
@tracer.capture_lambda_handler
def handle(event, context):
    logger.info(event)
    session, org, caller_identity = session_for_event(event)
    table = session.resource('dynamodb').Table(table_name)
    
    table_results = {}
    for org in all_orgs:
        try:
            query_response = table.query(KeyConditionExpression=Key('PK').eq(f'{org}#things'))
            table_results[org] = query_response['Items']
        except ClientError as e:
            logger.error(e)
            table_results[org] = str(e)
    logger.info({'table_results': table_results})

    body = {
        "message": "hello",
        "input": event,
        "table_results": table_results,
        "caller_identity": caller_identity
    }
    
    response = {
        "statusCode": 200,
        "body": json.dumps(body),
        "headers": {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": True,
        },
    }

    return response
