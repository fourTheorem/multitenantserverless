import json
from nis import match
import os
import boto3
from botocore.exceptions import ClientError
from boto3.dynamodb.conditions import Key
from aws_lambda_powertools import Logger, Tracer
from aws_lambda_powertools.logging import correlation_paths

from tenant_session import session_for_event

logger = Logger(service='user-group')
tracer = Tracer()

all_orgs = ['acme', 'tinycorp', 'bigcorp']
table_name = os.environ['TABLE_NAME']
user_pool_id = os.environ['USER_POOL_ID']

@logger.inject_lambda_context(correlation_id_path=correlation_paths.API_GATEWAY_REST)
@tracer.capture_lambda_handler
def handle_put(event, context):
    logger.info(event)
    session, session_org, caller_identity = session_for_event(event)
    idp_client = session.client('cognito-idp')

    body = json.loads(event['body'])
    email = body.get('email', '')
    org = body.get('org', '')
    ou = body.get('ou', '')
    group = body.get('group', '')

    existing_user = None
    user_updates = {}
    if len(email) > 0:
        matching_users = []
        try:
            matching_users = idp_client.list_users(UserPoolId=user_pool_id, Filter=f'email = "{email}"')['Users']
        except ClientError as e:
            user_updates['list_error'] = str(e)

        existing_user = matching_users[0] if len(matching_users) > 0 else None
        if existing_user is not None:
            attribute_updates = []
            if len(org) > 0:
                attribute_updates.append({'Name': 'custom:org', 'Value': org})
            if len(ou) > 0:
                attribute_updates.append({'Name': 'custom:ou', 'Value': ou})
            if len(attribute_updates) > 0:
                try:
                    attr_update_response = idp_client.admin_update_user_attributes(
                        UserPoolId=user_pool_id,
                        Username=existing_user['UserId'],
                        UserAttributes=attribute_updates
                    )
                    user_updates['attributes'] = attr_update_response
                except ClientError as e:
                    user_updates['attributes'] = str(e)

            if len(group) > 0:
                try:
                    group_update_response = idp_client.admin_add_user_to_group(
                        UserPoolId=user_pool_id,
                        Username=existing_user['UserId'],
                        GroupName=group
                    )
                    user_updates['groups'] = group_update_response
                except ClientError as e:
                    user_updates['groups'] = str(e)

    response_body = {
        'message': 'hello',
        'input': event,
        'existing_user': existing_user,
        'user_updates': user_updates
    }

    logger.info({'response_body': response_body})
    response = {
        'statusCode': 200,
        'body': json.dumps(response_body),
        'headers': {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Credentials': True,
        },
    }

    return response
