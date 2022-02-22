import boto3

from aws_lambda_powertools import Tracer, Logger

logger = Logger()
tracer = Tracer()

def session_for_event(event):
    auth = event['requestContext'].get('authorizer', {})
    access_key = auth.get('accesskey')
    secret_key = auth.get('secretkey')
    session_token = auth.get('sessiontoken')
    org = auth.get('org', 'NO_ORG')
    tracer.put_annotation(key='org', value=org)

    session = boto3.session.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token
    ) if access_key is not None else boto3.session.Session()

    sts = session.client('sts')

    caller_identity = sts.get_caller_identity()
    logger.info({'caller_identity': caller_identity})
    return session, org, caller_identity
