# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

# From https://github.com/aws-samples/aws-saas-factory-ref-solution-serverless-saas/blob/cea081cb4ca6f4f228d4a5ff12cb5056b522499a/server/Resources/shared_service_authorizer.py

import re
import json
import os
import urllib.request
import boto3
import time
from jose import jwk, jwt
from jose.utils import base64url_decode
from aws_lambda_powertools import Logger, Tracer

logger = Logger(service="authorizer")
tracer = Tracer()

stage = os.environ['STAGE']
region = os.environ['AWS_REGION']
sts_client = boto3.client("sts", region_name=region)

user_pool_arn = os.environ['USER_POOL_ARN']
user_pool_id = os.environ['USER_POOL_ID']
app_client_id = os.environ['USER_POOL_CLIENT_ID']
table_name = os.environ['TABLE_NAME']

@logger.inject_lambda_context
@tracer.capture_lambda_handler
def lambda_handler(event, _):
    logger.info(event)
    
    #get JWT token after Bearer from authorization
    token = event['authorizationToken'].split(" ")
    if (token[0] != 'Bearer'):
        raise Exception('Authorization header should have a format Bearer <JWT> Token')
    jwt_bearer_token = token[1]
    logger.info("Method ARN: " + event['methodArn'])
    
    unauthorized_claims = jwt.get_unverified_claims(jwt_bearer_token)
    logger.info(unauthorized_claims)

    # get JWK for user pool to validate
    keys_url = f'https://cognito-idp.{region}.amazonaws.com/{user_pool_id}/.well-known/jwks.json'
    with urllib.request.urlopen(keys_url) as f:
        response = f.read()
    keys = json.loads(response.decode('utf-8'))['keys']

    # validate against cognito user pool using the key
    response = validateJWT(jwt_bearer_token, app_client_id, keys)
    
    # get authenticated claims
    if (response == False):
        logger.error('Unauthorized')
        raise Exception('Unauthorized')
    else:
        logger.info(response)
        principal_id = response["sub"]
        user_name = response["cognito:username"]
        groups = response.get("cognito:groups", [])
        org_id = response.get("custom:org")
        ou_id = response.get("custom:ou")
    
    
    tmp = event['methodArn'].split(':')
    api_gateway_arn_tmp = tmp[5].split('/')
    aws_account_id = tmp[4]    
    
    policy = AuthPolicy(principal_id, aws_account_id)
    policy.restApiId = api_gateway_arn_tmp[0]
    policy.region = tmp[3]
    policy.stage = api_gateway_arn_tmp[1]

    #only tenant admin and system admin can do certain actions like create and disable users
    # if (auth_manager.isTenantAdmin(user_role) or auth_manager.isSystemAdmin(user_role)):
    #     policy.allowAllMethods()
    #     if (auth_manager.isTenantAdmin(user_role)):
    #         policy.denyMethod(HttpVerb.POST, "tenant-activation")
    #         policy.denyMethod(HttpVerb.GET, "tenants")
    # else:
        #if not tenant admin or system admin then only allow to get info and update info
    if 'admin' in groups:
        policy.allowAllMethods()
    else:
        policy.allowAllMethods()
        policy.denyMethod(HttpVerb.PUT, "user-group")
        

    authResponse = policy.build()
 
    #   Generate STS credentials to be used for FGAC
    
    #   Important Note: 
    #   We are generating STS token inside Authorizer to take advantage of the caching behavior of authorizer
    #   Another option is to generate the STS token inside the lambda function itself, as mentioned in this blog post: https://aws.amazon.com/blogs/apn/isolating-saas-tenants-with-dynamically-generated-iam-policies/
    #   Finally, you can also consider creating one Authorizer per microservice in cases where you want the IAM policy specific to that service 
    
    iam_policy = getPolicyForUser(org_id, ou_id, region, groups, aws_account_id)
    logger.info(iam_policy)
    
    role_arn = f"arn:aws:iam::{aws_account_id}:role/authorizer-access-role-{stage}"
    
    assumed_role = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName="tenant-aware-session",
        Policy=json.dumps(iam_policy),
    )
    credentials = assumed_role["Credentials"]

    #pass sts credentials to lambda
    context = {
        'accesskey': credentials['AccessKeyId'], # $context.authorizer.key -> value
        'secretkey' : credentials['SecretAccessKey'],
        'sessiontoken' : credentials["SessionToken"],
        'userName': user_name,
        'org': org_id,
        'ou': ou_id,
        'groups': ','.join(groups)  # The context object cannot contain arrays
    }
    
    authResponse['context'] = context

    logger.info(authResponse) 

    return authResponse

def validateJWT(token, app_client_id, keys):
    # get the kid from the headers prior to verification
    headers = jwt.get_unverified_headers(token)
    kid = headers['kid']
    # search for the kid in the downloaded public keys
    key_index = -1
    for i in range(len(keys)):
        if kid == keys[i]['kid']:
            key_index = i
            break
    if key_index == -1:
        logger.info('Public key not found in jwks.json')
        return False
    # construct the public key
    public_key = jwk.construct(keys[key_index])
    # get the last two sections of the token,
    # message and signature (encoded in base64)
    message, encoded_signature = str(token).rsplit('.', 1)
    # decode the signature
    decoded_signature = base64url_decode(encoded_signature.encode('utf-8'))
    # verify the signature
    if not public_key.verify(message.encode("utf8"), decoded_signature):
        logger.info('Signature verification failed')
        return False
    logger.info('Signature successfully verified')
    # since we passed the verification, we can now safely
    # use the unverified claims
    claims = jwt.get_unverified_claims(token)
    # additionally we can verify the token expiration
    if time.time() > claims['exp']:
        logger.info('Token is expired')
        return False
    # and the Audience  (use claims['client_id'] if verifying an access token)
    if claims['aud'] != app_client_id:
        logger.info('Token was not issued for this audience')
        return False
    # now we can use the claims
    logger.info(claims)
    return claims


class HttpVerb:
    GET     = "GET"
    POST    = "POST"
    PUT     = "PUT"
    PATCH   = "PATCH"
    HEAD    = "HEAD"
    DELETE  = "DELETE"
    OPTIONS = "OPTIONS"
    ALL     = "*"

class AuthPolicy(object):
    awsAccountId = ""
    """The AWS account id the policy will be generated for. This is used to create the method ARNs."""
    principalId = ""
    """The principal used for the policy, this should be a unique identifier for the end user."""
    version = "2012-10-17"
    """The policy version used for the evaluation. This should always be '2012-10-17'"""
    pathRegex = "^[/.a-zA-Z0-9-\*]+$"
    """The regular expression used to validate resource paths for the policy"""

    """these are the internal lists of allowed and denied methods. These are lists
    of objects and each object has 2 properties: A resource ARN and a nullable
    conditions statement.
    the build method processes these lists and generates the approriate
    statements for the final policy"""
    allowMethods = []
    denyMethods = []

    restApiId = "*"
    """The API Gateway API id. By default this is set to '*'"""
    region = "*"
    """The region where the API is deployed. By default this is set to '*'"""
    stage = "*"
    """The name of the stage used in the policy. By default this is set to '*'"""

    def __init__(self, principal, awsAccountId):
        self.awsAccountId = awsAccountId
        self.principalId = principal
        self.allowMethods = []
        self.denyMethods = []

    def _addMethod(self, effect, verb, resource, conditions):
        """Adds a method to the internal lists of allowed or denied methods. Each object in
        the internal list contains a resource ARN and a condition statement. The condition
        statement can be null."""
        if verb != "*" and not hasattr(HttpVerb, verb):
            raise NameError("Invalid HTTP verb " + verb + ". Allowed verbs in HttpVerb class")
        resourcePattern = re.compile(self.pathRegex)
        if not resourcePattern.match(resource):
            raise NameError("Invalid resource path: " + resource + ". Path should match " + self.pathRegex)

        if resource[:1] == "/":
            resource = resource[1:]

        resourceArn = ("arn:aws:execute-api:" +
            self.region + ":" +
            self.awsAccountId + ":" +
            self.restApiId + "/" +
            self.stage + "/" +
            verb + "/" +
            resource)

        if effect.lower() == "allow":
            self.allowMethods.append({
                'resourceArn' : resourceArn,
                'conditions' : conditions
            })
        elif effect.lower() == "deny":
            self.denyMethods.append({
                'resourceArn' : resourceArn,
                'conditions' : conditions
            })

    def _getEmptyStatement(self, effect):
        """Returns an empty statement object prepopulated with the correct action and the
        desired effect."""
        statement = {
            'Action': 'execute-api:Invoke',
            'Effect': effect[:1].upper() + effect[1:].lower(),
            'Resource': []
        }

        return statement

    def _getStatementForEffect(self, effect, methods):
        """This function loops over an array of objects containing a resourceArn and
        conditions statement and generates the array of statements for the policy."""
        statements = []

        if len(methods) > 0:
            statement = self._getEmptyStatement(effect)

            for curMethod in methods:
                if curMethod['conditions'] is None or len(curMethod['conditions']) == 0:
                    statement['Resource'].append(curMethod['resourceArn'])
                else:
                    conditionalStatement = self._getEmptyStatement(effect)
                    conditionalStatement['Resource'].append(curMethod['resourceArn'])
                    conditionalStatement['Condition'] = curMethod['conditions']
                    statements.append(conditionalStatement)

            statements.append(statement)

        return statements

    def allowAllMethods(self):
        """Adds a '*' allow to the policy to authorize access to all methods of an API"""
        self._addMethod("Allow", HttpVerb.ALL, "*", [])

    def denyAllMethods(self):
        """Adds a '*' allow to the policy to deny access to all methods of an API"""
        self._addMethod("Deny", HttpVerb.ALL, "*", [])

    def allowMethod(self, verb, resource):
        """Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods for the policy"""
        self._addMethod("Allow", verb, resource, [])

    def denyMethod(self, verb, resource):
        """Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods for the policy"""
        self._addMethod("Deny", verb, resource, [])

    def allowMethodWithConditions(self, verb, resource, conditions):
        """Adds an API Gateway method (Http verb + Resource path) to the list of allowed
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition"""
        self._addMethod("Allow", verb, resource, conditions)

    def denyMethodWithConditions(self, verb, resource, conditions):
        """Adds an API Gateway method (Http verb + Resource path) to the list of denied
        methods and includes a condition for the policy statement. More on AWS policy
        conditions here: http://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements.html#Condition"""
        self._addMethod("Deny", verb, resource, conditions)

    def build(self):
        """Generates the policy document based on the internal lists of allowed and denied
        conditions. This will generate a policy with two main statements for the effect:
        one statement for Allow and one statement for Deny.
        Methods that includes conditions will have their own statement in the policy."""
        if ((self.allowMethods is None or len(self.allowMethods) == 0) and
            (self.denyMethods is None or len(self.denyMethods) == 0)):
            raise NameError("No statements defined for the policy")

        policy = {
            'principalId' : self.principalId,
            'policyDocument' : {
                'Version' : self.version,
                'Statement' : []
            }
        }

        policy['policyDocument']['Statement'].extend(self._getStatementForEffect("Allow", self.allowMethods))
        policy['policyDocument']['Statement'].extend(self._getStatementForEffect("Deny", self.denyMethods))

        return policy


def getPolicyForUser(org_id, ou_id, region, groups, aws_account_id):
    """ This method is being used by Authorizer to get appropriate policy by user role
    Args:
        org_id (string): Organisation
        ou_id (string): Organisation Unit
        region (string): 
        aws_account_id (string):  
    Returns:
        string: policy that tenant needs to assume
    """
    statements = []
    if org_id is not None:
        statements.append({
            "Effect": "Allow",
                    "Action": [
                        "dynamodb:UpdateItem",
                        "dynamodb:GetItem",
                        "dynamodb:PutItem",
                        "dynamodb:DeleteItem",
                        "dynamodb:Query"
                    ],
            "Resource": [
                        f"arn:aws:dynamodb:{region}:{aws_account_id}:table/{table_name}",
                    ],
            "Condition": {
                        "ForAllValues:StringLike": {
                            "dynamodb:LeadingKeys": [
                                f"{org_id}#*"
                            ]
                        }
                    }
        })
    if 'admin' in groups:
        statements.append({
            "Effect": "Allow",
                "Action": [
                    "cognito-idp:AdminGetUser",
                    "cognito-idp:ListUsers",
                    "cognito-idp:AdminUpdateUserAttributes",
                    "cognito-idp:AdminAddUserToGroup",
                ],
            "Resource": [user_pool_arn]
    })

    return {	
        "Version": "2012-10-17",
          "Statement": statements
        }
