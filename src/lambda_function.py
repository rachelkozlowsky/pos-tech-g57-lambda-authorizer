import os
import boto3
import logging
from typing import Dict, Any
from botocore.exceptions import ClientError

# --- Configuration ---
# It's a best practice to initialize the logger and AWS clients
# outside the handler to be reused across invocations (improves performance).
logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

dynamodb = boto3.resource('dynamodb')

# --- Helper Function ---
def _generate_policy(principal_id: str, effect: str, resource: str) -> Dict[str, Any]:
    """
    Generates the IAM policy document required by API Gateway Lambda authorizers.
    """
    return {
        'principalId': principal_id,
        'policyDocument': {
            'Version': '2012-10-17',
            'Statement': [{
                'Action': 'execute-api:Invoke',
                'Effect': effect,
                'Resource': resource
            }]
        }
    }

# --- Main Handler ---
def lambda_handler(event: Dict[str, Any], context: object) -> Dict[str, Any]:
    """
    Main handler for the Lambda Authorizer.
    It validates a token (expected to be a CPF) from the 'Authorization' header
    against a DynamoDB table.

    :param event: The event dict from API Gateway, contains request context.
    :param context: The context object, contains runtime information.
    :return: An IAM policy document.
    """
    logger.debug(f"Authorizer event received: {event}")

    # --- Input Validation ---
    token = event.get('authorizationToken')
    method_arn = event.get('methodArn')

    if not token or not method_arn:
        logger.warning("Request is missing 'authorizationToken' or 'methodArn'.")
        # Cannot generate a valid policy without method_arn, so deny access.
        # Use a generic principalId as the user is unknown.
        return _generate_policy('user_unauthorized', 'Deny', '*')

    # --- Environment and Configuration Check ---
    table_name = os.environ.get('DYNAMODB_TABLE_NAME')
    if not table_name:
        logger.critical("FATAL: 'DYNAMODB_TABLE_NAME' environment variable is not set.")
        # This is a server-side configuration error. Deny all requests.
        return _generate_policy(token, 'Deny', method_arn)

    try:
        table = dynamodb.Table(table_name)
        # The token is the CPF, which we use as the partition key (pk).
        cpf = token
        logger.info(f"Validating CPF (token): {cpf} against table: {table_name}")

        # --- Core Logic: DynamoDB Lookup ---
        response = table.get_item(Key={'pk': cpf})

        if 'Item' in response:
            logger.info(f"CPF '{cpf}' found and is valid. Granting access.")
            return _generate_policy(cpf, 'Allow', method_arn)
        else:
            logger.warning(f"CPF '{cpf}' not found in the database. Denying access.")
            return _generate_policy(cpf, 'Deny', method_arn)

    except ClientError as e:
        # Handle specific AWS SDK errors
        error_code = e.response.get("Error", {}).get("Code")
        logger.error(f"AWS ClientError occurred: {error_code} - {e}")
        # Deny access by default on any database error for security.
        return _generate_policy(token, 'Deny', method_arn)

    except Exception as e:
        # Catch-all for any other unexpected errors
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        # Deny access by default on any unexpected error.
        return _generate_policy(token, 'Deny', method_arn)
