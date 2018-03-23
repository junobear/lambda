'''
Follow these steps to configure the webhook in Slack:

  1. Navigate to https://<your-team-domain>.slack.com/services/new

  2. Search for and select "Incoming WebHooks".

  3. Choose the default channel where messages will be sent and click "Add Incoming WebHooks Integration".

  4. Copy the webhook URL from the setup instructions and use it in the next section.

To encrypt your secrets use the following steps:

  1. Create or use an existing KMS Key - http://docs.aws.amazon.com/kms/latest/developerguide/create-keys.html

  2. Click the "Enable Encryption Helpers" checkbox

  3. Paste <SLACK_CHANNEL> into the slackChannel environment variable

  Note: The Slack channel does not contain private info, so do NOT click encrypt

  4. Paste <SLACK_HOOK_URL> into the kmsEncryptedHookUrl environment variable and click encrypt

  Note: You must exclude the protocol from the URL (e.g. "hooks.slack.com/services/abc123").

  5. Give your function's role permission for the kms:Decrypt action.

     Example:

{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "Stmt1443036478000",
            "Effect": "Allow",
            "Action": [
                "kms:Decrypt"
            ],
            "Resource": [
                "<your KMS key ARN>"
            ]
        }
    ]
}
'''
from __future__ import print_function # Python 2/3 compatibility
import boto3
import json
import logging
import os
from boto3.dynamodb.conditions import Key, Attr
from botocore.exceptions import ClientError
from base64 import b64decode
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# Helper class to convert a DynamoDB item to JSON.
class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, decimal.Decimal):
            if o % 1 > 0:
                return float(o)
            else:
                return int(o)
        return super(DecimalEncoder, self).default(o)
        

# The base-64 encoded, encrypted key (CiphertextBlob) stored in the kmsEncryptedHookUrl environment variable
ENCRYPTED_HOOK_URL = os.environ['kmsEncryptedHookUrl']
# The Slack channel to send a message to stored in the slackChannel environment variable
SLACK_CHANNEL = os.environ['slackChannel']

HOOK_URL = "https://" + boto3.client('kms').decrypt(CiphertextBlob=b64decode(ENCRYPTED_HOOK_URL))['Plaintext'].decode('utf-8')

logger = logging.getLogger()
logger.setLevel(logging.INFO)
#logger.info("message: variable HOOK_URL" + str(HOOK_URL))

def lambda_handler(event, context):
    logger.info("Event: " + str(event))
    message = json.loads(event['Records'][0]['Sns']['Message'])
    #message = event['Records'][0]['Sns']['Message']
    logger.info("Message: " + str(message))
    processEvent(message,context)


#For now we are defaulting as a CW event
def processEvent(message,context):
    logger.info("Message: " + str(message))
    
    alarm_name = message['AlarmName']
    region_name = message['Region']
    new_state = message['NewStateValue']
    new_reason = message['NewStateReason']
    trigger_metric = message['Trigger']['MetricName']
    #link=https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#alarm:alarmFilter=ANY;name=ADCreditUsage
    alarm_title = "CloudWatch Notification for account # "
    name = message['Trigger']['Dimensions'][0]['name']
    instance_id = message['Trigger']['Dimensions'][0]['value']
    account_id = message['AWSAccountId']
    namespace = message['Trigger']['Namespace']
    
    if new_state == "OK":
        alarm_color = "good"
        alarm_filter = "inOk"
    elif new_state == "ALARM":
        alarm_color = "danger"
        alarm_filter = "inAlarm"
    else:
        alarm_color = "good"
        alarm_filter = "ANY"
        
    if region_name == "US East (N. Virginia)":
        region = "us-east-1"
    
    sm_link = "https://console.aws.amazon.com/cloudwatch/home?region="+str(region)+"#alarm:alarmFilter="+str(alarm_filter)+";name="+alarm_name
    
    #get_inst_info
    ec2_psme = get_ec2_psme(instance_id)
    ec2_ssme = get_ec2_ssme(instance_id)
    ec2_env = get_ec2_env(instance_id)
    ec2_proj = get_ec2_project(instance_id)
    
    dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
    table = dynamodb.Table('wcmid_slack')
    
    try:
        response = table.get_item(
            Key={
                'id': ec2_psme
            }
        )
    except ClientError as e:
        logger.error("Error: " + e.response['Error']['Message'])
    else:
        if 'Item' in response:
            item = response['Item']
            #replace with slack id 
            ec2_psme = "<@"+item['slackid']+">"
            logger.info("GetItem PSME succeeded:" + json.dumps(item, indent=4, cls=DecimalEncoder))
        else:
            logger.info("GetItem PSME failed for " + ec2_psme)

    try:
        response = table.get_item(
            Key={
                'id': ec2_ssme
            }
        )
    except ClientError as e:
        logger.error("Error: " + e.response['Error']['Message'])
    else:
        if 'Item' in response:
            item = response['Item']
            #replace with slack id 
            ec2_ssme = "<@"+item['slackid']+">"
            logger.info("GetItem SSME succeeded:" + json.dumps(item, indent=4, cls=DecimalEncoder))
        else:
            logger.info("GetItem SSME failed for " + ec2_ssme)
    
    slack_message = {
        "channel": SLACK_CHANNEL,
        "attachments": [ 
            {
                "color": alarm_color,
                "title": alarm_title + account_id + " @ " + region,
                "fields": [
                    {
                        "title": "Alarm Name for " + namespace,
                        "value": alarm_name
                    },
                    {
                        "title": "Alarm Description",
                        "value": new_reason
                    },
                    {
                        "title": "Project",
                        "value": ec2_proj,
                        "short": "true"
                    },
                    {
                        "title": "Environment",
                        "value": ec2_env,
                        "short": "true"
                    },
                    {
                        "title": "Primary SME",
                        "value": ec2_psme,
                        "short": "true"
                    },
                    {
                        "title": "Secondary SME",
                        "value": ec2_ssme,
                        "short": "true"
                    },
                    {
                        "title": "Link to Alarm",
                        "value": sm_link
                    }
                ]
            }
        ]
    }
    req = Request(HOOK_URL, json.dumps(slack_message).encode('utf-8'))
    try:
        response = urlopen(req)
        response.read()
        logger.info("Message posted to %s", slack_message['channel'])
    except HTTPError as e:
        logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
        logger.error("Server connection failed: %s", e.reason)


def get_ec2_psme(i_id):
    ec2 = boto3.resource('ec2')
    ec2instance = ec2.Instance(i_id)
    psme = ''
    for tags in ec2instance.tags:
        if tags["Key"] == 'PrimarySME':
            psme = tags["Value"]
    return psme
    
def get_ec2_ssme(i_id):
    ec2 = boto3.resource('ec2')
    ec2instance = ec2.Instance(i_id)
    ssme = ''
    for tags in ec2instance.tags:
        if tags["Key"] == 'SecondarySME':
            ssme = tags["Value"]
    return ssme

def get_ec2_project(i_id):
    ec2 = boto3.resource('ec2')
    ec2instance = ec2.Instance(i_id)
    project = ''
    for tags in ec2instance.tags:
        if tags["Key"] == 'Application':
            project = tags["Value"]
    return project

def get_ec2_env(i_id):
    ec2 = boto3.resource('ec2')
    ec2instance = ec2.Instance(i_id)
    env = ''
    for tags in ec2instance.tags:
        if tags["Key"] == 'Environment':
            env = tags["Value"]
    return env   
