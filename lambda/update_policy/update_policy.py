import json
import boto3

s3 = boto3.client('s3')
iam = boto3.client('iam')

def create_new_policy(my_name, my_policy):
  print('Creating new IAM policy '.format(my_name))
  try:
    my_response = iam.create_policy(
      PolicyName=my_name,
      PolicyDocument=my_policy
    )
  except:
    raise Exception('Failed to create new policy '.format(policy_name))
  print('Created policy: {}'.format(my_response))

def update_policy(my_name, my_policy, my_arn):
  print('Creating new version of IAM policy '.format(my_name))
  try:
    my_response = iam.create_policy_version(PolicyArn=my_arn,
      PolicyDocument=my_policy,
      SetAsDefault=True
    )
  except:
    raise Exception('Failed to update policy '.format(policy_name))
  my_current_policy = iam.get_policy(
    PolicyArn=my_arn
  )
  my_policy_version = iam.get_policy_version(
    PolicyArn = my_arn,
    VersionId = my_current_policy['Policy']['DefaultVersionId']
  )
  print('Updated policy: {}'.format(my_policy_version['PolicyVersion']['Document']))

def lambda_handler(event, context):
  max_versions = 5
  aws_account = '119178693678'
  policy_name = 'scpCloudTrailDisable'
  policy_arn = 'arn:aws:iam::{}:policy/{}'.format(aws_account, policy_name)

  test_policy = {
      "Version": "2012-10-17",
      "Statement": [
      {
        "Effect": "Deny",
        "Action": "cloudtrail:StopLogging",
        "Resource": "*"
      }
    ]
  }
  test_bucket_name = 'configuration-119178693678'
  test_file_key = 'Sevice-Control-Policies/scp_cloudtrail_disable.json'

  bucket_name = event['Records'][0]['s3']['bucket']['name']
  file_key = event['Records'][0]['s3']['object']['key']

  print('Getting new policy from S3 bucket {}, file {}'.format(bucket_name, file_key))
  try:
    file_object = s3.get_object(Bucket=bucket_name, Key=file_key)
  except:
    raise Exception('Could not get S3 object {}/{}'.format(bucket_name, file_key))

  new_policy = file_object["Body"].read().decode()
  print('New policy:\n{}'.format(new_policy))

  print('Getting IAM policy {} ({})'.format(policy_name, policy_arn))
  try:
    current_policy = iam.get_policy(
      PolicyArn=policy_arn
    )
  except:
    print('Failed to get IAM policy {} ({})'.format(policy_name, policy_arn))
    print('Creating a new policy: {}'.format(new_policy))
    try:
      create_new_policy(policy_name, test_policy)
    except:
      raise Exception('Failed to create new policy '.format(policy_name))

  try:
    policy_versions = iam.list_policy_versions(
      PolicyArn=policy_arn
    )
  except:
    raise Exception('Failed to get versions')

  if len(policy_versions['Versions']) >= 5:
    oldest_version = policy_versions['Versions'][-1]['VersionId']
    print('Policy has reached maximum of {} versions\nDeleting oldest version {}'.format(max_versions, oldest_version))
    try:
      iam.delete_policy_version(
        PolicyArn=policy_arn,
        VersionId=oldest_version
      )
    except:
      raise Exception('Failed to delete policy version {}'.format(oldest_version))

  policy_version = iam.get_policy_version(
    PolicyArn = policy_arn,
    VersionId = current_policy['Policy']['DefaultVersionId']
  )
  print('Updating policy {}'.format(policy_name))
  print('Current policy: {}'.format(policy_version['PolicyVersion']['Document']))
  update_policy(policy_name, new_policy, policy_arn)



#def lambda_handler(event, context):
#    # TODO implement
#    return {
#        'statusCode': 200,
#        'body': json.dumps('Hello from Lambda!')
#    }
