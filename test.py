import boto3
from s3_encryption_client import S3EncryptionClient

kms_key_id = "<YOUR_KMS_ARN_HERE>"
s3_bucket = "<YOUR_S3_BUCKET_NAME_HERE>"
s3_key = "foo"
secret_message = "bar"

s3_client = boto3.resource('s3')
kms_client = boto3.client('kms')
s3_enc_client = S3EncryptionClient(kms_key_id, kms_client, s3_client)

s3_enc_client.put_object(s3_bucket, s3_key, secret_message)

print(s3_enc_client.get_object(s3_bucket, s3_key))
