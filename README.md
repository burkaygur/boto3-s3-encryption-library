# S3 Encryption Library

This is a client-side S3 encryption library that is compatible with aws-sdk-go and aws-sdk-ruby etc.

It is built in the absence of boto3 not currently supporting client side S3 encryption.

https://docs.aws.amazon.com/general/latest/gr/aws_sdk_cryptography.html

Currently only support is for KMS key provider (to generate data keys) and Python `cryptography`'s AESGCM.
