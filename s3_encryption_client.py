import boto3, os, base64, hashlib, json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class S3EncryptionClient():
    def __init__(self, kms_key_id, kms_client, s3_client, nonce_size = 12, tag_length = 128):
        self.kms_key_id = kms_key_id 
        self.kms_client = kms_client
        self.s3_client = s3_client
        self.nonce_size = nonce_size
        self.tag_length = str(tag_length)
        
    def put_object(self, bucket, key, body):
        kms_cmk_id = self.kms_key_id
        encryption_context = { "kms_cmk_id" : kms_cmk_id }

        out = self.kms_client.generate_data_key(
            KeyId=kms_cmk_id,
            EncryptionContext=encryption_context,
            KeySpec='AES_256')

        data_key = out['Plaintext']
        encrypted_data_key = out['CiphertextBlob']

        iv = os.urandom(self.nonce_size)

        aesgcm = AESGCM(data_key)
        cipher_text = aesgcm.encrypt(iv, body, None)

        md5 = base64.b64encode(hashlib.md5(body).digest())
        content_length = str(len(body))
 
        # delete keys and data?

        cipher_data = {}
        cipher_data['x-amz-wrap-alg']= 'kms'
        cipher_data['x-amz-matdesc'] = json.dumps(encryption_context)
        cipher_data['x-amz-key-v2'] = base64.b64encode(encrypted_data_key)
        cipher_data['x-amz-iv'] = base64.b64encode(iv)
        cipher_data['x-amz-cek-alg'] = 'AES/GCM/NoPadding'
        cipher_data['x-amz-tag-len'] = self.tag_length
        cipher_data['x-amz-unencrypted-content-md5'] = md5
        cipher_data['x-amz-unencrypted-content-length'] = content_length
        
        return self.s3_client.Object(bucket, key).put(Body=cipher_text, Metadata=cipher_data)
    
    def get_object(self, bucket, key): 
        s3_response = self.s3_client.Object(bucket, key).get()
        
        encrypted_data = s3_response['Body'].read()
        metadata = s3_response['Metadata']
        encrypted_data_key = base64.b64decode(metadata['x-amz-key-v2'])
        iv = base64.b64decode(metadata['x-amz-iv'])
        encryption_context = json.loads(metadata['x-amz-matdesc'])

        out = self.kms_client.decrypt(
            CiphertextBlob=encrypted_data_key,
            EncryptionContext=encryption_context
        )

        decrypted_data_key = out['Plaintext']
        aesgcm = AESGCM(decrypted_data_key)
        data = aesgcm.decrypt(iv, encrypted_data, None)
        
        return data
