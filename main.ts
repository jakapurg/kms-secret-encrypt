import { CreateKeyCommand, DecryptCommand, EncryptCommand, KMSClient } from '@aws-sdk/client-kms';
import 'dotenv/config';


const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

const client = new KMSClient({
  region: process.env.AWS_REGION,
  credentials: {
    accessKeyId: process.env.AWS_KEY ?? "",
    secretAccessKey: process.env.AWS_SECRET ?? "",
  },
});

const kmsEncryption = async () => {
  let keyToSave: string | undefined;

  if(!process.env.KMS_KEY){
    const response = await client.send(new CreateKeyCommand({
        KeyUsage: "ENCRYPT_DECRYPT",
      }));
    
      const keyId = response.KeyMetadata?.KeyId;
    
      if(!keyId){
        throw new Error("Key not generated");
      }

      keyToSave = keyId;
    
  }
  else{
    keyToSave = process.env.KMS_KEY;
  }


  const secrets = {
    key1: "key1",
    key2: "key2",
    key3: "key3"
  }

  const encoder = new TextEncoder();
  const secretsUint8Array = encoder.encode(JSON.stringify(secrets));


  const encryptionResponse = await client.send(new EncryptCommand({
    KeyId: keyToSave,
    Plaintext: secretsUint8Array
  }))

  if(!encryptionResponse.CiphertextBlob){
    throw new Error("Encryption failed");
  }

  const encryptedSecrets = Buffer.from(encryptionResponse.CiphertextBlob).toString(
    'base64'
  )

  console.log("Encrypted secrets: ", encryptedSecrets);


  const buffer = Buffer.from(encryptedSecrets, 'base64');
  const uint8Array = new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength );


  const decryptionResponse = await client.send(new DecryptCommand({
    KeyId: keyToSave,
    CiphertextBlob: uint8Array
  }));

  if(!decryptionResponse.Plaintext){
    throw new Error("Decryption failed");
  }
  const textDecoder = new TextDecoder();
  const decryptedSecrets = textDecoder.decode(decryptionResponse.Plaintext);

  const decryptedSecretsObj = JSON.parse(decryptedSecrets);

  console.log("Decrypted secrets: ", decryptedSecretsObj);
} 

async function run() {
  await kmsEncryption();
}

run()
  .then(() => {
    console.log('done');
    process.exit(0);
  })
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
