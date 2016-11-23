//
//  Encryption.m
//  Encrypt-Decrypt
//
//  Created by Alexey Bondarchuk on 11/12/16.
//

#import "Encryption.h"
#import "NSData+Encryption.h"
#import "UICKeyChainStore.h"

static NSString *const kKeychainServiceName = @"good_dynamics_demo_keychain";

@implementation Encryption

- (void)generateRandomString
{
    _generatedString = [NSUUID UUID].UUIDString;
}

- (void)encrypt
{
    NSString *rsaPublicKey = [NSUUID UUID].UUIDString;
    NSString *rsaPrivateKey = [NSUUID UUID].UUIDString;
    
    NSString *aesKey = [NSUUID UUID].UUIDString;
    NSString *iv = [NSUUID UUID].UUIDString;
    
    NSLog(@"RSA public key - %@", rsaPublicKey);
    NSLog(@"RSA private key - %@", rsaPrivateKey);
    NSLog(@"AES key - %@", aesKey);
    NSLog(@"AES IV - %@", iv);
    
    UICKeyChainStore *keychain = [UICKeyChainStore keyChainStoreWithService:kKeychainServiceName];
    keychain[@"rsa_private_key"] = rsaPrivateKey;
    
    NSData *generatedStringData = [_generatedString dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *aes256_encrypted = [generatedStringData AES256EncryptWithKey:aesKey iv:iv];
    _encryptedString = [aes256_encrypted base64EncodedStringWithOptions:0];
    
    NSData *aesKeyData = [aesKey dataUsingEncoding:NSUTF8StringEncoding];
    NSData *ivData = [iv dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *aesKeyEncryptedData = [aesKeyData RSA2048EncryptWithPublicKey:rsaPublicKey privateKey:rsaPrivateKey];
    NSData *ivEncryptedData = [ivData RSA2048EncryptWithPublicKey:rsaPublicKey privateKey:rsaPrivateKey];
    
    NSString *encryptedAesKey = [aesKeyEncryptedData base64EncodedStringWithOptions:0];
    NSString *encryptedIV = [ivEncryptedData base64EncodedStringWithOptions:0];
    
    keychain[@"aes_key"] = encryptedAesKey;
    keychain[@"aes_iv"] = encryptedIV;
    
    /**
     
     1. Encrypt plain text with aes256 with random key and random initialization vector
     
     2. Encrypt the key and IV of aes256 with RSA2048. Need to encrypt with Public key and dectypt with PRIVATE
     
     3. Dectypt key and IV ... 
     
     */
}

- (void)decrypt
{
    UICKeyChainStore *keychain = [UICKeyChainStore keyChainStoreWithService:kKeychainServiceName];
    NSString *privateKey = keychain[@"rsa_private_key"];
    NSString *aesEncryptedKey = keychain[@"aes_key"];
    NSString *encryptedIV = keychain[@"aes_iv"];
    
    NSLog(@"RSA private key from keychain - %@", privateKey);
    
    NSData *aesKeyEncryptedData = [[NSData alloc] initWithBase64EncodedString:aesEncryptedKey options:0];
    NSData *aesIVEncryptedData = [[NSData alloc] initWithBase64EncodedString:encryptedIV options:0];
    
    NSData *aesDecryptedKeyData = [aesKeyEncryptedData RSA2048DecryptWithPrivateKey:privateKey];
    NSData *aesDecryptedIVData = [aesIVEncryptedData RSA2048DecryptWithPrivateKey:privateKey];
    
    NSString *aesKey = [[NSString alloc] initWithData:aesDecryptedKeyData encoding:NSUTF8StringEncoding];
    NSString *aesIV = [[NSString alloc] initWithData:aesDecryptedIVData encoding:NSUTF8StringEncoding];
    
    NSLog(@"Decrypted AES key - %@", aesKey);
    NSLog(@"Decrypted AES IV - %@", aesIV);
    
    NSData *encryptedStringData = [[NSData alloc] initWithBase64EncodedString:_encryptedString options:0];
    NSData *decryptedData = [encryptedStringData AES256DecryptWithKey:aesKey iv:aesIV];
    
    _decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
}

@end
