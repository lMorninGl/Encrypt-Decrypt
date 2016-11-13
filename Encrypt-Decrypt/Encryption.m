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
    NSString *publicKey = [NSUUID UUID].UUIDString;
    NSString *privateKey = [NSUUID UUID].UUIDString;
    
    UICKeyChainStore *keychain = [UICKeyChainStore keyChainStoreWithService:kKeychainServiceName];
    keychain[@"private_key"] = privateKey;
    
    NSData *generatedStringData = [_generatedString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *aes256_encrypted = [generatedStringData AES256EncryptWithKey:privateKey];
    NSData *rsa2048Encrypted = [aes256_encrypted RSA2048EncryptWithPublicKey:publicKey privateKey:privateKey];
    
    _encryptedString = [rsa2048Encrypted base64EncodedStringWithOptions:0];
}

- (void)decrypt
{
    UICKeyChainStore *keychain = [UICKeyChainStore keyChainStoreWithService:kKeychainServiceName];
    NSString *privateKey = keychain[@"private_key"];
    
    NSData *encryptedData = [[NSData alloc] initWithBase64EncodedString:_encryptedString options:0];
    NSData *rsaDecryptedData = [encryptedData RSA2048DecryptWithPrivateKey:privateKey];
    NSData *decryptedData = [rsaDecryptedData AES256DecryptWithKey:privateKey];
    _decryptedString = [[NSString alloc] initWithData:decryptedData encoding:NSUTF8StringEncoding];
}

@end
