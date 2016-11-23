//
//  NSData+Encryption.h
//  Encrypt-Decrypt
//
//  Created by Alexey Bondarchuk on 11/12/16.
//

#import <Foundation/Foundation.h>

@interface NSData (Encryption)

- (NSData *)AES256EncryptWithKey:(NSString *)key iv:(NSString *)iv;
- (NSData *)AES256DecryptWithKey:(NSString *)key iv:(NSString *)iv;

- (NSData *)RSA2048EncryptWithPublicKey:(NSString *)publicKey privateKey:(NSString *)privateKey;
- (NSData *)RSA2048DecryptWithPrivateKey:(NSString *)privateKey;

@end
