//
//  NSData+Encryption.m
//  Encrypt-Decrypt
//
//  Created by Alexey Bondarchuk on 11/12/16.
//

#import "NSData+Encryption.h"
#import <CommonCrypto/CommonCrypto.h>
@import Security;

SecKeyRef publicKey;
SecKeyRef privateKey;

@implementation NSData (Encryption)

- (NSData *)AES256EncryptWithKey:(NSString *)key iv:(NSString *)iv
{
    char keyPtr[kCCKeySizeAES256+1];
    char ivPointer[kCCBlockSizeAES128+2];
    
    bzero(keyPtr, sizeof(keyPtr));
    bzero(ivPointer, sizeof(ivPointer));
    
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    [iv getCString:ivPointer maxLength:sizeof(ivPointer) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [self length];
    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                          keyPtr, kCCKeySizeAES256,
                                          ivPointer,
                                          [self bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesEncrypted);
    if (cryptStatus == kCCSuccess)
    {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    
    free(buffer);
    return nil;
}

- (NSData *)AES256DecryptWithKey:(NSString *)key iv:(NSString *)iv
{
    char keyPtr[kCCKeySizeAES256+1];
    char ivPointer[kCCBlockSizeAES128+2];
    
    bzero(keyPtr, sizeof(keyPtr));
    bzero(ivPointer, sizeof(ivPointer));
    
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    [iv getCString:ivPointer maxLength:sizeof(ivPointer) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [self length];
    
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    
    size_t numBytesDecrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                          keyPtr, kCCKeySizeAES256,
                                          ivPointer,
                                          [self bytes], dataLength,
                                          buffer, bufferSize,
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess)
    {
        return [NSData dataWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    
    free(buffer);
    return nil;
}

size_t BUFFER_SIZE = 64;
size_t CIPHER_BUFFER_SIZE = 2048;

- (NSData *)RSA2048EncryptWithPublicKey:(NSString *)publicKey privateKey:(NSString *)privateKey
{
    NSData *privateTag = [privateKey dataUsingEncoding:NSUTF8StringEncoding];
    NSData *publicTag = [publicKey dataUsingEncoding:NSUTF8StringEncoding];
    
    [self generateKeyPair:2048 privateTag:privateTag publicTag:publicTag];
    
    uint8_t *cipherBuffer;
    
    const char *inputString = [self base64EncodedStringWithOptions:0].UTF8String;
    unsigned long len = strlen(inputString);
    BUFFER_SIZE = len;
    
    cipherBuffer = (uint8_t *)calloc(CIPHER_BUFFER_SIZE, sizeof(uint8_t));
    
    [self encryptWithPublicKey:publicTag plainBuffer:(UInt8 *)inputString cipherBuffer:cipherBuffer];
    
    NSData *data = [NSData dataWithBytes:cipherBuffer length:CIPHER_BUFFER_SIZE];
    
    free(cipherBuffer);
    
    return data;
}

- (NSData *)RSA2048DecryptWithPrivateKey:(NSString *)privateKey
{
    NSData *privateTag = [privateKey dataUsingEncoding:NSUTF8StringEncoding];
    
    uint8_t *decryptedBuffer;
    
    decryptedBuffer = (uint8_t *)calloc(BUFFER_SIZE, sizeof(uint8_t));
    
    [self decryptWithPrivateKey:privateTag cipherBuffer:(uint8_t *)self.bytes plainBuffer:decryptedBuffer];
    
    NSString *str = [[NSString alloc] initWithBytes:decryptedBuffer length:BUFFER_SIZE encoding:NSUTF8StringEncoding];
    NSData *data = [[NSData alloc] initWithBase64EncodedString:str options:0];

    free(decryptedBuffer);
    
    return data;
}

- (SecKeyRef)getPublicKeyRefFromTag:(NSData *)publicTag
{
    OSStatus sanityCheck = noErr;
    SecKeyRef publicKeyReference = NULL;
    
    if (publicKeyReference == NULL)
    {
        NSMutableDictionary *queryPublicKey = [NSMutableDictionary dictionary];
        
        [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
        [queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
        [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
        [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
        
        sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKeyReference);
        
        if (sanityCheck != noErr)
        {
            publicKeyReference = NULL;
        }
    }
    else
    {
        publicKeyReference = publicKey;
    }
    
    return publicKeyReference;
}

- (OSStatus)encryptWithPublicKey:(NSData *)publicTag plainBuffer:(uint8_t *)plainBuffer cipherBuffer:(uint8_t *)cipherBuffer
{
    OSStatus status = noErr;
    
    size_t plainBufferSize = BUFFER_SIZE;
    size_t cipherBufferSize = 2048;
    
    status = SecKeyEncrypt([self getPublicKeyRefFromTag:publicTag],
                           kSecPaddingNone,
                           plainBuffer,
                           plainBufferSize,
                           &cipherBuffer[0],
                           &cipherBufferSize
                           );
    CIPHER_BUFFER_SIZE = (size_t)cipherBufferSize;
    
    return status;
}

- (void)decryptWithPrivateKey:(NSData *)privateTag cipherBuffer:(uint8_t *)cipherBuffer plainBuffer:(uint8_t *)plainBuffer
{
    OSStatus status = noErr;
    
    size_t cipherBufferSize = CIPHER_BUFFER_SIZE;
    size_t plainBufferSize = BUFFER_SIZE;
    
    status = SecKeyDecrypt([self getPrivateKeyRefFromTag:privateTag],
                           kSecPaddingNone,
                           &cipherBuffer[0],
                           cipherBufferSize,
                           &plainBuffer[0],
                           &plainBufferSize
                           );
}

- (SecKeyRef)getPrivateKeyRefFromTag:(NSData *)privateTag
{
    OSStatus resultCode = noErr;
    SecKeyRef privateKeyReference = NULL;
    NSMutableDictionary *queryPrivateKey = [NSMutableDictionary dictionary];
    [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPrivateKey setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    resultCode = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKeyReference);
    
    if (resultCode != noErr)
    {
        privateKeyReference = NULL;
    }
    
    return privateKeyReference;
}

- (void)generateKeyPair:(NSUInteger)keySize privateTag:(NSData *)privateTag publicTag:(NSData *)publicTag
{
    publicKey = NULL;
    privateKey = NULL;
    
    NSMutableDictionary *privateKeyAttr = [NSMutableDictionary dictionary];
    NSMutableDictionary *publicKeyAttr = [NSMutableDictionary dictionary];
    NSMutableDictionary *keyPairAttr = [NSMutableDictionary dictionary];
    
    [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyPairAttr setObject:[NSNumber numberWithUnsignedInteger:keySize] forKey:(__bridge id)kSecAttrKeySizeInBits];
    
    [privateKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [privateKeyAttr setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    [publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    [keyPairAttr setObject:privateKeyAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
    [keyPairAttr setObject:publicKeyAttr forKey:(__bridge id)kSecPublicKeyAttrs];
    
    SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKey, &privateKey);
}

@end
