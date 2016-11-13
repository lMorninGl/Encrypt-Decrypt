//
//  Encryption.h
//  Encrypt-Decrypt
//
//  Created by Alexey Bondarchuk on 11/12/16.
//

#import <Foundation/Foundation.h>

@interface Encryption : NSObject

@property (strong, nonatomic, readonly) NSString *generatedString;
@property (strong, nonatomic, readonly) NSString *encryptedString;
@property (strong, nonatomic, readonly) NSString *decryptedString;

- (void)generateRandomString;
- (void)encrypt;
- (void)decrypt;

@end
