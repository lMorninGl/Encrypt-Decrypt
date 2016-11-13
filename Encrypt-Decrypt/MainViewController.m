//
//  MainViewController.m
//  Encrypt-Decrypt
//
//  Created by Alexey Bondarchuk on 11/12/16.
//

#import "MainViewController.h"
#import "Encryption.h"

@interface MainViewController ()

@property (weak, nonatomic) IBOutlet UIButton *generateButton;
@property (weak, nonatomic) IBOutlet UILabel *generatedStringLabel;
@property (weak, nonatomic) IBOutlet UIButton *encryptButton;
@property (weak, nonatomic) IBOutlet UILabel *encryptedStringLabel;
@property (weak, nonatomic) IBOutlet UIButton *decryptButton;
@property (weak, nonatomic) IBOutlet UILabel *decryptedStringLabel;

@property (strong, nonatomic) Encryption *encryption;

@end

@implementation MainViewController

#pragma mark - Event handlers

- (IBAction)onGenerate
{
    self.generatedStringLabel.hidden = false;
    self.encryptButton.hidden = false;
    self.encryptedStringLabel.hidden = true;
    self.decryptButton.hidden = true;
    self.decryptedStringLabel.hidden = true;
    
    self.encryption = [Encryption new];
    [self.encryption generateRandomString];
    self.generatedStringLabel.text = self.encryption.generatedString;
}

- (IBAction)onEncrypt
{
    self.encryptedStringLabel.hidden = false;
    self.decryptButton.hidden = false;
    self.decryptedStringLabel.hidden = true;
    
    [self.encryption encrypt];
    self.encryptedStringLabel.text = self.encryption.encryptedString;
}

- (IBAction)onDecrypt
{
    self.decryptedStringLabel.hidden = false;
    
    [self.encryption decrypt];
    self.decryptedStringLabel.text = self.encryption.decryptedString;
}

@end
