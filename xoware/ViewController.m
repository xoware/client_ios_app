//
//  ViewController.m
//  xoware
//
//  Created by Guna Ramireddy on 9/8/15.
//  Copyright (c) 2015 Sample. All rights reserved.
//

#import "ViewController.h"
#import <NetworkExtension/NEVPNManager.h>
#import <NetworkExtension/NEVPNProtocolIPSec.h>
#import <NetworkExtension/NEVPNProtocolIKEv2.h>
#import <NetworkExtension/NEVPNConnection.h>
#import "NSData+Base64.h"

@interface protocol : NEVPNProtocolIKEv2 {
    
    
}

@property (readonly, assign) NEVPNProtocolIKEv2 *protocol;

@end

@interface ViewController ()

@property (nonatomic, strong) NEVPNManager *manager;;
@property (nonatomic, strong) NEVPNIKEv2SecurityAssociationParameters *myIKESecurityAssociationParameters;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
    
    [self setupVPNConfig];
}

-(void)setupVPNConfig
{
    
        self.manager = [NEVPNManager sharedManager];

    
        [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(vpnConnectionStatusChanged) name:NEVPNStatusDidChangeNotification object:nil];
    
        [self.manager loadFromPreferencesWithCompletionHandler:^(NSError *error) {
            NSError *startError;
        
            if (error) {
                NSLog(@"Load config failed [%@]", error.localizedDescription);
                return;
            }
        
            
            NEVPNProtocolIKEv2 *protocol = (NEVPNProtocolIKEv2 *)self.manager.protocol;
            if (!protocol) {
               // protocol = [[NEVPNProtocolIPSec alloc] init];
                protocol = [[NEVPNProtocolIKEv2 alloc] init];
            }
            
            NSString *filePath = [[NSBundle mainBundle] pathForResource:@"Guna" ofType:@"txt"];
            NSString *certBase64String = [NSString stringWithContentsOfFile:filePath encoding:NSUTF8StringEncoding error:NULL];
            NSString *certPassword = @"vp3x";
        
            NSString *url = @"98.173.164.221";
            
            
            protocol.certificateType = NEVPNIKEv2CertificateTypeECDSA256;
            protocol.authenticationMethod = NEVPNIKEAuthenticationMethodCertificate;
            protocol.serverAddress = url;
            protocol.identityData = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"clientCert" ofType:@"p12"]];
            protocol.identityDataPassword = certPassword;
            protocol.localIdentifier = @"guna5@vpex.org";
            protocol.remoteIdentifier = @"EXONET@vpex.org";
            protocol.disconnectOnSleep = NO;
            protocol.useExtendedAuthentication = NO;
            
            //iOS does not allow changes to IKESecurityAssociationParameters
            [_myIKESecurityAssociationParameters setDiffieHellmanGroup:NEVPNIKEv2DiffieHellmanGroup14];
            [_myIKESecurityAssociationParameters setEncryptionAlgorithm:NEVPNIKEv2EncryptionAlgorithmAES256];
            [_myIKESecurityAssociationParameters setIntegrityAlgorithm:NEVPNIKEv2IntegrityAlgorithmSHA256];
            
           // [protocol setValue:_myIKESecurityAssociationParameters forKeyPath:@"IKESecurityAssociationParameters"];
            
        
            [self.manager setProtocol:protocol];
            [self.manager setOnDemandEnabled:NO];
            [self.manager setLocalizedDescription:@"xonet VPN"];
        
            // Enable VPN
            [[NEVPNManager sharedManager] setEnabled:YES];
            
            [self.manager saveToPreferencesWithCompletionHandler:^(NSError *error) {
                if(error) {
                    NSLog(@"Save error: %@", error);
                } else {
                    NSLog(@"Saved!");
                    NSError *startError;
                    [self.manager.connection startVPNTunnelAndReturnError:&startError];
                    if(startError) {
                        NSLog(@"Start error: %@", startError.localizedDescription);
                    }
                }
            }];
        }];
        //[self connect];
}


-(void)connect
{
    
    [self.manager loadFromPreferencesWithCompletionHandler:^(NSError *error) {
        NSError *startError;
        [self.manager.connection startVPNTunnelAndReturnError:&startError];
    
        if(startError) {
            NSLog(@"Start error: %@", startError.localizedDescription);
        }
    }];
}

-(void)vpnConnectionStatusChanged
{
    
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (NSData*)extractCertificateFromProfile
{
    
    
        /*
         It's easy to load the certificate using the code in -installCertificate
         It's more difficult to get the identity.
         We can get it from a .p12 file, but you need a passphrase:
         */
        
        NSString *p12Path = [[NSBundle mainBundle] pathForResource:@"clientCert" ofType:@"p12"];
        NSData *p12Data = [[NSData alloc] initWithContentsOfFile:p12Path];
        
        CFStringRef password = CFSTR("vp3x");
        const void *keys[] = { kSecImportExportPassphrase };
        const void *values[] = { password };
        CFDictionaryRef optionsDictionary = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
        CFArrayRef p12Items;
        
        OSStatus result = SecPKCS12Import((__bridge CFDataRef)p12Data, optionsDictionary, &p12Items);
        
        if(result == noErr) {
            CFDictionaryRef identityDict = CFArrayGetValueAtIndex(p12Items, 0);
            SecIdentityRef identityApp =(SecIdentityRef)CFDictionaryGetValue(identityDict,kSecImportItemIdentity);
            
            SecCertificateRef certRef;
            SecIdentityCopyCertificate(identityApp, &certRef);
            NSData *certificateData = (__bridge NSData*)certRef;
            return certificateData;
        }
        return nil;
    
}

@end
