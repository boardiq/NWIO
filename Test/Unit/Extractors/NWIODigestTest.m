//
//  NWIODigestTest.m
//  NWIO
//
//  Copyright 2011 Noodlewerk
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//  http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
//

#import "NWIODigestTest.h"
#import "NWIO.h"
#import "NWIOTestTools.h"

@implementation NWIODigestTest

- (void)test {
    NSData *data = [@"for the specific language governing permissions" dataUsingEncoding:NSUTF8StringEncoding];
    NWIODigestExtract *extract = [[NWIODigestExtract alloc] init];
    [extract extractFrom:data.bytes length:data.length];
    NSData *checkData = DATA(@"cc34c804e5cabb30bd73689049c2834557a70638");
    NSAssert([extract.digest isEqualToData:checkData], @"Should be equal: %@==%@", extract.digest, checkData);
}

@end
