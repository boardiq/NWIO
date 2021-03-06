//
//  NWIODeflate.h
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

#import "NWIOTransform.h"


/**
 * Applies zlib's deflate algorithm.
 *
 * This transform uses the default deflate and inflate configuration, without allowing further configuration. The implementation functions mostly as an example on how to use zlib in an NWIOTransform.
 */
@interface NWIODeflateTransform : NWIOTransform

/**
 * The length of the substitute buffer that is allocated (and reused) when a NULL buffer is passed as toBuffer.
 */
@property (nonatomic, assign) NSUInteger substituteBufferLength;

@end


/**
 * A transform stream based on the deflate transform.
 */
@interface NWIODeflateStream : NWIOTransformStream
@end
