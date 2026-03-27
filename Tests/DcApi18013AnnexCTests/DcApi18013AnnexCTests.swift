/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import Testing
@testable import DcApi18013AnnexC
import Foundation

@Test func dcApiRequestNSCodingRoundTripWithOriginUrl() throws {
    let request = DcApiRequest(rawRequestData: Data([0x01, 0x02, 0x03]), originUrl: "https://example.org")
    let archived = try NSKeyedArchiver.archivedData(withRootObject: request, requiringSecureCoding: true)

    let decodedObject = try NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(archived)
    let decodedRequest = try #require(decodedObject as? DcApiRequest)

    #expect(decodedRequest.rawRequestData == request.rawRequestData)
    #expect(decodedRequest.originUrl == request.originUrl)
}

@Test func dcApiRequestNSCodingRoundTripWithNilOriginUrl() throws {
    let request = DcApiRequest(rawRequestData: Data([0xAA, 0xBB]), originUrl: nil)
    let archived = try NSKeyedArchiver.archivedData(withRootObject: request, requiringSecureCoding: false)

    let decodedObject = try NSKeyedUnarchiver.unarchiveTopLevelObjectWithData(archived)
    let decodedRequest = try #require(decodedObject as? DcApiRequest)

    #expect(decodedRequest.rawRequestData == request.rawRequestData)
    #expect(decodedRequest.originUrl == nil)
}
