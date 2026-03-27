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

import Foundation
import MdocDataModel18013
import SwiftCBOR

/// can be used to send request for processing to other app or web service
public struct DcApiExtensionRequest: Sendable, Codable {
	public var rawRequestData: Data
	public var originUrl: String?

	public init(rawRequestData: Data, originUrl: String?) {
		self.rawRequestData = rawRequestData
		self.originUrl = originUrl
	}
	
	// need extension request only when it contains zk-system-specs
	public init?(deviceRequest: DeviceRequest, rawRequestData: Data, originUrl: String?) {
		guard deviceRequest.docRequests
			.first(where: { $0.itemsRequest.requestInfo?.zkRequest?.systemSpecs != nil }) != nil, originUrl != nil else { return nil }
		self.rawRequestData = rawRequestData
		self.originUrl = originUrl
	}
}
