//
//  DcApiRequest.swift
//  DcApi18013AnnexC
//
//  Created by ffeli on 27/03/2026.
//

import Foundation

public class DcApiRequest: NSCoding {
	private enum CodingKeys {
		static let rawRequestData = "rawRequestData"
		static let originUrl = "originUrl"
	}

	public init(rawRequestData: Data, originUrl: String?) {
		self.rawRequestData = rawRequestData
		self.originUrl = originUrl
	}

	public func encode(with coder: NSCoder) {
		coder.encode(rawRequestData, forKey: CodingKeys.rawRequestData)
		coder.encode(originUrl, forKey: CodingKeys.originUrl)
	}

	public required init?(coder: NSCoder) {
		guard let rawRequestData = coder.decodeObject(forKey: CodingKeys.rawRequestData) as? Data else {
			return nil
		}
		self.rawRequestData = rawRequestData
		self.originUrl = coder.decodeObject(forKey: CodingKeys.originUrl) as? String
	}

	public var rawRequestData: Data
	public var originUrl: String?
}
