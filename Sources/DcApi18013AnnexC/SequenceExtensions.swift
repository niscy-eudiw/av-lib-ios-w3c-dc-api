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

public extension Sequence {
  
  func asyncCompactMap<T>(
    _ transform: @Sendable (Element) async throws -> T?
  ) async rethrows -> [T] {
    var values = [T]()
    
    for element in self {
      if let value = try await transform(element) {
        values.append(value)
      }
    }
    
    return values
  }
}

extension Array where Element == DocClaimMetadata {
    func convertToCborClaimMetadata(_ uiCulture: String?) -> (displayNames: [NameSpace: [String: String]], mandatory: [NameSpace: [String: Bool]]) {
        guard allSatisfy({ $0.claimPath.count > 1 }) else { return ([:], [:]) } // sanity check
        let dictNs = Dictionary(grouping: self, by: { $0.claimPath[0]})
        let dictNsAndKeys = dictNs.mapValues { Dictionary(grouping: $0, by: { $0.claimPath[1]}) } // group by namespace and key
        let displayNames = dictNsAndKeys.mapValues { nsv in nsv.compactMapValues { kv in kv.first?.display?.getName(uiCulture) } }
        let mandatory = dictNsAndKeys.mapValues { nsv in nsv.compactMapValues { kv in kv.first?.isMandatory } }
        return (displayNames, mandatory)
    }
}
