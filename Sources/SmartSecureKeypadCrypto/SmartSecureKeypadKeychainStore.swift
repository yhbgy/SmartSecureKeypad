//
//  SmartSecureKeypadKeychainStore.swift
//  SmartSecureKeypad
//
//  Keychain-backed storage for SmartSecureKeypadCrypto.
//  - Stores Codable values as JSON Data.
//  - Provides convenience APIs for WrappedVaultKey.
//
//  Created by INSEONG on 12/19/25.
//

import Foundation
import Security

/// SmartSecureKeypadCrypto에서 사용하는 Keychain 저장소 래퍼.
///
/// 설계 목표:
/// - LocalVault(순수 크립토)와 저장소(Keychain) 접근을 분리한다.
/// - `Codable` 값을 JSON으로 인코딩하여 Keychain에 저장한다.
/// - 호스트 앱은 service/account만 정하면 쉽게 저장/로드/삭제할 수 있다.
public struct SmartSecureKeypadKeychainStore: Sendable {

    // MARK: - Configuration

    /// Keychain item을 구분하는 service.
    /// - 기본값은 라이브러리명으로 두되, 앱에서 번들ID 기반 문자열로 바꿔도 좋다.
    public let service: String

    /// Keychain 접근성(보호 수준)
    /// - `.whenPasscodeSetThisDeviceOnly` : 기기 패스코드 설정 필수 + 이 기기에서만
    /// - `.whenUnlockedThisDeviceOnly`    : 잠금 해제 상태에서만 + 이 기기에서만
    public enum Accessibility: Sendable {
        case whenUnlockedThisDeviceOnly
        case whenPasscodeSetThisDeviceOnly

        fileprivate var secAttrValue: CFString {
            switch self {
            case .whenUnlockedThisDeviceOnly:
                return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            case .whenPasscodeSetThisDeviceOnly:
                return kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly
            }
        }
    }

    public let accessibility: Accessibility

    public init(
        service: String = "SmartSecureKeypad",
        accessibility: Accessibility = .whenPasscodeSetThisDeviceOnly
    ) {
        self.service = service
        self.accessibility = accessibility
    }

    // MARK: - Public API (Codable)

    /// Codable 값을 Keychain에 저장한다. (기존 값이 있으면 업데이트)
    public func saveCodable<T: Codable>(_ value: T, account: String) throws {
        let data = try JSONEncoder().encode(value)
        try saveData(data, account: account)
    }

    /// Codable 값을 Keychain에서 로드한다. 없으면 nil.
    public func loadCodable<T: Codable>(_ type: T.Type, account: String) throws -> T? {
        guard let data = try loadData(account: account) else { return nil }
        return try JSONDecoder().decode(type, from: data)
    }

    /// Keychain에서 삭제한다. (없어도 성공 처리)
    public func delete(account: String) throws {
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        if status == errSecSuccess || status == errSecItemNotFound {
            return
        }
        throw SmartSecureKeypadCryptoError.storageFailure(status: status)
    }

    // MARK: - Convenience (WrappedVaultKey)

    /// 라이브러리 기본 account에 WrappedVaultKey 저장
    public func saveWrappedVaultKey(
        _ wrapped: SmartSecureKeypadWrappedVaultKey,
        account: String = SmartSecureKeypadKeychainStoreDefaults.wrappedVaultKeyAccount
    ) throws {
        try saveCodable(wrapped, account: account)
    }

    /// 라이브러리 기본 account에서 WrappedVaultKey 로드
    public func loadWrappedVaultKey(
        account: String = SmartSecureKeypadKeychainStoreDefaults.wrappedVaultKeyAccount
    ) throws -> SmartSecureKeypadWrappedVaultKey? {
        try loadCodable(SmartSecureKeypadWrappedVaultKey.self, account: account)
    }

    /// 라이브러리 기본 account에서 WrappedVaultKey 삭제
    public func deleteWrappedVaultKey(
        account: String = SmartSecureKeypadKeychainStoreDefaults.wrappedVaultKeyAccount
    ) throws {
        try delete(account: account)
    }

    // MARK: - Internal Data API

    private func saveData(_ data: Data, account: String) throws {
        // 존재 여부 확인
        let exists = (try loadData(account: account)) != nil

        if exists {
            // Update
            let query = baseQuery(account: account)
            let attributes: [String: Any] = [kSecValueData as String: data]
            let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
            guard status == errSecSuccess else {
                throw SmartSecureKeypadCryptoError.storageFailure(status: status)
            }
        } else {
            // Add
            var query = baseQuery(account: account)
            query[kSecValueData as String] = data
            query[kSecAttrAccessible as String] = accessibility.secAttrValue

            let status = SecItemAdd(query as CFDictionary, nil)
            guard status == errSecSuccess else {
                throw SmartSecureKeypadCryptoError.storageFailure(status: status)
            }
        }
    }

    private func loadData(account: String) throws -> Data? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)

        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess else {
            throw SmartSecureKeypadCryptoError.storageFailure(status: status)
        }
        return item as? Data
    }

    private func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }
}

/// KeychainStore의 기본 account 명을 모아둔 네임스페이스
public enum SmartSecureKeypadKeychainStoreDefaults {
    /// WrappedVaultKey를 저장하는 기본 account
    public static let wrappedVaultKeyAccount = "wrappedVaultKey"

    /// LockoutPolicy 상태를 저장하는 기본 account
    public static let lockoutStateAccount = "lockoutState"
}
