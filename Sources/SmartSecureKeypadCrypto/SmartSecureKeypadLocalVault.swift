//
//  SmartSecureKeypadCrypto.swift
//  SmartSecureKeypad
//
//  SmartSecureKeypadCrypto 모듈의 목표 (Local-only)
//  - 서버 통신/검증을 전제로 하지 않는다.
//  - 숫자(PIN)로 “VaultKey(랜덤 대칭키)”를 보호하고,
//    VaultKey로 실제 데이터를 AES-GCM으로 암호화/복호화한다.
//
//  핵심 아이디어
//  1) 실제 데이터는 강한 랜덤키(VaultKey)로 AES-GCM 암호화한다.
//  2) VaultKey 자체는 PIN으로부터 유도한 PinKey로 "랩핑(감싸서 암호화)"해 저장한다.
//     => PIN이 바뀌면 데이터 재암호화 없이 VaultKey만 재랩핑하면 된다.
//
//  Created by INSEONG on 12/19/25.
//

import Foundation
import CryptoKit
import CommonCrypto

// MARK: - Sealed Payload (암호화된 데이터 컨테이너)

/// 로컬 저장형의 “암호화 결과” 컨테이너.
///
/// - combined:
///   CryptoKit의 AES.GCM.SealedBox가 제공하는 combined 표현.
///   데이터 레이아웃은 nonce + ciphertext + tag 이며,
///   기본 nonce 크기는 12바이트이다.  [oai_citation:2‡Apple Developer](https://developer.apple.com/documentation/cryptokit/aes/gcm/sealedbox/combined?utm_source=chatgpt.com)
///
/// - 이 타입은 "암호문"만 담는다.
///   (어떤 키로 암호화했는지, 어떤 AAD를 썼는지는 호출부/상위 계층에서 관리)
public struct SmartSecureKeypadSealedPayload: Sendable, Hashable, Codable {
    public let combined: Data

    public init(combined: Data) {
        self.combined = combined
    }
}

// MARK: - Wrapped Vault Key (PIN으로 보호된 VaultKey 메타데이터)

/// VaultKey(랜덤 대칭키)를 PIN으로 보호하기 위한 “랩핑 메타데이터”.
///
/// 앱은 이 구조체를 Keychain/파일/DB 어디든 저장할 수 있다.
///
/// 저장되는 항목
/// - version:
///   포맷 버전(향후 마이그레이션 대비)
/// - salt:
///   PIN 키 유도(KDF)에 쓰는 랜덤 salt (반드시 랜덤이어야 함)
/// - iterations:
///   PIN 키 유도 비용(클수록 느리지만 오프라인 추측 공격에 강해짐)
/// - wrappedVaultKeyCombined:
///   PinKey로 VaultKey를 AES-GCM으로 암호화(wrap)한 SealedBox.combined
///
/// 보안적으로 중요한 점
/// - PIN은 공간이 작으므로(예: 6자리=100만) 오프라인 추측 공격 대상이 된다.
/// - 그래서 KDF 비용(iterations) + 시도 제한/지연/잠금 정책이 사실상 필수다.
public struct SmartSecureKeypadWrappedVaultKey: Sendable, Hashable, Codable {
    public let version: Int
    public let salt: Data
    public let iterations: Int
    public let wrappedVaultKeyCombined: Data

    public init(version: Int = 1, salt: Data, iterations: Int, wrappedVaultKeyCombined: Data) {
        self.version = version
        self.salt = salt
        self.iterations = iterations
        self.wrappedVaultKeyCombined = wrappedVaultKeyCombined
    }
}

// MARK: - Local Vault

/// 로컬 Vault
///
/// - 역할:
///   1) Vault 생성 시 랜덤 VaultKey를 만들고,
///      PIN으로부터 유도한 PinKey로 VaultKey를 랩핑(wrap)하여 저장 가능한 형태로 만든다.
///   2) 저장된 wrapped 정보를 PIN으로 풀어(unlock) VaultKey를 복원한다.
///   3) VaultKey로 실제 데이터(Data)를 AES-GCM으로 seal/open 한다.
///
/// - 왜 VaultKey를 따로 두나?
///   PIN으로 곧바로 데이터를 암호화하면,
///   PIN 변경 시 "전체 데이터를 재암호화"해야 하거나 구조가 복잡해진다.
///   VaultKey를 분리하면 "VaultKey만 재랩핑"으로 해결된다.
///
/// - AAD(Associated Data):
///   AES-GCM은 암호화되지 않지만 “무결성 검증”에 포함될 추가 데이터를 받을 수 있다.
///   예: userId, docId, fileName 등 "변조되면 안 되는 메타"
///   CryptoKit에서는 seal/open의 authenticating 파라미터로 전달한다.
public struct SmartSecureKeypadLocalVault: Sendable {

    public enum VaultError: Error {
        /// PIN이 틀렸거나(대부분), wrapped 데이터가 변조/손상된 경우
        case invalidPIN

        /// wrapped 포맷이 유효하지 않거나 기대한 조건을 만족하지 못하는 경우
        case invalidWrappedKey

        /// CryptoKit 내부 오류 또는 예상치 못한 상태
        case cryptoFailure
    }

    /// 실제 데이터 암호화에 쓰는 “랜덤 대칭키”
    private let vaultKey: SymmetricKey

    private init(vaultKey: SymmetricKey) {
        self.vaultKey = vaultKey
    }

    // MARK: Create / Open (VaultKey 관리)

    /// 새 Vault 생성
    ///
    /// 동작:
    /// 1) 랜덤 VaultKey(256-bit) 생성
    /// 2) PIN 키 유도용 salt 생성(랜덤)
    /// 3) PinKey 유도(KDF)
    /// 4) VaultKey를 PinKey로 AES-GCM seal => wrappedVaultKeyCombined 생성
    ///
    /// Returns:
    /// - vault: 즉시 사용할 수 있는 Vault 인스턴스(메모리상 VaultKey 보유)
    /// - wrapped: 저장해야 하는 랩핑 메타데이터(다음에 열 때 필요)
    public static func createNew(
        pin: String,
        iterations: Int = 120_000
    ) throws -> (vault: SmartSecureKeypadLocalVault, wrapped: SmartSecureKeypadWrappedVaultKey) {

        // 1) 랜덤 VaultKey 생성 (데이터 암호화용)
        let vaultKey = SymmetricKey(size: .bits256)

        // 2) PIN 키 유도용 salt 생성(랜덤)
        // - salt는 랜덤이어야 동일 PIN이라도 PinKey가 달라져 추측 공격이 어려워짐
        let salt = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }

        // 3) PinKey 유도
        let pinKey = Self.derivePinKey(pin: pin, salt: salt, iterations: iterations)

        // 4) VaultKey를 PinKey로 랩핑(AES-GCM)
        let vaultKeyData = vaultKey.withUnsafeBytes { Data($0) }
        let sealed = try AES.GCM.seal(vaultKeyData, using: pinKey)

        guard let combined = sealed.combined else { throw VaultError.cryptoFailure }

        let wrapped = SmartSecureKeypadWrappedVaultKey(
            version: 1,
            salt: salt,
            iterations: iterations,
            wrappedVaultKeyCombined: combined
        )

        return (SmartSecureKeypadLocalVault(vaultKey: vaultKey), wrapped)
    }

    /// 저장된 wrapped 정보 + PIN으로 Vault 열기(unlock)
    ///
    /// 동작:
    /// 1) wrapped.salt/iterations로 PinKey 유도
    /// 2) wrappedVaultKeyCombined를 AES-GCM open => VaultKey 복원
    ///
    /// 실패 원인:
    /// - PIN이 틀림
    /// - wrapped 데이터가 변조됨(AEAD 인증 실패)
    /// - combined 포맷이 깨짐
    public static func open(
        pin: String,
        wrapped: SmartSecureKeypadWrappedVaultKey
    ) throws -> SmartSecureKeypadLocalVault {

        // 버전이 늘어나면 여기서 분기 처리
        guard wrapped.version == 1 else { throw VaultError.invalidWrappedKey }

        let pinKey = Self.derivePinKey(pin: pin, salt: wrapped.salt, iterations: wrapped.iterations)

        do {
            let sealedBox = try AES.GCM.SealedBox(combined: wrapped.wrappedVaultKeyCombined)
            let vaultKeyData = try AES.GCM.open(sealedBox, using: pinKey)
            let vaultKey = SymmetricKey(data: vaultKeyData)
            return SmartSecureKeypadLocalVault(vaultKey: vaultKey)
        } catch {
            // PIN 오류/변조/포맷 이상 모두 “열 수 없음”으로 처리
            throw VaultError.invalidPIN
        }
    }

    // MARK: Change PIN (VaultKey 재랩핑)

    /// PIN 변경
    ///
    /// 개념:
    /// - 실제 데이터는 VaultKey로 암호화되어 있으므로, PIN을 바꿀 때 데이터를 재암호화할 필요가 없다.
    /// - 대신, 기존 PIN으로 wrappedVaultKey를 열어 VaultKey를 복원한 뒤
    ///   새 PIN으로 다시 VaultKey를 랩핑(wrap)하여 `SmartSecureKeypadWrappedVaultKey`만 교체하면 된다.
    ///
    /// 동작:
    /// 1) oldPin + 기존 wrapped로 VaultKey 복원
    /// 2) newPin용 salt(랜덤) 생성
    /// 3) newPin으로 PinKey 유도(PBKDF2)
    /// 4) VaultKey를 새 PinKey로 AES-GCM seal하여 wrappedVaultKeyCombined 생성
    ///
    /// - Parameters:
    ///   - oldPin: 기존 PIN
    ///   - newPin: 새 PIN
    ///   - wrapped: 기존 `SmartSecureKeypadWrappedVaultKey`
    ///   - newIterations: 새 PIN용 KDF 비용(미지정 시 기존 iterations 사용)
    /// - Returns:
    ///   - 새 PIN으로 재랩핑된 `SmartSecureKeypadWrappedVaultKey`
    public static func changePIN(
        oldPin: String,
        newPin: String,
        wrapped: SmartSecureKeypadWrappedVaultKey,
        newIterations: Int? = nil
    ) throws -> SmartSecureKeypadWrappedVaultKey {

        // 버전이 늘어나면 여기서 분기 처리
        guard wrapped.version == 1 else { throw VaultError.invalidWrappedKey }

        // 1) 기존 PIN으로 VaultKey 복원
        let oldPinKey = Self.derivePinKey(pin: oldPin, salt: wrapped.salt, iterations: wrapped.iterations)

        let vaultKeyData: Data
        do {
            let sealedBox = try AES.GCM.SealedBox(combined: wrapped.wrappedVaultKeyCombined)
            vaultKeyData = try AES.GCM.open(sealedBox, using: oldPinKey)
        } catch {
            throw VaultError.invalidPIN
        }

        // 2) 새 PIN용 파라미터 결정
        let iterations = newIterations ?? wrapped.iterations

        // 3) 새 PIN용 salt 생성(랜덤)
        let newSalt = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }

        // 4) 새 PIN으로 PinKey 유도
        let newPinKey = Self.derivePinKey(pin: newPin, salt: newSalt, iterations: iterations)

        // 5) VaultKey를 새 PinKey로 재랩핑(AES-GCM)
        let sealed = try AES.GCM.seal(vaultKeyData, using: newPinKey)
        guard let combined = sealed.combined else { throw VaultError.cryptoFailure }

        return SmartSecureKeypadWrappedVaultKey(
            version: 1,
            salt: newSalt,
            iterations: iterations,
            wrappedVaultKeyCombined: combined
        )
    }

    /// 이미 열린 Vault 인스턴스를 기준으로 PIN 변경(재랩핑)
    ///
    /// - Note:
    ///   이 메서드는 현재 인스턴스가 보유한 VaultKey를 사용해 새 PIN으로 wrappedKey를 생성한다.
    ///   (즉, oldPin을 다시 요구하지 않는다 — 이미 unlock된 상태이기 때문)
    public func changePIN(
        newPin: String,
        iterations: Int = 120_000
    ) throws -> SmartSecureKeypadWrappedVaultKey {

        // 새 PIN용 salt 생성(랜덤)
        let newSalt = SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) }

        // 새 PIN으로 PinKey 유도
        let newPinKey = Self.derivePinKey(pin: newPin, salt: newSalt, iterations: iterations)

        // VaultKey를 새 PinKey로 랩핑(AES-GCM)
        let vaultKeyData = vaultKey.withUnsafeBytes { Data($0) }
        let sealed = try AES.GCM.seal(vaultKeyData, using: newPinKey)
        guard let combined = sealed.combined else { throw VaultError.cryptoFailure }

        return SmartSecureKeypadWrappedVaultKey(
            version: 1,
            salt: newSalt,
            iterations: iterations,
            wrappedVaultKeyCombined: combined
        )
    }

    // MARK: Seal / Open (실제 데이터 암호화/복호화)

    /// 임의 데이터(Data)를 VaultKey로 AES-GCM 암호화(seal)
    ///
    /// - Parameters:
    ///   - plaintext: 암호화할 원본 데이터
    ///   - aad: (선택) 무결성만 보장할 메타데이터
    ///     - 이 값은 암호문에 포함되지 않지만,
    ///       tag에 포함되어 변조되면 open이 실패한다.  [oai_citation:4‡Apple Developer](https://developer.apple.com/documentation/cryptokit/aes/gcm/seal%28_%3Ausing%3Anonce%3Aauthenticating%3A%29?utm_source=chatgpt.com)
    public func seal(
        _ plaintext: Data,
        aad: Data? = nil
    ) throws -> SmartSecureKeypadSealedPayload {
        let sealed = try AES.GCM.seal(
            plaintext,
            using: vaultKey,
            authenticating: aad ?? Data()
        )
        guard let combined = sealed.combined else { throw VaultError.cryptoFailure }
        return SmartSecureKeypadSealedPayload(combined: combined)
    }

    /// VaultKey로 AES-GCM 복호화(open)
    ///
    /// - Parameters:
    ///   - payload: seal 결과(SealedBox.combined)
    ///   - aad: seal 때 넣었던 aad와 "완전히 동일"해야 한다.
    public func open(
        _ payload: SmartSecureKeypadSealedPayload,
        aad: Data? = nil
    ) throws -> Data {
        let box = try AES.GCM.SealedBox(combined: payload.combined)
        return try AES.GCM.open(
            box,
            using: vaultKey,
            authenticating: aad ?? Data()
        )
    }

    // MARK: PIN -> PinKey (KDF)

    /// PIN에서 “PinKey”를 유도하는 함수 (KDF)
    ///
    /// 중요:
    /// - PIN은 공간이 작아서 단순 Hash(SHA256(pin)) 같은 방식은 빠른 대입 공격에 취약하다.
    /// - 따라서 "느린 KDF"를 적용해 오프라인 추측 공격 비용을 높이는 것이 필수다.
    ///
    /// 구현:
    /// - CommonCrypto의 PBKDF2-HMAC-SHA256을 사용해 32바이트 키를 유도한다.
    /// - `iterations`는 KDF 비용(=공격 비용)으로 직접 반영된다.
    ///
    /// 추가 권장:
    /// - 실패 횟수 제한/지연/잠금 정책은 상위 계층(Core/앱)에서 반드시 함께 적용하는 것이 좋다.
    private static func derivePinKey(
        pin: String,
        salt: Data,
        iterations: Int
    ) -> SymmetricKey {

        // 최소 안전장치: iterations가 너무 작으면 기본값으로 보정
        let rounds = max(iterations, 10_000)

        guard let pinData = pin.data(using: .utf8) else {
            // 거의 발생하지 않지만, 안전하게 랜덤키 반환
            return SymmetricKey(size: .bits256)
        }

        var derivedKey = Data(count: 32)
        let derivedKeyLength = derivedKey.count
        let saltLength = salt.count
        let pinLength = pinData.count

        let result: Int32 = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
            salt.withUnsafeBytes { saltBytes in
                pinData.withUnsafeBytes { pinBytes in
                    return CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),

                        // password (bytes + length)
                        pinBytes.bindMemory(to: Int8.self).baseAddress,
                        pinLength,

                        // salt (bytes + length)
                        saltBytes.bindMemory(to: UInt8.self).baseAddress,
                        saltLength,

                        // PRF = HMAC-SHA256
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),

                        // iterations
                        UInt32(rounds),

                        // output
                        derivedKeyBytes.bindMemory(to: UInt8.self).baseAddress,
                        derivedKeyLength
                    )
                }
            }
        }

        // kCCSuccess(0) 이외는 실패
        guard result == kCCSuccess else {
            return SymmetricKey(size: .bits256)
        }

        return SymmetricKey(data: derivedKey)
    }
}
