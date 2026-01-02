//
//  SmartSecureKeypadCryptoError.swift
//  SmartSecureKeypad
//
//  Created by INSEONG on 1/2/26.
//

import Foundation
import Security

/// SmartSecureKeypadCrypto 모듈에서 발생 가능한 오류를 한 곳에 모은 타입.
///
/// 설계 의도:
/// - LocalVault / KeychainStore / LockoutPolicy 등 파일이 분리되면서
///   에러 타입도 분산되기 쉬우므로, 외부(호스트 앱)에서 처리하기 쉽게 통합한다.
public enum SmartSecureKeypadCryptoError: Error, Sendable, Equatable {

    // MARK: - Local Vault

    /// PIN이 틀렸거나, wrapped 데이터가 변조/손상되어 VaultKey 복원이 실패한 경우
    case invalidPIN

    /// wrapped 포맷이 유효하지 않거나 기대한 조건을 만족하지 못하는 경우
    /// (예: version mismatch)
    case invalidWrappedKey

    /// CryptoKit / CommonCrypto 내부 오류 또는 예상치 못한 상태
    case cryptoFailure

    // MARK: - Storage / Policy

    /// Keychain 저장/로드/삭제 실패 등 저장소 관련 오류
    case storageFailure(status: OSStatus)

    /// 잠금(락아웃) 상태로 인해 시도를 막아야 하는 경우
    case locked(until: Date)

    /// PIN 정책 위반 (길이, 숫자 여부, 약한 PIN 등)
    case invalidPINFormat(reason: String)

    // MARK: - Convenience

    /// 디버깅 및 로그 출력에 유용한 간단 메시지
    public var message: String {
        switch self {
        case .invalidPIN:
            return "Invalid PIN"
        case .invalidWrappedKey:
            return "Invalid wrapped key"
        case .cryptoFailure:
            return "Crypto failure"
        case .storageFailure(let status):
            return "Keychain storage failure (OSStatus: \(status))"
        case .locked(let until):
            return "Locked until \(until)"
        case .invalidPINFormat(let reason):
            return "Invalid PIN format: \(reason)"
        }
    }
}
