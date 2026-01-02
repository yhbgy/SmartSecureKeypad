
//
//  SmartSecureKeypadPINPolicy.swift
//  SmartSecureKeypad
//
//  Created by INSEONG on 1/2/26.
//

import Foundation

/// PIN 입력 규칙(정책)을 정의하는 타입.
///
/// 목적:
/// - UI/Core/앱에서 중복 검증을 줄이고, PIN 규칙을 한 곳에서 일관되게 관리한다.
/// - 로컬 전용 Vault 시나리오에서 PIN은 오프라인 추측 공격 대상이 되기 쉬우므로,
///   최소한의 형식 검증(길이/숫자 여부/약한 PIN 차단 등)을 제공한다.
///
/// 권장:
/// - 기본값(6자리 + recommended)을 그대로 사용해도 무난하다.
/// - 서비스 정책에 따라 약한 PIN 룰을 강화/완화할 수 있다.
public struct SmartSecureKeypadPINPolicy: Sendable, Equatable {

    // MARK: - Weak PIN Rules

    /// 약한 PIN 차단 규칙
    public enum WeakPINRule: Sendable, Equatable {
        /// 약한 PIN 체크를 하지 않음
        case none

        /// 같은 숫자 반복(예: 000000, 111111) 차단
        case disallowAllSame

        /// 단순 증가/감소 수열(예: 123456, 654321) 차단
        case disallowStraightSequence

        /// 기본 권장(위 두 개 모두)
        case recommended

        /// 커스텀(blacklist + 옵션 룰)
        /// - blacklist: 서비스에서 금지할 PIN 목록 (예: 생년월일, 전화번호 뒷자리 등)
        /// - disallowAllSame: 같은 숫자 반복 차단 여부
        /// - disallowStraight: 직선 수열 차단 여부
        case custom(
            blacklist: Set<String>,
            disallowAllSame: Bool,
            disallowStraight: Bool
        )
    }

    // MARK: - Configuration

    /// 고정 PIN 길이(예: 6)
    public let length: Int

    /// 약한 PIN 차단 규칙
    public let weakRule: WeakPINRule

    public init(length: Int = 6, weakRule: WeakPINRule = .recommended) {
        self.length = length
        self.weakRule = weakRule
    }

    // MARK: - Validation

    /// PIN 문자열이 정책을 만족하는지 검증한다.
    ///
    /// - Throws: `SmartSecureKeypadCryptoError.invalidPINFormat`
    public func validate(pin: String) throws {
        // 1) 길이
        guard pin.count == length else {
            throw SmartSecureKeypadCryptoError.invalidPINFormat(reason: "PIN length must be \(length)")
        }

        // 2) 숫자만
        guard pin.unicodeScalars.allSatisfy({ CharacterSet.decimalDigits.contains($0) }) else {
            throw SmartSecureKeypadCryptoError.invalidPINFormat(reason: "PIN must contain digits only")
        }

        // 3) 약한 PIN 룰
        try validateWeakness(pin: pin)
    }

    /// Validate + 정규화(현재는 trim만)
    /// - Note: 정책에 따라 공백/기타 문자를 허용하지 않으므로, 실제로는 validate만 호출해도 충분.
    public func normalizedAndValidate(pin: String) throws -> String {
        let trimmed = pin.trimmingCharacters(in: .whitespacesAndNewlines)
        try validate(pin: trimmed)
        return trimmed
    }

    // MARK: - Weakness Checks

    private func validateWeakness(pin: String) throws {
        switch weakRule {
        case .none:
            return

        case .disallowAllSame:
            if isAllSame(pin) {
                throw SmartSecureKeypadCryptoError.invalidPINFormat(reason: "Weak PIN: all digits are the same")
            }

        case .disallowStraightSequence:
            if isStraightSequence(pin) {
                throw SmartSecureKeypadCryptoError.invalidPINFormat(reason: "Weak PIN: straight sequence")
            }

        case .recommended:
            if isAllSame(pin) {
                throw SmartSecureKeypadCryptoError.invalidPINFormat(reason: "Weak PIN: all digits are the same")
            }
            if isStraightSequence(pin) {
                throw SmartSecureKeypadCryptoError.invalidPINFormat(reason: "Weak PIN: straight sequence")
            }

        case .custom(let blacklist, let disallowAllSame, let disallowStraight):
            if blacklist.contains(pin) {
                throw SmartSecureKeypadCryptoError.invalidPINFormat(reason: "Weak PIN: blacklisted")
            }
            if disallowAllSame, isAllSame(pin) {
                throw SmartSecureKeypadCryptoError.invalidPINFormat(reason: "Weak PIN: all digits are the same")
            }
            if disallowStraight, isStraightSequence(pin) {
                throw SmartSecureKeypadCryptoError.invalidPINFormat(reason: "Weak PIN: straight sequence")
            }
        }
    }

    private func isAllSame(_ pin: String) -> Bool {
        guard let first = pin.first else { return false }
        return pin.allSatisfy { $0 == first }
    }

    /// 123456 / 654321 같은 단순 증가/감소 수열인지
    private func isStraightSequence(_ pin: String) -> Bool {
        let digits = pin.compactMap { $0.wholeNumberValue }
        guard digits.count == length else { return false }

        var inc = true
        var dec = true
        for i in 1..<digits.count {
            inc = inc && (digits[i] == digits[i - 1] + 1)
            dec = dec && (digits[i] == digits[i - 1] - 1)
        }
        return inc || dec
    }
}

