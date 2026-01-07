//
//  SmartSecureKeypadPINFlowViewModel.swift
//  SmartSecureKeypad
//
//  Created by INSEONG on 1/5/26.
//

//
//  SmartSecureKeypadPINFlowViewModel.swift
//  SmartSecureKeypad
//
//  Created by INSEONG on 1/5/26.
//

import Foundation
import Combine

// MARK: - Crypto Bridge (Core-level protocol)

/// Core는 Crypto 타깃에 의존하지 않도록, 필요한 동작만 프로토콜로 추상화한다.
///
/// Crypto 타깃에서 어댑터(`SmartSecureKeypadPINFlowCryptoAdapter`)로 구현해 주입하면 된다.
public protocol SmartSecureKeypadPINFlowCrypto: Sendable {
    func createPIN(_ pin: String, iterations: Int) throws
    func unlock(pin: String) throws
    func changePIN(oldPIN: String, newPIN: String) throws
}

// MARK: - Core Error

/// PIN Flow에서 UI에 노출하기 쉬운 형태로 정리한 Core 에러.
public struct SmartSecureKeypadPINFlowError: Error, Sendable, Equatable {
    public enum Code: Sendable, Equatable {
        case invalidPINFormat
        case weakPIN
        case pinMismatch
        case locked
        case notRegistered
        case cryptoFailure
        case unknown
    }

    public let code: Code
    public let message: String
    public let lockedUntil: Date?

    public init(code: Code, message: String, lockedUntil: Date? = nil) {
        self.code = code
        self.message = message
        self.lockedUntil = lockedUntil
    }
}

// MARK: - Policy (Core-level)

/// Core에서 최소한으로 제공하는 PIN 정책.
public struct SmartSecureKeypadPINPolicy: Sendable, Equatable {
    public enum WeakRule: Sendable, Equatable {
        case none
        case recommended
    }

    public let length: Int
    public let weakRule: WeakRule

    public init(length: Int = 6, weakRule: WeakRule = .recommended) {
        self.length = length
        self.weakRule = weakRule
    }

    /// 공백 제거 + 숫자/길이 검증 + (옵션) 약한 PIN 룰 검증
    public func normalizedAndValidate(pin: String) throws -> String {
        let normalized = pin.trimmingCharacters(in: .whitespacesAndNewlines)
        try validateFormatOnly(pin: normalized)

        if weakRule == .recommended, Self.isWeakRecommended(normalized) {
            throw SmartSecureKeypadPINFlowError(
                code: .weakPIN,
                message: "너무 쉬운 PIN입니다. 다른 PIN을 사용해 주세요."
            )
        }
        return normalized
    }

    /// verify/oldPIN 단계에서 사용하는 최소 형식 검증
    public func validateFormatOnly(pin: String) throws {
        guard pin.count == length else {
            throw SmartSecureKeypadPINFlowError(
                code: .invalidPINFormat,
                message: "PIN 길이는 \(length)자리여야 합니다."
            )
        }
        guard pin.unicodeScalars.allSatisfy({ CharacterSet.decimalDigits.contains($0) }) else {
            throw SmartSecureKeypadPINFlowError(
                code: .invalidPINFormat,
                message: "PIN은 숫자만 입력할 수 있습니다."
            )
        }
    }

    /// 아주 흔한 약한 PIN만 최소 차단 (필요하면 앱에서 확장)
    private static func isWeakRecommended(_ pin: String) -> Bool {
        // 동일 숫자 반복(000000, 111111)
        if Set(pin).count == 1 { return true }

        // 연속 증가/감소(012345, 123456, 654321)
        let digits = pin.compactMap { Int(String($0)) }
        guard digits.count == pin.count else { return false }

        let inc = zip(digits, digits.dropFirst()).allSatisfy { $1 - $0 == 1 }
        let dec = zip(digits, digits.dropFirst()).allSatisfy { $0 - $1 == 1 }
        if inc || dec { return true }

        // 흔한 패턴
        let common: Set<String> = [
            "000000","111111","222222","333333","444444","555555","666666","777777","888888","999999",
            "012345","123456","234567","345678","456789","987654","876543","765432","654321","543210"
        ]
        return common.contains(pin)
    }
}

// MARK: - ViewModel

@MainActor
public final class SmartSecureKeypadPINFlowViewModel: ObservableObject {

    // MARK: - Mode / Step

    /// PIN 플로우 모드
    public enum Mode: Sendable, Equatable {
        /// 신규 PIN 등록(보통 2회 입력 확인)
        case register
        /// 기존 PIN 검증(1회 입력)
        case verify
        /// PIN 변경(기존 PIN 검증 -> 신규 PIN 등록)
        case change
    }

    /// 내부 단계(화면 상태)
    public enum Step: Sendable, Equatable {
        /// register/verify에서 첫 입력 단계
        case enterPIN
        /// 신규 PIN 2회 확인 단계 (register/change에서 사용)
        case confirmNewPIN
        /// change에서 첫 단계(기존 PIN)
        case enterOldPIN
        /// change에서 신규 PIN 입력
        case enterNewPIN
        /// 완료
        case done
    }

    // MARK: - Published UI State

    /// 현재 모드
    @Published public private(set) var mode: Mode

    /// 현재 단계
    @Published public private(set) var step: Step

    /// 현재 입력 버퍼(숫자 문자열)
    /// - PINEntryView와 바인딩해도 되고, 앱이 자체 버퍼를 써도 된다.
    @Published public var pin: String = ""

    /// 신규 PIN 1차 입력 보관(2회 확인용)
    @Published public private(set) var newPINFirstEntry: String? = nil

    /// 에러 메시지(표시용)
    @Published public var errorMessage: String? = nil

    /// 락아웃 표시용(옵트인). nil이면 표시 안 함.
    @Published public var lockedUntil: Date? = nil

    /// 안내 문구(상단 title/message 구성용)
    @Published public private(set) var title: String = ""
    @Published public private(set) var message: String = ""

    // MARK: - Config

    /// PIN 최대 길이(키패드 완료 기준)
    public let maxLength: Int

    /// PIN 정책(형식/약한 PIN 룰)
    /// - verify 단계는 정책이 바뀌어도 기존 PIN이 유효할 수 있으므로
    ///   "약한 PIN" 차단은 적용하지 않고 형식만 최소 검증한다.
    public let pinPolicy: SmartSecureKeypadPINPolicy
    
    private let crypto: any SmartSecureKeypadPINFlowCrypto
    private let registerIterations: Int

    // MARK: - Callbacks

    public var onVerifySuccess: (() -> Void)?
    public var onRegisterSuccess: (() -> Void)?
    public var onChangeSuccess: (() -> Void)?

    // MARK: - Change Flow Storage

    /// change 모드에서 기존 PIN 보관
    private var oldPINForChange: String? = nil

    // MARK: - Init

    public init(
        mode: Mode,
        crypto: any SmartSecureKeypadPINFlowCrypto,
        maxLength: Int = 6,
        pinPolicy: SmartSecureKeypadPINPolicy = .init(length: 6, weakRule: .recommended),
        registerIterations: Int = 120_000
    ) {
        self.mode = mode
        self.crypto = crypto
        self.maxLength = maxLength
        self.pinPolicy = pinPolicy
        self.registerIterations = registerIterations

        switch mode {
        case .register:
            self.step = .enterPIN
        case .verify:
            self.step = .enterPIN
        case .change:
            self.step = .enterOldPIN
        }

        refreshCopy()
    }

    // MARK: - Public APIs (UI 연결)

    /// 키 입력이 들어오기 시작하면 에러/락아웃 문구를 지우고 싶을 때 호출.
    /// (PINEntryView의 `onKey`에서 호출하는 것을 권장)
    public func userDidInputKey() {
        clearErrorIfNeeded()
    }

    /// PIN 입력이 완료(길이 도달)되었을 때 호출.
    /// - UI는 이 메서드만 호출하면 되고, 내부에서 모드/단계에 맞게 처리한다.
    public func handleCompletedPIN(_ pin: String) {
        self.pin = pin
        submitIfComplete()
    }

    /// 화면에서 “다시 입력” 버튼 같은 것을 눌렀을 때
    public func resetCurrentStep() {
        pin = ""
        errorMessage = nil
        lockedUntil = nil
        refreshCopy()
    }

    /// 전체 초기화(모드 유지)
    public func clear() {
        pin = ""
        newPINFirstEntry = nil
        oldPINForChange = nil
        errorMessage = nil
        lockedUntil = nil
        refreshCopy()
    }

    /// 모드 전환(화면 전환 시 호출)
    public func setMode(_ mode: Mode) {
        self.mode = mode
        errorMessage = nil
        lockedUntil = nil
        pin = ""
        newPINFirstEntry = nil
        oldPINForChange = nil

        switch mode {
        case .register:
            step = .enterPIN
        case .verify:
            step = .enterPIN
        case .change:
            step = .enterOldPIN
        }

        refreshCopy()
    }

    // MARK: - Flow Core

    private func submitIfComplete() {
        do {
            switch mode {
            case .verify:
                try verifyFlow(pin: pin)
            case .register:
                try registerFlow(pin: pin)
            case .change:
                try changeFlow(pin: pin)
            }
        } catch {
            handle(error: error)
        }
    }

    private func verifyFlow(pin: String) throws {
        // verify는 약한 PIN 차단은 적용하지 않고 형식만
        try pinPolicy.validateFormatOnly(pin: pin)
        try crypto.unlock(pin: pin)
        pinSuccessCleanup()
        onVerifySuccess?()
    }

    private func registerFlow(pin: String) throws {
        switch step {
        case .enterPIN:
            let normalized = try pinPolicy.normalizedAndValidate(pin: pin)
            newPINFirstEntry = normalized
            self.pin = ""
            step = .confirmNewPIN
            refreshCopy()

        case .confirmNewPIN:
            let normalized = try pinPolicy.normalizedAndValidate(pin: pin)
            guard let first = newPINFirstEntry else {
                newPINFirstEntry = nil
                self.pin = ""
                step = .enterPIN
                refreshCopy()
                return
            }
            guard normalized == first else {
                throw SmartSecureKeypadPINFlowError(
                    code: .pinMismatch,
                    message: "PIN이 일치하지 않습니다. 다시 입력해 주세요."
                )
            }

            try crypto.createPIN(normalized, iterations: registerIterations)
            pinSuccessCleanup()
            step = .done
            refreshCopy()
            onRegisterSuccess?()

        default:
            clear()
            step = .enterPIN
            refreshCopy()
        }
    }

    private func changeFlow(pin: String) throws {
        switch step {
        case .enterOldPIN:
            try pinPolicy.validateFormatOnly(pin: pin)
            oldPINForChange = pin
            self.pin = ""
            step = .enterNewPIN
            refreshCopy()

        case .enterNewPIN:
            let normalizedNew = try pinPolicy.normalizedAndValidate(pin: pin)
            newPINFirstEntry = normalizedNew
            self.pin = ""
            step = .confirmNewPIN
            refreshCopy()

        case .confirmNewPIN:
            let normalizedConfirm = try pinPolicy.normalizedAndValidate(pin: pin)
            guard let newFirst = newPINFirstEntry else {
                self.pin = ""
                step = .enterNewPIN
                refreshCopy()
                return
            }
            guard normalizedConfirm == newFirst else {
                throw SmartSecureKeypadPINFlowError(
                    code: .pinMismatch,
                    message: "PIN이 일치하지 않습니다. 다시 입력해 주세요."
                )
            }
            guard let oldPIN = oldPINForChange else {
                clear()
                mode = .change
                step = .enterOldPIN
                refreshCopy()
                return
            }

            try crypto.changePIN(oldPIN: oldPIN, newPIN: normalizedConfirm)
            pinSuccessCleanup()
            step = .done
            refreshCopy()
            onChangeSuccess?()

        default:
            clear()
            mode = .change
            step = .enterOldPIN
            refreshCopy()
        }
    }

    // MARK: Error handling

    private func handle(error: Error) {
        if let e = error as? SmartSecureKeypadPINFlowError {
            lockedUntil = e.lockedUntil
            errorMessage = e.message
            pin = ""
        } else {
            lockedUntil = nil
            errorMessage = "Unknown error"
            pin = ""
        }
        refreshCopy()
    }

    private func clearErrorIfNeeded() {
        if errorMessage != nil || lockedUntil != nil {
            errorMessage = nil
            lockedUntil = nil
            refreshCopy()
        }
    }

    private func pinSuccessCleanup() {
        errorMessage = nil
        lockedUntil = nil
        pin = ""
        newPINFirstEntry = nil
        oldPINForChange = nil
    }

    // MARK: Copy

    private func refreshCopy() {
        switch mode {
        case .verify:
            title = "PIN 확인"
            message = "PIN을 입력해 주세요."

        case .register:
            title = "PIN 등록"
            switch step {
            case .enterPIN:
                message = "새 PIN을 입력해 주세요."
            case .confirmNewPIN:
                message = "PIN을 한 번 더 입력해 주세요."
            case .done:
                message = "PIN 등록이 완료되었습니다."
            default:
                message = "PIN을 입력해 주세요."
            }

        case .change:
            title = "PIN 변경"
            switch step {
            case .enterOldPIN:
                message = "기존 PIN을 입력해 주세요."
            case .enterNewPIN:
                message = "새 PIN을 입력해 주세요."
            case .confirmNewPIN:
                message = "새 PIN을 한 번 더 입력해 주세요."
            case .done:
                message = "PIN 변경이 완료되었습니다."
            default:
                message = "PIN을 입력해 주세요."
            }
        }
    }
}
