//
//  SmartSecureKeypadPINFlowViewModel.swift
//  SmartSecureKeypad
//
//  Created by INSEONG on 1/5/26.
//

/// PIN 등록/검증/변경 플로우 상태 머신 (Core 성격)
///
/// 설계 의도
/// - UI는 키패드/도트/문구를 자유롭게 꾸밀 수 있어야 함
/// - 플로우(등록/검증/변경)에서 실수하기 쉬운 상태 전환/정책 검증/에러 매핑을 Core에서 일원화
///
/// 사용 방식 (권장)
/// - UI는 `SmartSecureKeypadPINEntryView`(또는 커스텀 키패드)에서 입력을 받고
/// - 키 입력 시: `viewModel.userDidInputKey()` 호출(에러/락아웃 문구를 입력과 함께 초기화)
/// - PIN 완성 시: `viewModel.handleCompletedPIN(pin)` 호출(모드/단계에 맞게 내부에서 처리)
///
/// NOTE
/// - lockout은 Crypto에서 기본 OFF(0초 테이블)일 수 있으므로,
///   앱에서 lockout을 활성화한 경우에만 `lockedUntil`이 설정된다.
import Foundation
import Combine
import SmartSecureKeypadCrypto

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

    /// Crypto Facade
    private let manager: SmartSecureKeypadPINVaultManager

    /// 등록 시 PBKDF2 iterations
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
        manager: SmartSecureKeypadPINVaultManager = .init(),
        maxLength: Int = 6,
        pinPolicy: SmartSecureKeypadPINPolicy = .init(length: 6, weakRule: .recommended),
        registerIterations: Int = 120_000
    ) {
        self.mode = mode
        self.manager = manager
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
        // verify는 “형식” 최소 검증만 (숫자/길이)
        try validateFormatOnly(pin: pin)

        // unlock 성공/실패(락아웃 포함)는 manager가 처리
        try manager.unlock(pin: pin)
        pinSuccessCleanup()
        onVerifySuccess?()
    }

    private func registerFlow(pin: String) throws {
        switch step {
        case .enterPIN:
            // 신규 등록은 정책(약한 PIN 포함) 적용
            let normalized = try pinPolicy.normalizedAndValidate(pin: pin)
            newPINFirstEntry = normalized
            self.pin = ""
            step = .confirmNewPIN
            refreshCopy()

        case .confirmNewPIN:
            let normalized = try pinPolicy.normalizedAndValidate(pin: pin)
            guard let first = newPINFirstEntry else {
                // 이상 상태 -> 처음부터
                newPINFirstEntry = nil
                self.pin = ""
                step = .enterPIN
                refreshCopy()
                return
            }
            guard normalized == first else {
                errorMessage = "PIN이 일치하지 않습니다. 다시 입력해 주세요."
                lockedUntil = nil
                newPINFirstEntry = nil
                self.pin = ""
                step = .enterPIN
                refreshCopy()
                return
            }

            // 실제 등록
            try manager.createPIN(normalized, iterations: registerIterations)
            pinSuccessCleanup()
            step = .done
            refreshCopy()
            onRegisterSuccess?()

        default:
            // register에서 올 수 없는 상태면 초기화
            clear()
            step = .enterPIN
            refreshCopy()
        }
    }

    private func changeFlow(pin: String) throws {
        switch step {
        case .enterOldPIN:
            try validateFormatOnly(pin: pin)
            // 기존 PIN 저장
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
                // 이상 상태 -> 새 PIN 입력부터
                self.pin = ""
                step = .enterNewPIN
                refreshCopy()
                return
            }
            guard normalizedConfirm == newFirst else {
                errorMessage = "PIN이 일치하지 않습니다. 다시 입력해 주세요."
                lockedUntil = nil
                newPINFirstEntry = nil
                self.pin = ""
                step = .enterNewPIN
                refreshCopy()
                return
            }
            guard let oldPIN = oldPINForChange else {
                // 이상 상태 -> 처음부터
                clear()
                mode = .change
                step = .enterOldPIN
                refreshCopy()
                return
            }

            // 실제 변경
            try manager.changePIN(oldPIN: oldPIN, newPIN: normalizedConfirm)
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

    // MARK: - Validation

    private func validateFormatOnly(pin: String) throws {
        guard pin.count == maxLength else {
            throw SmartSecureKeypadCryptoError.invalidPINFormat(reason: "PIN length must be \(maxLength)")
        }
        guard pin.unicodeScalars.allSatisfy({ CharacterSet.decimalDigits.contains($0) }) else {
            throw SmartSecureKeypadCryptoError.invalidPINFormat(reason: "PIN must contain digits only")
        }
    }

    // MARK: - Error Handling

    private func handle(error: Error) {
        if let e = error as? SmartSecureKeypadCryptoError {
            switch e {
            case .locked(let until):
                lockedUntil = until
                errorMessage = e.message
                pin = ""
            default:
                lockedUntil = nil
                errorMessage = e.message
                pin = ""
            }
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

    // MARK: - UI Copy

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
