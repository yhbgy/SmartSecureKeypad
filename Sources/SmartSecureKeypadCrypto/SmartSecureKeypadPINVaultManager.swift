//
//  SmartSecureKeypadPINVaultManager.swift
//  SmartSecureKeypad
//
//  Created by INSEONG on 1/2/26.
//

import Foundation

/// PIN 기반 로컬 Vault를 "안전하게" 사용하기 위한 Facade(Manager).
///
/// 이 타입이 해결하는 문제
/// - LocalVault / KeychainStore / LockoutPolicy / PINPolicy를 앱이 직접 엮으면
///   호출 순서(락아웃 체크, 성공/실패 기록, 정책 검증 등)를 빠뜨리기 쉽다.
/// - Manager가 이 순서를 강제하여, 사용자가 실수하기 어려운 API를 제공한다.
///
/// 저장 방식
/// - WrappedVaultKey: Keychain(`SmartSecureKeypadKeychainStore`)에 저장
/// - Lockout 상태:   Keychain(`SmartSecureKeypadLockoutPolicy`)에 저장
/// - 실제 데이터(암호문): 호스트 앱이 원하는 저장소(파일/DB 등)에 `SmartSecureKeypadSealedPayload` 형태로 저장
///
/// 보안 주의
/// - 이 구조는 "로컬 전용"이며 서버 검증을 전제로 하지 않는다.
/// - 오프라인 PIN 특성상, PBKDF2 iterations + LockoutPolicy 조합이 사실상 필수다.
public final class SmartSecureKeypadPINVaultManager: @unchecked Sendable {

    // MARK: - Dependencies

    private let store: SmartSecureKeypadKeychainStore
    private let lockout: SmartSecureKeypadLockoutPolicy
    private let pinPolicy: SmartSecureKeypadPINPolicy

    /// WrappedVaultKey를 저장하는 account
    private let wrappedAccount: String

    /// Vault를 열어둔(언락된) 상태의 메모리 키.
    /// - 앱이 종료되면 사라지므로, 다시 쓰려면 unlock을 다시 해야 한다.
    private var currentVault: SmartSecureKeypadLocalVault?

    /// 동시 접근 보호
    private let lock = NSLock()

    // MARK: - Init

    /// - Parameters:
    ///   - store: Keychain store (서비스명/접근성 커스터마이즈 가능)
    ///   - lockout: Lockout policy (상태 저장 account/테이블 커스터마이즈 가능)
    ///   - pinPolicy: PIN 정책(길이/약한 PIN 룰)
    ///   - wrappedAccount: WrappedVaultKey 저장 account (기본값 권장)
    public init(
        store: SmartSecureKeypadKeychainStore = .init(),
        lockout: SmartSecureKeypadLockoutPolicy? = nil,
        pinPolicy: SmartSecureKeypadPINPolicy = .init(),
        wrappedAccount: String = SmartSecureKeypadKeychainStoreDefaults.wrappedVaultKeyAccount
    ) {
        self.store = store
        self.lockout = lockout ?? SmartSecureKeypadLockoutPolicy(store: store)
        self.pinPolicy = pinPolicy
        self.wrappedAccount = wrappedAccount
    }

    // MARK: - State

    /// 현재 언락되어 있는지
    public var isUnlocked: Bool {
        lock.lock(); defer { lock.unlock() }
        return currentVault != nil
    }

    /// 잠금 상태면 종료 시각을 반환(잠겨있지 않으면 nil)
    public func lockedUntil(now: Date = Date()) throws -> Date? {
        try lockout.lockedUntil(now: now)
    }

    /// 메모리상 vault를 비운다(로그아웃/백그라운드 진입 시 호출 권장)
    public func lockVaultInMemory() {
        lock.lock(); defer { lock.unlock() }
        currentVault = nil
    }

    /// WrappedVaultKey가 저장되어 있는지(=PIN 설정이 되어있는지)
    public func hasPIN() throws -> Bool {
        let wrapped = try store.loadWrappedVaultKey(account: wrappedAccount)
        return wrapped != nil
    }

    // MARK: - PIN Lifecycle

    /// PIN을 새로 설정(= Vault 생성 + WrappedVaultKey 저장)
    ///
    /// - Note:
    ///   기존 PIN이 있으면 덮어쓴다(기존 wrappedKey 삭제 후 새로 저장).
    ///   (호스트 앱 정책에 따라 "기존 PIN 존재 시 거부"로 바꾸고 싶으면 여기서 분기하면 됨)
    public func createPIN(
        _ pin: String,
        iterations: Int = 120_000
    ) throws {
        let normalized = try pinPolicy.normalizedAndValidate(pin: pin)

        let (vault, wrapped) = try SmartSecureKeypadLocalVault.createNew(pin: normalized, iterations: iterations)

        try store.saveWrappedVaultKey(wrapped, account: wrappedAccount)
        try lockout.recordSuccess() // 실패/잠금 초기화

        lock.lock(); defer { lock.unlock() }
        currentVault = vault
    }

    /// PIN으로 Vault를 언락한다.
    ///
    /// - Flow(강제):
    ///   1) 락아웃 체크
    ///   2) wrappedKey 로드
    ///   3) LocalVault.open
    ///   4) 성공/실패를 lockout에 기록
    public func unlock(pin: String, now: Date = Date()) throws {
        // 1) 락아웃 체크
        try lockout.throwIfLocked(now: now)

        // 2) wrappedKey 로드
        guard let wrapped = try store.loadWrappedVaultKey(account: wrappedAccount) else {
            // PIN 자체가 아직 설정되지 않은 상태
            throw SmartSecureKeypadCryptoError.invalidWrappedKey
        }

        do {
            // 3) open
            let normalized = pin.trimmingCharacters(in: .whitespacesAndNewlines)
            let vault = try SmartSecureKeypadLocalVault.open(pin: normalized, wrapped: wrapped)

            // 4) 성공 기록
            try lockout.recordSuccess()

            lock.lock(); defer { lock.unlock() }
            currentVault = vault
        } catch let e as SmartSecureKeypadCryptoError {
            // 실패 기록(대부분 invalidPIN)
            if case .invalidPIN = e {
                try lockout.recordFailure(now: now)
            }
            throw e
        } catch {
            // 예기치 못한 에러도 보수적으로 실패로 처리
            try lockout.recordFailure(now: now)
            throw SmartSecureKeypadCryptoError.cryptoFailure
        }
    }

    /// PIN 변경
    ///
    /// - Flow(강제):
    ///   1) 락아웃 체크
    ///   2) wrappedKey 로드
    ///   3) oldPIN으로 open
    ///   4) 새 PIN 정책 검증
    ///   5) VaultKey 재랩핑(데이터 재암호화 없음)
    ///   6) wrappedKey 저장
    ///   7) 성공/실패를 lockout에 기록
    public func changePIN(
        oldPIN: String,
        newPIN: String,
        newIterations: Int? = nil,
        now: Date = Date()
    ) throws {
        // 1) 락아웃 체크
        try lockout.throwIfLocked(now: now)

        // 2) wrappedKey 로드
        guard let wrapped = try store.loadWrappedVaultKey(account: wrappedAccount) else {
            throw SmartSecureKeypadCryptoError.invalidWrappedKey
        }

        // 3) oldPIN으로 open
        let vault: SmartSecureKeypadLocalVault
        do {
            let oldNormalized = oldPIN.trimmingCharacters(in: .whitespacesAndNewlines)
            vault = try SmartSecureKeypadLocalVault.open(pin: oldNormalized, wrapped: wrapped)
        } catch let e as SmartSecureKeypadCryptoError {
            if case .invalidPIN = e {
                try lockout.recordFailure(now: now)
            }
            throw e
        } catch {
            try lockout.recordFailure(now: now)
            throw SmartSecureKeypadCryptoError.cryptoFailure
        }

        // 4) 새 PIN 정책 검증
        let newNormalized = try pinPolicy.normalizedAndValidate(pin: newPIN)

        // 5) 재랩핑
        let iterations = newIterations ?? wrapped.iterations
        let newWrapped = try vault.changePIN(newPin: newNormalized, iterations: iterations)

        // 6) 저장
        try store.saveWrappedVaultKey(newWrapped, account: wrappedAccount)

        // 7) 성공 기록
        try lockout.recordSuccess()

        // 메모리 vault 갱신
        lock.lock(); defer { lock.unlock() }
        currentVault = vault
    }

    /// PIN 제거(초기화)
    /// - wrappedKey/lockoutState를 삭제하고 메모리 vault도 비운다.
    public func clearAll() throws {
        try store.deleteWrappedVaultKey(account: wrappedAccount)
        try lockout.reset()
        lockVaultInMemory()
    }

    // MARK: - Encrypt / Decrypt


    /// 언락된 상태에서만 데이터 암호화
    public func seal(_ plaintext: Data, aad: Data? = nil) throws -> SmartSecureKeypadSealedPayload {
        try withVault { vault in
            try vault.seal(plaintext, aad: aad)
        }
    }

    /// PIN 입력 직후 "한 번에" 암호화까지 수행하는 원샷 API.
    ///
    /// 사용 흐름:
    /// - UI에서 PIN 입력 완료 시 이 메서드를 호출하면,
    ///   (락아웃 체크 -> PIN으로 vault 언락 -> seal)까지 프레임워크 내부에서 처리된다.
    ///
    /// - Parameters:
    ///   - pin: 사용자가 입력한 PIN
    ///   - plaintext: 암호화할 원본 데이터
    ///   - aad: (선택) 무결성만 보장할 메타데이터 (예: deviceId)
    ///   - keepUnlockedInMemory:
    ///     true면 성공 시 vault를 메모리에 유지해 이후 `seal/open`을 PIN 없이 호출 가능
    ///     false면 작업 후 메모리 vault를 즉시 비워(프레임워크 외부에서 키가 오래 남지 않도록) 보수적으로 동작
    ///   - now: 테스트/주입 가능한 현재 시각(락아웃 계산용)
    public func sealUsingPIN(
        pin: String,
        plaintext: Data,
        aad: Data? = nil,
        keepUnlockedInMemory: Bool = false,
        now: Date = Date()
    ) throws -> SmartSecureKeypadSealedPayload {
        // 1) 락아웃 체크
        try lockout.throwIfLocked(now: now)

        // 2) wrappedKey 로드
        guard let wrapped = try store.loadWrappedVaultKey(account: wrappedAccount) else {
            throw SmartSecureKeypadCryptoError.invalidWrappedKey
        }

        do {
            // 3) PIN으로 open
            let normalized = pin.trimmingCharacters(in: .whitespacesAndNewlines)
            let vault = try SmartSecureKeypadLocalVault.open(pin: normalized, wrapped: wrapped)

            // 4) 암호화
            let payload = try vault.seal(plaintext, aad: aad)

            // 5) 성공 기록
            try lockout.recordSuccess()

            // 6) 메모리 유지 여부
            if keepUnlockedInMemory {
                lock.lock(); defer { lock.unlock() }
                currentVault = vault
            } else {
                // 보수적으로 메모리 키를 남기지 않음
                lockVaultInMemory()
            }

            return payload
        } catch let e as SmartSecureKeypadCryptoError {
            // PIN 오류는 실패 기록
            if case .invalidPIN = e {
                try lockout.recordFailure(now: now)
            }
            // 작업 실패 시 메모리 키 제거
            lockVaultInMemory()
            throw e
        } catch {
            try lockout.recordFailure(now: now)
            lockVaultInMemory()
            throw SmartSecureKeypadCryptoError.cryptoFailure
        }
    }

    /// PIN 입력 직후 "한 번에" 복호화까지 수행하는 원샷 API.
    ///
    /// - Flow:
    ///   (락아웃 체크 -> PIN으로 vault 언락 -> open)까지 프레임워크 내부에서 처리
    public func openUsingPIN(
        pin: String,
        payload: SmartSecureKeypadSealedPayload,
        aad: Data? = nil,
        keepUnlockedInMemory: Bool = false,
        now: Date = Date()
    ) throws -> Data {
        // 1) 락아웃 체크
        try lockout.throwIfLocked(now: now)

        // 2) wrappedKey 로드
        guard let wrapped = try store.loadWrappedVaultKey(account: wrappedAccount) else {
            throw SmartSecureKeypadCryptoError.invalidWrappedKey
        }

        do {
            // 3) PIN으로 open
            let normalized = pin.trimmingCharacters(in: .whitespacesAndNewlines)
            let vault = try SmartSecureKeypadLocalVault.open(pin: normalized, wrapped: wrapped)

            // 4) 복호화
            let plaintext = try vault.open(payload, aad: aad)

            // 5) 성공 기록
            try lockout.recordSuccess()

            // 6) 메모리 유지 여부
            if keepUnlockedInMemory {
                lock.lock(); defer { lock.unlock() }
                currentVault = vault
            } else {
                lockVaultInMemory()
            }

            return plaintext
        } catch let e as SmartSecureKeypadCryptoError {
            if case .invalidPIN = e {
                try lockout.recordFailure(now: now)
            }
            lockVaultInMemory()
            throw e
        } catch {
            try lockout.recordFailure(now: now)
            lockVaultInMemory()
            throw SmartSecureKeypadCryptoError.cryptoFailure
        }
    }

    /// 언락된 상태에서만 데이터 복호화
    public func open(_ payload: SmartSecureKeypadSealedPayload, aad: Data? = nil) throws -> Data {
        try withVault { vault in
            try vault.open(payload, aad: aad)
        }
    }

    // MARK: - Helpers

    private func withVault<T>(_ block: (SmartSecureKeypadLocalVault) throws -> T) throws -> T {
        let vault: SmartSecureKeypadLocalVault?
        lock.lock(); vault = currentVault; lock.unlock()

        guard let vault else {
            // 엄밀히는 별도 에러 케이스가 더 적절하지만,
            // 현재 CryptoError를 단일 타입으로 유지하기 위해 보수적으로 처리.
            throw SmartSecureKeypadCryptoError.cryptoFailure
        }
        return try block(vault)
    }
}
