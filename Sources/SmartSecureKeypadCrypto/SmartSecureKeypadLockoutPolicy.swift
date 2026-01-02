//
//  SmartSecureKeypadLockoutPolicy.swift
//  SmartSecureKeypad
//
//  Created by INSEONG on 1/2/26.
//

import Foundation

/// 로컬 PIN 시도에 대한 락아웃(잠금) 정책.
///
/// - 오프라인 PIN(예: 6자리)은 브루트포스(대입) 공격 대상이 되기 쉽다.
/// - PBKDF2 비용(iterations)만으로는 충분하지 않을 수 있으므로,
///   "시도 제한/지연/잠금"을 함께 적용하는 것이 실무적으로 매우 중요하다.
///
/// 이 타입의 책임:
/// - 실패 횟수/잠금 만료 시각을 상태(State)로 관리하는 "정책(상태 머신)".
/// - 상태 저장/로드는 `SmartSecureKeypadKeychainStore`를 사용해 Keychain에 유지한다.
///
/// 사용 패턴(권장):
/// 1) 입력 시도 전: `try policy.throwIfLocked()`
/// 2) PIN 검증 성공: `try policy.recordSuccess()`
/// 3) PIN 검증 실패: `try policy.recordFailure()`
public struct SmartSecureKeypadLockoutPolicy: Sendable {

    // MARK: - Persisted State

    /// Keychain에 저장되는 락아웃 상태.
    public struct State: Codable, Sendable, Equatable {
        /// 연속 실패 횟수
        public var failureCount: Int
        /// 잠금 만료 시각(잠겨있지 않다면 nil)
        public var lockedUntil: Date?

        public init(failureCount: Int = 0, lockedUntil: Date? = nil) {
            self.failureCount = failureCount
            self.lockedUntil = lockedUntil
        }
    }

    // MARK: - Configuration

    /// 상태 저장을 담당하는 KeychainStore
    public let store: SmartSecureKeypadKeychainStore

    /// 상태 저장 account
    public let account: String

    /// 실패 횟수에 따른 잠금 시간(초) 테이블.
    /// - index = failureCount
    /// - 예: [0, 0, 0, 0, 0, 30, 60, 300, 1800, 7200]
    ///   => 5회부터 잠금 시작(30초), 6회 60초, 7회 5분 ... 9회 이상은 2시간 고정
    public let lockSecondsByFailureCount: [Int]

    public init(
        store: SmartSecureKeypadKeychainStore = .init(),
        account: String = SmartSecureKeypadKeychainStoreDefaults.lockoutStateAccount,
        lockSecondsByFailureCount: [Int] = [
            0,   // 0 failures
            0,   // 1
            0,   // 2
            0,   // 3
            0,   // 4
            30,  // 5
            60,  // 6
            300, // 7  (5m)
            1800,// 8  (30m)
            7200 // 9+ (2h) -> 이후는 마지막 값을 유지
        ]
    ) {
        self.store = store
        self.account = account
        self.lockSecondsByFailureCount = lockSecondsByFailureCount
    }

    // MARK: - Load / Save

    /// Keychain에서 상태를 로드한다. 없으면 기본값(State()) 반환.
    public func loadState() throws -> State {
        try store.loadCodable(State.self, account: account) ?? State()
    }

    /// Keychain에 상태를 저장한다.
    public func saveState(_ state: State) throws {
        try store.saveCodable(state, account: account)
    }

    /// 락아웃 상태를 초기화(삭제)한다.
    public func reset() throws {
        try store.delete(account: account)
    }

    // MARK: - Query

    /// 잠겨있다면 잠금 만료 시각을 반환한다. (잠겨있지 않으면 nil)
    public func lockedUntil(now: Date = Date()) throws -> Date? {
        let state = try loadState()
        guard let until = state.lockedUntil, now < until else { return nil }
        return until
    }

    /// 현재 시도 가능한지 여부
    public func canAttempt(now: Date = Date()) throws -> Bool {
        (try lockedUntil(now: now)) == nil
    }

    /// 잠겨있다면 `SmartSecureKeypadCryptoError.locked(until:)`를 던진다.
    public func throwIfLocked(now: Date = Date()) throws {
        if let until = try lockedUntil(now: now) {
            throw SmartSecureKeypadCryptoError.locked(until: until)
        }
    }

    // MARK: - Transitions

    /// PIN 검증 성공 처리
    /// - 실패 횟수/잠금 해제
    public func recordSuccess() throws {
        var state = try loadState()
        state.failureCount = 0
        state.lockedUntil = nil
        try saveState(state)
    }

    /// PIN 검증 실패 처리
    /// - failureCount 증가
    /// - 테이블에 따라 잠금 설정(필요 시)
    public func recordFailure(now: Date = Date()) throws {
        var state = try loadState()

        state.failureCount += 1

        let seconds = lockSeconds(for: state.failureCount)
        if seconds > 0 {
            state.lockedUntil = now.addingTimeInterval(TimeInterval(seconds))
        } else {
            // 즉시 재시도 허용 구간이면 lockedUntil 제거
            state.lockedUntil = nil
        }

        try saveState(state)
    }

    // MARK: - Helpers

    private func lockSeconds(for failureCount: Int) -> Int {
        if failureCount < lockSecondsByFailureCount.count {
            return lockSecondsByFailureCount[failureCount]
        }
        return lockSecondsByFailureCount.last ?? 0
    }
}
