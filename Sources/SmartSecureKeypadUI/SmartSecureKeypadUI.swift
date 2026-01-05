//
//  SmartSecureKeypadUI.swift
//  SmartSecureKeypad
//
//  Created by INSEONG on 12/19/25.
//

import SwiftUI

// MARK: - Public Types

/// 3x4 고정 숫자 키패드에서 렌더링/입력되는 키 타입.
public enum SmartSecureKeypadKey: Sendable, Hashable {
    /// 0~9 숫자
    case digit(Int)
    /// 삭제(백스페이스)
    case delete
    /// 빈 칸(3x4 고정을 위해 사용)
    case empty

    public var digitValue: Int? {
        if case .digit(let d) = self { return d }
        return nil
    }
}

/// 키 렌더링 시 상태(눌림/비활성 등)를 전달하기 위한 UI 상태.
public struct SmartSecureKeypadKeyState: Sendable, Hashable {
    public var isPressed: Bool
    public var isEnabled: Bool

    public init(isPressed: Bool = false, isEnabled: Bool = true) {
        self.isPressed = isPressed
        self.isEnabled = isEnabled
    }
}

// MARK: - Numpad (3x4 Fixed)

/// 3x4 고정 숫자 키패드.
///
/// 커스터마이징 포인트:
/// - `keyRenderer`: 각 키를 원하는 UI로 렌더링(실무에서 제일 유용)
/// - `onKey`: 키 눌림 이벤트
/// - `onComplete`: PIN 길이가 maxLength에 도달했을 때 콜백
///
/// 기본 동작:
/// - 이 View가 `pin`을 버퍼링하고 digit/delete를 처리한다.
/// - 앱이 버퍼를 직접 관리하고 싶다면 `onKey`만 사용하고 `pin` 바인딩은 무시해도 된다.
public struct SmartSecureKeypadNumpad<KeyContent: View>: View {

    // MARK: Layout

    /// 3x4 고정 레이아웃 정의
    ///
    /// [1][2][3]
    /// [4][5][6]
    /// [7][8][9]
    /// [ ][0][⌫]
    public static var layout: [[SmartSecureKeypadKey]] {
        [
            [.digit(1), .digit(2), .digit(3)],
            [.digit(4), .digit(5), .digit(6)],
            [.digit(7), .digit(8), .digit(9)],
            [.empty,    .digit(0), .delete]
        ]
    }

    // MARK: Input

    @Binding private var pin: String
    private let maxLength: Int
    private let isKeyEnabled: (SmartSecureKeypadKey) -> Bool
    private let onKey: (SmartSecureKeypadKey) -> Void
    private let onComplete: (String) -> Void

    // MARK: Rendering

    private let keyRenderer: (SmartSecureKeypadKey, SmartSecureKeypadKeyState) -> KeyContent
    private let spacing: CGFloat
    private let keyHeight: CGFloat

    // MARK: Init

    public init(
        pin: Binding<String>,
        maxLength: Int = 6,
        spacing: CGFloat = 12,
        keyHeight: CGFloat = 56,
        isKeyEnabled: @escaping (SmartSecureKeypadKey) -> Bool = { _ in true },
        onKey: @escaping (SmartSecureKeypadKey) -> Void = { _ in },
        onComplete: @escaping (String) -> Void = { _ in },
        @ViewBuilder keyRenderer: @escaping (SmartSecureKeypadKey, SmartSecureKeypadKeyState) -> KeyContent
    ) {
        self._pin = pin
        self.maxLength = maxLength
        self.spacing = spacing
        self.keyHeight = keyHeight
        self.isKeyEnabled = isKeyEnabled
        self.onKey = onKey
        self.onComplete = onComplete
        self.keyRenderer = keyRenderer
    }

    /// 기본 UI(최소한의 스타일)로 쓰고 싶을 때.
    public init(
        pin: Binding<String>,
        maxLength: Int = 6,
        spacing: CGFloat = 12,
        keyHeight: CGFloat = 56,
        isKeyEnabled: @escaping (SmartSecureKeypadKey) -> Bool = { _ in true },
        onKey: @escaping (SmartSecureKeypadKey) -> Void = { _ in },
        onComplete: @escaping (String) -> Void = { _ in }
    ) where KeyContent == SmartSecureKeypadDefaultKeyView {
        self.init(
            pin: pin,
            maxLength: maxLength,
            spacing: spacing,
            keyHeight: keyHeight,
            isKeyEnabled: isKeyEnabled,
            onKey: onKey,
            onComplete: onComplete,
            keyRenderer: { key, state in
                SmartSecureKeypadDefaultKeyView(key: key, state: state)
            }
        )
    }

    // MARK: Body

    public var body: some View {
        VStack(spacing: spacing) {
            ForEach(Array(Self.layout.enumerated()), id: \.offset) { _, row in
                HStack(spacing: spacing) {
                    ForEach(row, id: \.self) { key in
                        keyButton(for: key)
                    }
                }
            }
        }
        .accessibilityElement(children: .contain)
    }

    // MARK: Key Button

    @ViewBuilder
    private func keyButton(for key: SmartSecureKeypadKey) -> some View {
        let enabled = isKeyEnabled(key)

        if key == .empty {
            Color.clear
                .frame(maxWidth: .infinity)
                .frame(height: keyHeight)
                .contentShape(Rectangle())
                .accessibilityHidden(true)
        } else {
            SmartSecureKeypadPressableButton(
                isEnabled: enabled,
                label: { isPressed in
                    keyRenderer(key, .init(isPressed: isPressed, isEnabled: enabled))
                        .frame(maxWidth: .infinity)
                        .frame(height: keyHeight)
                },
                action: {
                    handleKeyTap(key)
                }
            )
            .accessibilityLabel(accessibilityLabel(for: key))
            .accessibilityAddTraits(.isButton)
        }
    }

    private func accessibilityLabel(for key: SmartSecureKeypadKey) -> Text {
        switch key {
        case .digit(let d):
            return Text("\(d)")
        case .delete:
            return Text("Delete")
        case .empty:
            return Text("")
        }
    }

    // MARK: Input Handling

    private func handleKeyTap(_ key: SmartSecureKeypadKey) {
        onKey(key)

        switch key {
        case .digit(let d):
            guard pin.count < maxLength else { return }
            pin.append(String(d))
            if pin.count == maxLength {
                onComplete(pin)
            }

        case .delete:
            guard !pin.isEmpty else { return }
            pin.removeLast()

        case .empty:
            break
        }
    }
}

// MARK: - PIN Indicator (Dots)

/// PIN 입력 진행 상태를 보여주는 Dot Indicator.
public struct SmartSecureKeypadPINDotsView: View {
    public let maxLength: Int
    public let enteredCount: Int
    public let dotSize: CGFloat
    public let dotSpacing: CGFloat

    public init(
        maxLength: Int,
        enteredCount: Int,
        dotSize: CGFloat = 12,
        dotSpacing: CGFloat = 10
    ) {
        self.maxLength = maxLength
        self.enteredCount = enteredCount
        self.dotSize = dotSize
        self.dotSpacing = dotSpacing
    }

    public var body: some View {
        HStack(spacing: dotSpacing) {
            ForEach(0..<maxLength, id: \.self) { idx in
                Circle()
                    .fill(Color.primary.opacity(idx < enteredCount ? 0.85 : 0.18))
                    .frame(width: dotSize, height: dotSize)
                    .accessibilityLabel(Text(idx < enteredCount ? "Filled" : "Empty"))
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(Text("PIN entry"))
    }
}

// MARK: - Lockout UI Helpers (Opt-in)

/// 락아웃 남은 시간을 "mm:ss"로 표시하기 위한 유틸.
public enum SmartSecureKeypadLockoutTimeFormatter {
    /// until - now 를 계산해서 0 이상이면 mm:ss, 아니면 nil
    public static func remainingMMSS(until: Date, now: Date = Date()) -> String? {
        let remaining = Int(ceil(until.timeIntervalSince(now)))
        guard remaining > 0 else { return nil }
        let minutes = remaining / 60
        let seconds = remaining % 60
        return String(format: "%02d:%02d", minutes, seconds)
    }
}

/// 락아웃 메시지를 "잠금 해제까지 00:30" 형태로 보여주는 뷰.
public struct SmartSecureKeypadLockoutMessageView: View {
    public let lockedUntil: Date
    public let prefix: String

    public init(lockedUntil: Date, prefix: String = "잠금 해제까지") {
        self.lockedUntil = lockedUntil
        self.prefix = prefix
    }

    public var body: some View {
        TimelineView(.periodic(from: .now, by: 1.0)) { context in
            if let mmss = SmartSecureKeypadLockoutTimeFormatter.remainingMMSS(until: lockedUntil, now: context.date) {
                Text("\(prefix) \(mmss)")
                    .font(.system(size: 13, weight: .semibold, design: .monospaced))
                    .foregroundStyle(Color.red)
                    .multilineTextAlignment(.center)
            } else {
                EmptyView()
            }
        }
        .accessibilityLabel(Text("Locked"))
    }
}

// MARK: - PIN Entry Container

/// Dot Indicator + Numpad를 함께 제공하는 상위 PIN 입력 UI.
///
/// 커스터마이징 포인트:
/// - `keyRenderer`로 키 UI 완전 커스텀
/// - 상단 타이틀/설명/에러/락아웃 문구를 앱에서 원하는 대로 구성 가능
public struct SmartSecureKeypadPINEntryView<KeyContent: View>: View {

    @Binding private var pin: String

    private let title: String?
    private let message: String?
    private let errorMessage: String?
    private let lockedUntil: Date?

    private let maxLength: Int
    private let spacing: CGFloat

    private let isKeyEnabled: (SmartSecureKeypadKey) -> Bool
    private let onKey: (SmartSecureKeypadKey) -> Void
    private let onSubmit: (String) -> Void

    private let keyRenderer: (SmartSecureKeypadKey, SmartSecureKeypadKeyState) -> KeyContent

    public init(
        pin: Binding<String>,
        title: String? = nil,
        message: String? = nil,
        errorMessage: String? = nil,
        lockedUntil: Date? = nil,
        maxLength: Int = 6,
        spacing: CGFloat = 16,
        isKeyEnabled: @escaping (SmartSecureKeypadKey) -> Bool = { _ in true },
        onKey: @escaping (SmartSecureKeypadKey) -> Void = { _ in },
        onSubmit: @escaping (String) -> Void,
        @ViewBuilder keyRenderer: @escaping (SmartSecureKeypadKey, SmartSecureKeypadKeyState) -> KeyContent
    ) {
        self._pin = pin
        self.title = title
        self.message = message
        self.errorMessage = errorMessage
        self.lockedUntil = lockedUntil
        self.maxLength = maxLength
        self.spacing = spacing
        self.isKeyEnabled = isKeyEnabled
        self.onKey = onKey
        self.onSubmit = onSubmit
        self.keyRenderer = keyRenderer
    }

    /// 기본 키 스타일을 쓰는 편의 생성자
    public init(
        pin: Binding<String>,
        title: String? = nil,
        message: String? = nil,
        errorMessage: String? = nil,
        lockedUntil: Date? = nil,
        maxLength: Int = 6,
        spacing: CGFloat = 16,
        isKeyEnabled: @escaping (SmartSecureKeypadKey) -> Bool = { _ in true },
        onKey: @escaping (SmartSecureKeypadKey) -> Void = { _ in },
        onSubmit: @escaping (String) -> Void
    ) where KeyContent == SmartSecureKeypadDefaultKeyView {
        self.init(
            pin: pin,
            title: title,
            message: message,
            errorMessage: errorMessage,
            lockedUntil: lockedUntil,
            maxLength: maxLength,
            spacing: spacing,
            isKeyEnabled: isKeyEnabled,
            onKey: onKey,
            onSubmit: onSubmit,
            keyRenderer: { key, state in
                SmartSecureKeypadDefaultKeyView(key: key, state: state)
            }
        )
    }

    public var body: some View {
        VStack(spacing: spacing) {
            header

            SmartSecureKeypadPINDotsView(
                maxLength: maxLength,
                enteredCount: min(pin.count, maxLength)
            )
            .padding(.bottom, 4)

            SmartSecureKeypadNumpad(
                pin: $pin,
                maxLength: maxLength,
                isKeyEnabled: isKeyEnabled,
                onKey: onKey,
                onComplete: { pin in
                    onSubmit(pin)
                },
                keyRenderer: keyRenderer
            )
        }
        .padding()
    }

    @ViewBuilder
    private var header: some View {
        VStack(spacing: 8) {
            if let title {
                Text(title)
                    .font(.system(size: 20, weight: .semibold))
                    .multilineTextAlignment(.center)
            }
            if let message {
                Text(message)
                    .font(.system(size: 14))
                    .foregroundStyle(Color.secondary)
                    .multilineTextAlignment(.center)
            }
            if let lockedUntil {
                SmartSecureKeypadLockoutMessageView(lockedUntil: lockedUntil)
                    .padding(.top, 2)
            }
            if let errorMessage, !errorMessage.isEmpty {
                Text(errorMessage)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Color.red)
                    .multilineTextAlignment(.center)
                    .padding(.top, 2)
            }
        }
        .frame(maxWidth: .infinity)
    }
}

// MARK: - Default Key Renderer

/// 기본 키 렌더러(최소한의 디자인)
public struct SmartSecureKeypadDefaultKeyView: View {
    public let key: SmartSecureKeypadKey
    public let state: SmartSecureKeypadKeyState

    public init(key: SmartSecureKeypadKey, state: SmartSecureKeypadKeyState) {
        self.key = key
        self.state = state
    }

    public var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 12)
                .fill(Color.primary.opacity(backgroundOpacity))

            content
                .foregroundStyle(foregroundStyle)
        }
        .animation(.easeOut(duration: 0.12), value: state.isPressed)
        .animation(.easeOut(duration: 0.12), value: state.isEnabled)
    }

    @ViewBuilder
    private var content: some View {
        switch key {
        case .digit(let d):
            Text("\(d)")
                .font(.system(size: 22, weight: .semibold, design: .rounded))

        case .delete:
            Image(systemName: "delete.left")
                .font(.system(size: 18, weight: .semibold))

        case .empty:
            EmptyView()
        }
    }

    private var backgroundOpacity: Double {
        if !state.isEnabled { return 0.06 }
        return state.isPressed ? 0.18 : 0.10
    }

    private var foregroundStyle: some ShapeStyle {
        if !state.isEnabled {
            return AnyShapeStyle(Color.secondary.opacity(0.5))
        }
        return AnyShapeStyle(Color.primary)
    }
}

// MARK: - Pressable Button Primitive

private struct SmartSecureKeypadPressableButton<Label: View>: View {
    let isEnabled: Bool
    let label: (_ isPressed: Bool) -> Label
    let action: () -> Void

    @GestureState private var isPressed: Bool = false

    var body: some View {
        label(isPressed)
            .contentShape(Rectangle())
            .opacity(isEnabled ? 1 : 0.45)
            .gesture(
                DragGesture(minimumDistance: 0)
                    .updating($isPressed) { _, state, _ in
                        if isEnabled { state = true }
                    }
                    .onEnded { _ in
                        guard isEnabled else { return }
                        action()
                    }
            )
    }
}

// MARK: - Preview

#Preview {
    struct Demo: View {
        @State var pin: String = ""
        @State var lockedUntil: Date? = Date().addingTimeInterval(75)

        var body: some View {
            VStack(spacing: 16) {
                SmartSecureKeypadPINEntryView(
                    pin: $pin,
                    title: "Enter PIN",
                    message: "PIN을 입력하세요",
                    errorMessage: nil,
                    lockedUntil: lockedUntil,
                    onSubmit: { _ in }
                )

                SmartSecureKeypadNumpad(
                    pin: $pin,
                    maxLength: 6,
                    keyRenderer: { key, state in
                        ZStack {
                            RoundedRectangle(cornerRadius: 16)
                                .fill(Color.blue.opacity(state.isPressed ? 0.35 : 0.18))
                            if case .digit(let d) = key {
                                Text("\(d)")
                                    .font(.system(size: 22, weight: .bold))
                                    .foregroundStyle(Color.white)
                            } else if key == .delete {
                                Image(systemName: "delete.left")
                                    .font(.system(size: 18, weight: .bold))
                                    .foregroundStyle(Color.white)
                            }
                        }
                    }
                )
            }
            .padding()
        }
    }

    return Demo()
}
