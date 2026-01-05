//
//  PINFlowDemoView.swift
//  SmartSecureNumpadDemoApp
//
//  Created by INSEONG on 1/5/26.
//

import SwiftUI
import SmartSecureKeypad

struct PINFlowDemoView: View {
    @StateObject private var vm: SmartSecureKeypadPINFlowViewModel

    init() {
        // ✅ 락아웃 기본 OFF면 그냥 .init()
        let manager = SmartSecureKeypadPINVaultManager()

        // ✅ 락아웃 ON 하고 싶은 사람만 (옵트인)
        // let lockout = SmartSecureKeypadLockoutPolicy.recommended()
        // let manager = SmartSecureKeypadPINVaultManager(lockout: lockout)

        _vm = StateObject(wrappedValue: .init(mode: .verify, manager: manager))
    }

    var body: some View {
        VStack(spacing: 12) {
            // 모드 전환 예시
            Picker("Mode", selection: Binding(
                get: { vm.mode },
                set: { vm.setMode($0) }
            )) {
                Text("Verify").tag(SmartSecureKeypadPINFlowViewModel.Mode.verify)
                Text("Register").tag(SmartSecureKeypadPINFlowViewModel.Mode.register)
                Text("Change").tag(SmartSecureKeypadPINFlowViewModel.Mode.change)
            }
            .pickerStyle(.segmented)
            .padding(.horizontal)

            SmartSecureKeypadPINEntryView(
                pin: $vm.pin,
                title: vm.title,
                message: vm.message,
                errorMessage: vm.errorMessage,
                lockedUntil: vm.lockedUntil,
                onKey: { _ in
                    vm.userDidInputKey()
                },
                onSubmit: { pin in
                    vm.handleCompletedPIN(pin)
                }
            )

            // 성공 콜백은 onAppear에서 연결해두는 게 깔끔
            // (아래 onAppear 참고)
        }
        .onAppear {
            vm.onVerifySuccess = {
                print("✅ verify success")
            }
            vm.onRegisterSuccess = {
                print("✅ register success")
            }
            vm.onChangeSuccess = {
                print("✅ change success")
            }
        }
    }
}
