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
        let manager = SmartSecureKeypadPINVaultManager()                 // Crypto
        let crypto = SmartSecureKeypadPINFlowCryptoAdapter(manager: manager) // Crypto adapter
        let vm = SmartSecureKeypadPINFlowViewModel(mode: .verify, crypto: crypto) // Core
        _vm = StateObject(wrappedValue: vm)
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
                isKeyEnabled: { _ in vm.lockedUntil == nil },
                onKey: { _ in
                    vm.userDidInputKey()
                },
                onSubmit: { pin in
                    vm.handleCompletedPIN(pin)
                }
            )
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
