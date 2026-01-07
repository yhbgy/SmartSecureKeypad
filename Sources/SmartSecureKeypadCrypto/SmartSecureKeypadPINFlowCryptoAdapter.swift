//
//  SmartSecureKeypadPINFlowCryptoAdapter.swift
//  SmartSecureKeypad
//
//  Created by INSEONG on 1/5/26.
//

import Foundation
import SmartSecureKeypadCore

public struct SmartSecureKeypadPINFlowCryptoAdapter: SmartSecureKeypadPINFlowCrypto {

    private let manager: SmartSecureKeypadPINVaultManager

    public init(manager: SmartSecureKeypadPINVaultManager = .init()) {
        self.manager = manager
    }

    public func createPIN(_ pin: String, iterations: Int) throws {
        do { try manager.createPIN(pin, iterations: iterations) }
        catch { throw map(error) }
    }

    public func unlock(pin: String) throws {
        do { try manager.unlock(pin: pin) }
        catch { throw map(error) }
    }

    public func changePIN(oldPIN: String, newPIN: String) throws {
        do { try manager.changePIN(oldPIN: oldPIN, newPIN: newPIN) }
        catch { throw map(error) }
    }

    private func map(_ error: Error) -> SmartSecureKeypadPINFlowError {
        if let e = error as? SmartSecureKeypadCryptoError {
            switch e {
            case .locked(let until):
                return .init(code: .locked, message: e.message, lockedUntil: until)
            case .pinNotRegistered:
                return .init(code: .notRegistered, message: e.message)
            case .invalidPIN, .invalidPINFormat:
                return .init(code: .invalidPINFormat, message: e.message)
            default:
                return .init(code: .cryptoFailure, message: e.message)
            }
        }
        return .init(code: .unknown, message: "Unknown error")
    }
}
