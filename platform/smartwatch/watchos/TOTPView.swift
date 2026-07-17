import SwiftUI
import CryptoKit
import WatchKit

// MARK: - WatchOS TOTP Display
//
// Minimal WatchOS app that displays TOTP codes for a list of accounts.
// Secrets are synced via CloudKit NSUbiquitousKeyValueStore (encrypted).

struct Account: Identifiable, Codable {
    let id: String
    let label: String
    let secret: String   // Base32-encoded shared secret
    let issuer: String
}

struct ContentView: View {
    @State private var accounts: [Account] = []
    @State private var currentTime: Date = Date()
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        NavigationStack {
            List(accounts) { account in
                TOTPRow(account: account, currentTime: currentTime)
            }
            .navigationTitle("ZK Vault")
            .onReceive(timer) { time in
                currentTime = time
            }
            .onAppear {
                loadAccounts()
            }
        }
    }

    private func loadAccounts() {
        let store = NSUbiquitousKeyValueStore.default
        guard let data = store.data(forKey: "totp_accounts"),
              let decoded = try? JSONDecoder().decode([Account].self, from: data)
        else { return }
        accounts = decoded
    }
}

struct TOTPRow: View {
    let account: Account
    let currentTime: Date

    var totpCode: String {
        let counter = UInt64(currentTime.timeIntervalSince1970 / 30)
        return generateTOTP(secret: account.secret, counter: counter)
    }

    var timeRemaining: Int {
        30 - Int(currentTime.timeIntervalSince1970) % 30
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(account.label)
                .font(.caption)
                .foregroundColor(.secondary)
            Text(totpCode)
                .font(.system(.title2, design: .monospaced))
                .fontWeight(.bold)
                .foregroundColor(.green)
            ProgressView(value: Double(timeRemaining) / 30.0)
                .tint(timeRemaining < 5 ? .red : .green)
        }
        .padding(.vertical, 4)
    }

    private func generateTOTP(secret: String, counter: UInt64) -> String {
        // Use CryptoKit's HMAC implementation
        guard let secretData = base32Decode(secret) else { return "------" }
        var counterBigEndian = counter.bigEndian
        let counterData = Data(bytes: &counterBigEndian, count: MemoryLayout<UInt64>.size)

        let key = SymmetricKey(data: secretData)
        let hmac = HMAC<Insecure.SHA1>.authenticationCode(for: counterData, using: key)
        let hmacBytes = Data(hmac)

        let offset = Int(hmacBytes.last! & 0x0f)
        let code = (UInt32(hmacBytes[offset] & 0x7f) << 24) |
                   (UInt32(hmacBytes[offset + 1] & 0xff) << 16) |
                   (UInt32(hmacBytes[offset + 2] & 0xff) << 8) |
                   UInt32(hmacBytes[offset + 3] & 0xff)

        let otp = code % 1_000_000
        return String(format: "%06d", otp)
    }

    private func base32Decode(_ string: String) -> Data? {
        let chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        let cleaned = string.uppercased().filter { chars.contains($0) }
        var bits = [Bool]()
        for char in cleaned {
            if let index = chars.firstIndex(of: char) {
                let val = chars.distance(from: chars.startIndex, to: index)
                for i in 0..<5 {
                    bits.append((val >> (4 - i)) & 1 == 1)
                }
            }
        }
        var bytes = [UInt8]()
        for i in stride(from: 0, to: bits.count - 7, by: 8) {
            var byte: UInt8 = 0
            for j in 0..<8 {
                byte = (byte << 1) | (bits[i + j] ? 1 : 0)
            }
            bytes.append(byte)
        }
        return Data(bytes)
    }
}

#Preview {
    ContentView()
}
