import CryptoKit
import Darwin
import Foundation
import SQLite3
import Testing
@testable import OpenClawKit

struct DeviceIdentityCoordinatorTests {
    @Test(arguments: [false, true])
    func `native migration holds the Node state-local coordinator through claim`(useAlias: Bool) throws {
        let fixture = DeviceIdentityMigrationFixture(databasePath: "state/openclaw.sqlite")
        let source = try fixture.source()
        #expect(!FileManager.default.fileExists(atPath: fixture.destination.path))
        let selectedStateURL: URL
        if useAlias {
            try FileManager.default.createDirectory(at: fixture.destination, withIntermediateDirectories: true)
            selectedStateURL = fixture.url("state-alias")
            try FileManager.default.createSymbolicLink(at: selectedStateURL, withDestinationURL: fixture.destination)
        } else {
            selectedStateURL = fixture.destination
        }
        let databaseURL = selectedStateURL.appendingPathComponent("state/openclaw.sqlite")
        let coordinatorURL = Self.nodeCoordinatorURL(fixture)

        let identity = try DeviceIdentitySQLiteStore.loadOrCreate(
            databaseURL: databaseURL,
            destinationStateDirURL: selectedStateURL,
            profile: .primary,
            legacySources: [source],
            beforeLegacyClaim: { _ in
                // An independent SQLite connection at Node's expected path must be blocked.
                #expect(try Self.probeCoordinator(coordinatorURL) == SQLITE_BUSY)
            })

        #expect(try Self.probeCoordinator(coordinatorURL) == SQLITE_OK)
        #expect(try fixture.load().deviceId == identity.deviceId)
        #expect(try Self.permissions(coordinatorURL.deletingLastPathComponent()) == 0o700)
        #expect(try Self.permissions(coordinatorURL) == 0o600)
    }

    @Test
    func `native coordinator releases when migration fails before its claim`() throws {
        let fixture = DeviceIdentityMigrationFixture(databasePath: "state/openclaw.sqlite")
        let source = try fixture.source()
        let coordinatorURL = Self.nodeCoordinatorURL(fixture)

        #expect(throws: ProbeFailure.self) {
            try fixture.load(sources: [source], beforeLegacyClaim: { _ in
                #expect(try Self.probeCoordinator(coordinatorURL) == SQLITE_BUSY)
                throw ProbeFailure.stop
            })
        }

        #expect(try Self.probeCoordinator(coordinatorURL) == SQLITE_OK)
        #expect(FileManager.default.fileExists(atPath: source.identityURL.path))
        #expect(!FileManager.default.fileExists(atPath: fixture.databaseURL.path))
        #expect(!FileManager.default.fileExists(atPath: fixture.claimURL(for: source).path))
    }

    @Test
    func `native coordinator rejects a symlink leaf without claiming identity`() throws {
        let fixture = DeviceIdentityMigrationFixture(databasePath: "state/openclaw.sqlite")
        let source = try fixture.source()
        let coordinatorDirectory = Self.nodeCoordinatorURL(fixture).deletingLastPathComponent()
        let targetURL = fixture.url("unrelated-directory")
        try FileManager.default.createDirectory(
            at: coordinatorDirectory.deletingLastPathComponent(),
            withIntermediateDirectories: true)
        try FileManager.default.createDirectory(
            at: targetURL,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o755])
        let previousPermissions = try Self.permissions(targetURL)
        try FileManager.default.createSymbolicLink(at: coordinatorDirectory, withDestinationURL: targetURL)

        #expect(throws: NSError.self) {
            try fixture.load(sources: [source])
        }

        #expect(try Self.permissions(targetURL) == previousPermissions)
        #expect(FileManager.default.fileExists(atPath: source.identityURL.path))
        #expect(!FileManager.default.fileExists(atPath: fixture.databaseURL.path))
        #expect(!FileManager.default.fileExists(atPath: fixture.claimURL(for: source).path))
    }

    private enum ProbeFailure: Error {
        case stop
    }

    private static func nodeCoordinatorURL(_ fixture: DeviceIdentityMigrationFixture) -> URL {
        // The fixture root exists; resolve that ancestor before adding the absent database path.
        let stateURL = fixture.root.resolvingSymlinksInPath().appendingPathComponent("destination")
        let databaseURL = stateURL.appendingPathComponent("state/openclaw.sqlite")
        let digest = SHA256.hash(data: Data(databaseURL.path.utf8))
        let pathHash = digest.prefix(4).map { String(format: "%02x", $0) }.joined()
        return stateURL.appendingPathComponent("tmp/openclaw-\(getuid())")
            .appendingPathComponent("device-identity.\(pathHash).lock.sqlite")
    }

    private static func probeCoordinator(_ url: URL) throws -> Int32 {
        try FileManager.default.createDirectory(
            at: url.deletingLastPathComponent(),
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])
        var database: OpaquePointer?
        let result = sqlite3_open_v2(url.path, &database, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nil)
        guard result == SQLITE_OK, let database else {
            if let database { sqlite3_close(database) }
            throw NSError(domain: "DeviceIdentityCoordinatorTests", code: Int(result))
        }
        defer { sqlite3_close(database) }
        sqlite3_busy_timeout(database, 0)
        let acquireResult = sqlite3_exec(database, "BEGIN EXCLUSIVE", nil, nil, nil)
        if acquireResult == SQLITE_OK {
            #expect(sqlite3_exec(database, "ROLLBACK", nil, nil, nil) == SQLITE_OK)
        }
        return acquireResult
    }

    private static func permissions(_ url: URL) throws -> Int {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        return try #require(attributes[.posixPermissions] as? NSNumber).intValue
    }
}
