import Foundation

/// Mounting remote directories over SSH with FUSE-T sshfs.
///
/// FUSE-T only — it is kextless (a local NFSv4 loopback server), needs no
/// restart, no Recovery-mode security downgrade, and no root, matching how
/// Burrow runs everything else in userspace. macFUSE is deliberately not
/// supported.
public enum FolderSupport {
    /// FUSE-T's sshfs. /usr/local/bin is its fixed install location; the
    /// PATH fallback still requires the FUSE-T library so a macFUSE sshfs
    /// can't sneak in.
    public static func sshfsPath() -> String? {
        if let override = ProcessInfo.processInfo.environment["BURROW_SSHFS"],
           FileManager.default.isExecutableFile(atPath: override) {
            return override
        }
        let fixed = "/usr/local/bin/sshfs"
        if FileManager.default.isExecutableFile(atPath: fixed), fuseTInstalled() {
            return fixed
        }
        return nil
    }

    public static func fuseTInstalled() -> Bool {
        (try? FileManager.default.contentsOfDirectory(atPath: "/usr/local/lib"))?
            .contains { $0.hasPrefix("libfuse-t") } ?? false
    }

    /// sshfs arguments for a folder. BatchMode keeps a silent mount from
    /// hanging on an interactive prompt: with a warm master it succeeds
    /// instantly; without one it fails fast with a classifiable error.
    public static func buildArguments(for folder: FolderConfig) -> [String] {
        let target = folder.user.map { "\($0)@\(folder.host)" } ?? folder.host
        var args = [
            "\(target):\(folder.remotePath)",
            folder.effectiveLocalPath,
            "-o", "volname=\(folder.name)",
            "-o", "reconnect",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
            "-o", "BatchMode=yes",
            "-o", "follow_symlinks",
        ]
        if let jump = folder.jumpHost, !jump.isEmpty {
            // FUSE-T's sshfs (2.9) rejects -o ProxyJump; route it via the
            // ssh command line instead.
            args.append(contentsOf: ["-o", "ssh_command=ssh -J \(jump)"])
        }
        for option in folder.extraOptions where !option.isEmpty {
            args.append(contentsOf: ["-o", option])
        }
        return args
    }

    /// Whether the folder's mountpoint currently has a FUSE-T mount on it.
    public static func isMounted(_ folder: FolderConfig) -> Bool {
        fuseMountCount(at: folder.effectiveLocalPath) > 0
    }

    /// How many FUSE-T mounts sit on `path`, read from the kernel mount table
    /// with MNT_NOWAIT. Never statfs(path) here: on a dead mount that blocks
    /// for minutes, and it can't see *stacked* mounts — the exact combination
    /// that let a remount pile seven dead layers on one mountpoint.
    public static func fuseMountCount(at path: String) -> Int {
        var entries: UnsafeMutablePointer<statfs>?
        let count = getmntinfo(&entries, MNT_NOWAIT)
        guard count > 0, let entries else { return 0 }
        var matches = 0
        for index in 0..<Int(count) {
            var entry = entries[index]
            let mountedOn = withUnsafeBytes(of: &entry.f_mntonname) { raw in
                String(cString: raw.bindMemory(to: CChar.self).baseAddress!)
            }
            guard mountedOn == path else { continue }
            let from = withUnsafeBytes(of: &entry.f_mntfromname) { raw in
                String(cString: raw.bindMemory(to: CChar.self).baseAddress!)
            }
            if from.hasPrefix("fuse-t:") {
                matches += 1
            }
        }
        return matches
    }

    public struct MountResult: Sendable {
        public let succeeded: Bool
        public let output: String
    }

    /// Mounts the folder, creating the mountpoint if needed. Blocking — call
    /// off the main thread. sshfs daemonizes once the mount is up, so a
    /// successful call returns quickly.
    public static func mount(_ folder: FolderConfig, executablePath: String) -> MountResult {
        let localPath = folder.effectiveLocalPath
        // A dead mount (VPN dropped, host gone) still occupies the mountpoint;
        // mounting over it stacks layers that hang Finder and every file-table
        // scan on the machine. Clear any existing layers first.
        if fuseMountCount(at: localPath) > 0 && !unmount(folder) {
            return MountResult(succeeded: false, output: "a previous mount is stuck at \(localPath) and couldn't be removed — close anything using it and try again")
        }
        do {
            try FileManager.default.createDirectory(atPath: localPath, withIntermediateDirectories: true)
        } catch {
            return MountResult(succeeded: false, output: "couldn't create \(localPath): \(error.localizedDescription)")
        }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executablePath)
        process.arguments = buildArguments(for: folder)
        process.standardOutput = FileHandle.nullDevice
        // Same trap as SSHHostWarmer: the daemonized sshfs child inherits a
        // piped stderr and holds it open for the mount's lifetime, so capture
        // through a temp file instead of a pipe.
        let logURL = FileManager.default.temporaryDirectory
            .appendingPathComponent("burrow-sshfs-\(UUID().uuidString).log")
        FileManager.default.createFile(atPath: logURL.path, contents: nil)
        let errorHandle = try? FileHandle(forWritingTo: logURL)
        process.standardError = errorHandle ?? FileHandle.nullDevice
        defer {
            try? errorHandle?.close()
            try? FileManager.default.removeItem(at: logURL)
        }
        do {
            try process.run()
        } catch {
            return MountResult(succeeded: false, output: "failed to launch sshfs: \(error.localizedDescription)")
        }
        process.waitUntilExit()
        let output = ((try? String(contentsOf: logURL, encoding: .utf8)) ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return MountResult(succeeded: process.terminationStatus == 0 && isMounted(folder), output: output)
    }

    /// Unmounts (popping every stacked layer) and removes an empty auto-created
    /// mountpoint. Falls back to a forced unmount for a busy or dead mount.
    @discardableResult
    public static func unmount(_ folder: FolderConfig) -> Bool {
        let localPath = folder.effectiveLocalPath
        // Each umount removes one layer; a healthy mountpoint has one, but a
        // remount-over-dead-mount bug can stack several — pop them all.
        var remaining = fuseMountCount(at: localPath)
        var attempts = 0
        while remaining > 0 && attempts < remaining + 8 {
            attempts += 1
            if runQuietly("/sbin/umount", [localPath]) != 0,
               runQuietly("/sbin/umount", ["-f", localPath]) != 0,
               runQuietly("/usr/sbin/diskutil", ["unmount", "force", localPath]) != 0 {
                break
            }
            remaining = fuseMountCount(at: localPath)
        }
        let unmounted = fuseMountCount(at: localPath) == 0
        if unmounted {
            // rmdir only removes an EMPTY directory — a stray mountpoint dir —
            // and fails harmlessly otherwise. Never a recursive delete here.
            _ = rmdir(localPath)
        }
        return unmounted
    }

    private static func runQuietly(_ path: String, _ arguments: [String]) -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
        } catch {
            return -1
        }
        process.waitUntilExit()
        return process.terminationStatus
    }
}
