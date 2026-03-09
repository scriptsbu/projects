import Foundation

enum CloneMethod: String, CaseIterable {
    case smart = "Smart Clone"
    case dd = "Block Copy (dd)"
    case asr = "Apple Software Restore (asr)"

    var description: String {
        switch self {
        case .smart: return "Copies partition + files. Works when destination is smaller than source but larger than actual data."
        case .dd: return "Byte-for-byte whole-disk copy. Source and destination must be the same size or destination larger."
        case .asr: return "macOS-native restore. Best for macOS volumes (APFS/HFS+)."
        }
    }
}

enum CloneStatus: Equatable {
    case idle
    case unmounting
    case preparing
    case cloning
    case completed
    case failed(String)

    static func == (lhs: CloneStatus, rhs: CloneStatus) -> Bool {
        switch (lhs, rhs) {
        case (.idle, .idle), (.unmounting, .unmounting),
             (.preparing, .preparing),
             (.cloning, .cloning),
             (.completed, .completed):
            return true
        case (.failed(let a), .failed(let b)):
            return a == b
        default:
            return false
        }
    }
}

@MainActor
class CloneEngine: ObservableObject {
    @Published var status: CloneStatus = .idle
    @Published var progress: Double = 0
    @Published var currentStep: String = ""
    @Published var log: [String] = []
    @Published var showLog = false

    nonisolated(unsafe) private var activeProcess: Process?
    private var cancelled = false

    func clone(source: DiskInfo, destination: DiskInfo, method: CloneMethod) {
        cancelled = false
        log = []
        progress = 0
        currentStep = ""
        showLog = true

        Task {
            switch method {
            case .smart:
                await runSmartClone(source: source, destination: destination)
            case .dd:
                await runDDClone(source: source, destination: destination)
            case .asr:
                await runASRClone(source: source, destination: destination)
            }
        }
    }

    func cancel() {
        cancelled = true
        activeProcess?.terminate()
        appendLog("--- Cancelled by user ---")
        status = .failed("Cancelled by user")
    }

    // MARK: - Smart Clone

    private func runSmartClone(source: DiskInfo, destination: DiskInfo) async {
        status = .preparing
        appendLog("=== Smart Clone ===")
        appendLog("Source: \(source.displayName) (\(source.deviceNode))")
        appendLog("Destination: \(destination.displayName) (\(destination.deviceNode))")

        let srcPart = findFirstDataPartition(source.id) ?? "\(source.id)s1"
        let dstPart = findFirstDataPartition(destination.id) ?? "\(destination.id)s1"

        // Mount source first to check file sizes
        let _ = await runLocal("/usr/sbin/diskutil", args: ["mountDisk", source.deviceNode])
        try? await Task.sleep(nanoseconds: 1_000_000_000)

        let srcMountForCheck = findMountPoint(srcPart)
            ?? findMountPoint("\(source.id)s1")
            ?? findMountPoint("\(source.id)s2")

        // Detect if any file exceeds 4GB (FAT32 limit)
        let needsExFAT: Bool
        if let mountPath = srcMountForCheck {
            let maxFileSize = findLargestFile(at: mountPath)
            let fat32Limit: UInt64 = 4_294_967_295 // 4GB - 1 byte
            needsExFAT = maxFileSize > fat32Limit
            if needsExFAT {
                appendLog("Detected file > 4GB (\(DiskManager.formatBytes(maxFileSize))). Using ExFAT instead of FAT32.")
            }
        } else {
            needsExFAT = false
        }

        let fsType = needsExFAT ? "ExFAT" : "FAT32"
        let srcVolName = source.volumeNames.first ?? source.name
        let volumeName = sanitizeFAT32Name(srcVolName)
        appendLog("Filesystem: \(fsType) | Volume name: \(volumeName)")

        // Step 1: Erase destination (requires admin — single password prompt)
        updateStep("Erasing destination as MBR \(fsType)...", step: 1, of: 5)

        let eraseScript = """
        diskutil unmountDisk \(destination.deviceNode) 2>/dev/null || true
        diskutil eraseDisk \(fsType) \(volumeName) MBRFormat \(destination.deviceNode) 2>&1
        """
        let eraseOk = await runPrivileged(eraseScript)
        if !eraseOk {
            if cancelled { return }
            status = .failed("Failed to erase destination disk")
            return
        }

        if cancelled { return }

        // Step 2: Mount both disks (no admin needed for diskutil mount)
        updateStep("Mounting disks...", step: 2, of: 5)

        // Make sure source is mounted
        let _ = await runLocal("/usr/sbin/diskutil", args: ["mountDisk", source.deviceNode])
        // Destination should already be mounted after erase, but ensure it
        let _ = await runLocal("/usr/sbin/diskutil", args: ["mountDisk", destination.deviceNode])

        // Small delay for mount to settle
        try? await Task.sleep(nanoseconds: 2_000_000_000)

        if cancelled { return }

        // Step 3: Find mount points
        updateStep("Locating volumes...", step: 3, of: 5)

        let srcMount = findMountPoint(srcPart) ?? findMountPoint("\(source.id)s1")
            ?? findMountPoint("\(source.id)s2")
        let dstMount = findMountPoint(dstPart) ?? findMountPoint("\(destination.id)s1")

        guard let srcPath = srcMount, let dstPath = dstMount else {
            appendLog("ERROR: Could not find mount points")
            appendLog("Source partitions checked: \(srcPart), \(source.id)s1, \(source.id)s2")
            appendLog("Destination partitions checked: \(dstPart), \(destination.id)s1")
            if let src = srcMount { appendLog("Source mounted at: \(src)") }
            else { appendLog("Source: NOT MOUNTED") }
            if let dst = dstMount { appendLog("Destination mounted at: \(dst)") }
            else { appendLog("Destination: NOT MOUNTED") }
            status = .failed("Could not mount volumes — see log")
            return
        }

        appendLog("Source volume: \(srcPath)")
        appendLog("Destination volume: \(dstPath)")

        if cancelled { return }

        // Step 4: Copy files with rsync (runs as current user — FAT32 is user-accessible)
        status = .cloning
        updateStep("Copying files...", step: 4, of: 5)

        let rsyncExitCode = await runLocalStreamingWithExitCode(
            "/usr/bin/rsync",
            args: [
                "-av", "--delete", "--progress",
                "--exclude", ".Spotlight-V100",
                "--exclude", ".fseventsd",
                "--exclude", ".Trashes",
                "--exclude", ".DS_Store",
                "\(srcPath)/", "\(dstPath)/"
            ]
        )

        // Exit code 0 = success, 23 = partial transfer (non-critical files skipped, e.g. locked Spotlight files)
        if rsyncExitCode != 0 && rsyncExitCode != 23 {
            if cancelled { return }
            status = .failed("File copy failed (exit code \(rsyncExitCode)) — see log")
            return
        }
        if rsyncExitCode == 23 {
            appendLog("NOTE: Some non-critical files were skipped (exit 23). This is normal.")
        }

        if cancelled { return }

        // Step 5: Sync
        updateStep("Syncing buffers...", step: 5, of: 5)
        let _ = await runLocal("/bin/sync", args: [])

        appendLog("NOTE: MBR/VBR boot sector copy skipped (macOS restricts raw disk access).")
        appendLog("The USB will boot via EFI (bootmgfw.efi). All modern PCs support EFI boot.")

        status = .completed
        progress = 1.0
        currentStep = "Done!"
        appendLog("=== Smart Clone completed successfully! ===")
    }

    // MARK: - Block Copy (dd)

    private func runDDClone(source: DiskInfo, destination: DiskInfo) async {
        status = .preparing
        appendLog("=== Block Copy (dd) ===")
        appendLog("Source: \(source.rdiskNode) -> Destination: \(destination.rdiskNode)")
        appendLog("Total size: \(source.size)")
        appendLog("This copies the entire disk byte-for-byte. It may take a long time.")

        updateStep("Unmounting and starting block copy...", step: 1, of: 2)

        // dd on raw disks requires the calling app to have Full Disk Access on modern macOS.
        // osascript's "with administrator privileges" runs as root but still lacks FDA.
        let script = """
        diskutil unmountDisk \(destination.deviceNode) 2>/dev/null || true
        diskutil unmountDisk \(source.deviceNode) 2>/dev/null || true
        dd if=\(source.rdiskNode) of=\(destination.rdiskNode) bs=1m 2>&1 && sync
        """

        status = .cloning
        let success = await runPrivileged(script)

        if cancelled { return }

        if success {
            updateStep("Done!", step: 2, of: 2)
            status = .completed
            progress = 1.0
            appendLog("Block copy completed successfully!")
        } else {
            appendLog("")
            appendLog("Block Copy failed. This can happen when macOS restricts raw disk access.")
            appendLog("Possible fixes:")
            appendLog("  1. Use Smart Clone instead (recommended) — it copies files without")
            appendLog("     raw disk access and works for bootable USBs and Windows installers.")
            appendLog("  2. Grant Full Disk Access: System Settings > Privacy & Security")
            appendLog("     > Full Disk Access > Add Terminal.app, then retry.")
            appendLog("  3. Try a different USB port or re-insert the drive.")
            status = .failed("Block copy failed — try Smart Clone instead")
        }
    }

    // MARK: - ASR

    private func runASRClone(source: DiskInfo, destination: DiskInfo) async {
        status = .preparing
        appendLog("=== Apple Software Restore ===")
        appendLog("Source: \(source.deviceNode) -> Destination: \(destination.deviceNode)")

        updateStep("Starting ASR restore...", step: 1, of: 2)

        let script = """
        diskutil unmountDisk \(destination.deviceNode) 2>/dev/null || true
        asr restore --source \(source.deviceNode) --target \(destination.deviceNode) --erase --noprompt 2>&1
        """

        status = .cloning
        let success = await runPrivileged(script)

        if cancelled { return }

        if success {
            updateStep("Done!", step: 2, of: 2)
            status = .completed
            progress = 1.0
            appendLog("ASR restore completed successfully!")
        } else {
            status = .failed("asr failed — see log")
        }
    }

    // MARK: - Execution Helpers

    /// Run a command with admin privileges via osascript (single password prompt).
    /// Use only for diskutil/system commands, NOT for file operations.
    private func runPrivileged(_ script: String) async -> Bool {
        appendLog("Requesting administrator privileges...")

        return await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                let process = Process()
                let outPipe = Pipe()

                // AppleScript's "do shell script" doesn't support literal newlines
                // in the string — join lines with "; " so the shell runs them sequentially
                let escaped = script
                    .components(separatedBy: "\n")
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty }
                    .joined(separator: "; ")
                    .replacingOccurrences(of: "\\", with: "\\\\")
                    .replacingOccurrences(of: "\"", with: "\\\"")

                process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
                process.arguments = [
                    "-e",
                    "do shell script \"\(escaped)\" with administrator privileges"
                ]
                process.standardOutput = outPipe
                process.standardError = outPipe

                DispatchQueue.main.async { self?.activeProcess = process }

                do {
                    try process.run()
                    process.waitUntilExit()

                    let data = outPipe.fileHandleForReading.readDataToEndOfFile()
                    let output = String(data: data, encoding: .utf8) ?? ""
                    let success = process.terminationStatus == 0

                    DispatchQueue.main.async {
                        // Log the output
                        for line in output.components(separatedBy: "\n") {
                            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                            if !trimmed.isEmpty {
                                self?.appendLog(trimmed)
                            }
                        }
                        self?.activeProcess = nil
                        continuation.resume(returning: success)
                    }
                } catch {
                    DispatchQueue.main.async {
                        self?.appendLog("Error: \(error.localizedDescription)")
                        self?.activeProcess = nil
                        continuation.resume(returning: false)
                    }
                }
            }
        }
    }

    /// Run a local (non-privileged) command and return success/failure.
    private func runLocal(_ path: String, args: [String]) async -> Bool {
        return await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                let process = Process()
                let outPipe = Pipe()
                process.executableURL = URL(fileURLWithPath: path)
                process.arguments = args
                process.standardOutput = outPipe
                process.standardError = outPipe

                do {
                    try process.run()
                    process.waitUntilExit()
                    let data = outPipe.fileHandleForReading.readDataToEndOfFile()
                    let output = String(data: data, encoding: .utf8) ?? ""
                    let success = process.terminationStatus == 0

                    DispatchQueue.main.async {
                        for line in output.components(separatedBy: "\n") {
                            let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                            if !trimmed.isEmpty {
                                self?.appendLog(trimmed)
                            }
                        }
                        continuation.resume(returning: success)
                    }
                } catch {
                    DispatchQueue.main.async {
                        self?.appendLog("Error: \(error.localizedDescription)")
                        continuation.resume(returning: false)
                    }
                }
            }
        }
    }

    /// Run a local command with live streaming output (for rsync progress). Returns exit code.
    private func runLocalStreamingWithExitCode(_ path: String, args: [String]) async -> Int32 {
        return await withCheckedContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                let process = Process()
                let outPipe = Pipe()
                process.executableURL = URL(fileURLWithPath: path)
                process.arguments = args
                process.standardOutput = outPipe
                process.standardError = outPipe

                DispatchQueue.main.async { self?.activeProcess = process }

                // Stream output line by line
                let handle = outPipe.fileHandleForReading
                var lineBuffer = ""
                var fileCount = 0

                handle.readabilityHandler = { fileHandle in
                    let data = fileHandle.availableData
                    guard !data.isEmpty else { return }
                    guard let chunk = String(data: data, encoding: .utf8) else { return }

                    lineBuffer += chunk
                    while let newlineRange = lineBuffer.range(of: "\n") {
                        let line = String(lineBuffer[lineBuffer.startIndex..<newlineRange.lowerBound])
                            .trimmingCharacters(in: .whitespacesAndNewlines)
                        lineBuffer = String(lineBuffer[newlineRange.upperBound...])

                        if !line.isEmpty {
                            // Count files for progress display
                            if !line.hasPrefix("sending") && !line.hasPrefix("sent ")
                                && !line.hasPrefix("total ") && !line.hasPrefix("building")
                                && !line.contains("bytes/sec") {
                                fileCount += 1
                            }

                            DispatchQueue.main.async {
                                self?.appendLog(line)
                                self?.currentStep = "Copying files... (\(fileCount) files)"
                            }
                        }
                    }
                }

                do {
                    try process.run()
                    process.waitUntilExit()

                    handle.readabilityHandler = nil

                    // Read any remaining data
                    let remaining = handle.readDataToEndOfFile()
                    if !remaining.isEmpty, let text = String(data: remaining, encoding: .utf8) {
                        let lines = text.components(separatedBy: "\n")
                        DispatchQueue.main.async {
                            for line in lines {
                                let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
                                if !trimmed.isEmpty {
                                    self?.appendLog(trimmed)
                                }
                            }
                        }
                    }

                    let exitCode = process.terminationStatus

                    DispatchQueue.main.async {
                        self?.activeProcess = nil
                        continuation.resume(returning: exitCode)
                    }
                } catch {
                    handle.readabilityHandler = nil
                    DispatchQueue.main.async {
                        self?.appendLog("Error: \(error.localizedDescription)")
                        self?.activeProcess = nil
                        continuation.resume(returning: -1)
                    }
                }
            }
        }
    }

    // MARK: - Helpers

    /// Sanitize a volume name for FAT32 (max 11 chars, uppercase, alphanumeric + hyphen/underscore)
    /// Find the largest file size in a directory tree
    private func findLargestFile(at path: String) -> UInt64 {
        let fm = FileManager.default
        guard let enumerator = fm.enumerator(atPath: path) else { return 0 }
        var maxSize: UInt64 = 0
        while let file = enumerator.nextObject() as? String {
            let fullPath = (path as NSString).appendingPathComponent(file)
            if let attrs = try? fm.attributesOfItem(atPath: fullPath),
               let size = attrs[.size] as? UInt64 {
                if size > maxSize { maxSize = size }
            }
        }
        return maxSize
    }

    private func sanitizeFAT32Name(_ name: String) -> String {
        let cleaned = name.uppercased()
            .replacingOccurrences(of: " ", with: "-")
            .filter { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" }
        let truncated = String(cleaned.prefix(11))
        return truncated.isEmpty ? "CLONED" : truncated
    }

    private func updateStep(_ text: String, step: Int, of total: Int) {
        currentStep = text
        progress = Double(step - 1) / Double(total)
        appendLog(">> \(text)")
    }

    private func findFirstDataPartition(_ diskId: String) -> String? {
        guard let data = runCommandSync("/usr/sbin/diskutil", arguments: ["list", "-plist", diskId]),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let allDisks = plist["AllDisksAndPartitions"] as? [[String: Any]] else {
            return nil
        }

        for entry in allDisks {
            if let partitions = entry["Partitions"] as? [[String: Any]] {
                for partition in partitions {
                    guard let partId = partition["DeviceIdentifier"] as? String else { continue }
                    let content = partition["Content"] as? String ?? ""
                    if content == "EFI" || content == "Apple_partition_scheme" { continue }
                    return partId
                }
            }
        }
        return "\(diskId)s1"
    }

    private func findMountPoint(_ partitionId: String) -> String? {
        guard let data = runCommandSync("/usr/sbin/diskutil", arguments: ["info", "-plist", partitionId]),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let mountPoint = plist["MountPoint"] as? String,
              !mountPoint.isEmpty else {
            return nil
        }
        return mountPoint
    }

    private func runCommandSync(_ path: String, arguments: [String]) -> Data? {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        do {
            try process.run()
            process.waitUntilExit()
            return pipe.fileHandleForReading.readDataToEndOfFile()
        } catch {
            return nil
        }
    }

    private func appendLog(_ message: String) {
        let timestamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        log.append("[\(timestamp)] \(message)")
    }
}
