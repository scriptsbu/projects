import Foundation

struct DiskInfo: Identifiable, Hashable {
    let id: String          // e.g. "disk2"
    let deviceNode: String  // e.g. "/dev/disk2"
    let name: String        // e.g. "DataTraveler 3.0" (media/hardware name)
    let volumeNames: [String] // e.g. ["ESD-USB", "Images"] (Finder-visible volume labels)
    let size: String        // e.g. "16.0 GB"
    let sizeBytes: UInt64
    let isExternal: Bool
    let isRemovable: Bool
    let mediaType: String   // e.g. "USB", "SSD", "Internal"

    /// Display like Finder: "DataTraveler 3.0 [ESD-USB]"
    var displayName: String {
        let label = name.isEmpty ? "Untitled" : name
        if !volumeNames.isEmpty {
            let volumes = volumeNames.joined(separator: ", ")
            return "\(label) [\(volumes)]"
        }
        return label
    }

    var rdiskNode: String {
        deviceNode.replacingOccurrences(of: "/dev/disk", with: "/dev/rdisk")
    }
}

class DiskManager {

    /// Parse `diskutil list -plist` to get whole-disk identifiers and volume names, then get info on each.
    static func listDisks() async -> [DiskInfo] {
        guard let plistData = runCommand("/usr/sbin/diskutil", arguments: ["list", "-plist"]) else {
            return []
        }

        guard let plist = try? PropertyListSerialization.propertyList(from: plistData, format: nil) as? [String: Any],
              let allDisks = plist["AllDisksAndPartitions"] as? [[String: Any]] else {
            return []
        }

        var disks: [DiskInfo] = []

        for entry in allDisks {
            guard let deviceId = entry["DeviceIdentifier"] as? String else { continue }

            // Collect volume names from partitions
            let volumeNames = extractVolumeNames(from: entry)

            if let info = getDiskInfo(deviceId, volumeNames: volumeNames) {
                if info.id == "disk0" { continue }
                if info.mediaType == "Disk Image" || info.mediaType == "Synthesized" { continue }
                disks.append(info)
            }
        }

        return disks
    }

    /// Extract volume names from the partition entries in diskutil list -plist output
    private static func extractVolumeNames(from diskEntry: [String: Any]) -> [String] {
        var names: [String] = []

        // Top-level volume name (for single-partition disks)
        if let volName = diskEntry["VolumeName"] as? String, !volName.isEmpty {
            names.append(volName)
        }

        // Check partitions
        if let partitions = diskEntry["Partitions"] as? [[String: Any]] {
            for partition in partitions {
                if let volName = partition["VolumeName"] as? String, !volName.isEmpty {
                    if !names.contains(volName) {
                        names.append(volName)
                    }
                }
            }
        }

        // Check APFSVolumes inside APFS containers
        if let partitions = diskEntry["Partitions"] as? [[String: Any]] {
            for partition in partitions {
                if let apfsVolumes = partition["APFSVolumes"] as? [[String: Any]] {
                    for vol in apfsVolumes {
                        if let volName = vol["VolumeName"] as? String, !volName.isEmpty {
                            if !names.contains(volName) {
                                names.append(volName)
                            }
                        }
                    }
                }
            }
        }

        // Also check top-level APFSVolumes (some formats put them here)
        if let apfsVolumes = diskEntry["APFSVolumes"] as? [[String: Any]] {
            for vol in apfsVolumes {
                if let volName = vol["VolumeName"] as? String, !volName.isEmpty {
                    if !names.contains(volName) {
                        names.append(volName)
                    }
                }
            }
        }

        return names
    }

    static func getDiskInfo(_ diskId: String, volumeNames: [String] = []) -> DiskInfo? {
        guard let data = runCommand("/usr/sbin/diskutil", arguments: ["info", "-plist", diskId]),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            return nil
        }

        let deviceNode = plist["DeviceNode"] as? String ?? "/dev/\(diskId)"
        let name = plist["MediaName"] as? String ?? plist["VolumeName"] as? String ?? ""
        let totalSize = plist["TotalSize"] as? UInt64 ?? plist["Size"] as? UInt64 ?? 0
        let isExternal = plist["Removable"] as? Bool ?? plist["RemovableMedia"] as? Bool ?? false
        let isRemovableMedia = plist["RemovableMediaOrExternalDevice"] as? Bool ?? false
        let isInternal = plist["Internal"] as? Bool ?? true
        let isSynthesized = plist["VirtualOrPhysical"] as? String == "Virtual"
        let isDiskImage = plist["DiskImagePath"] as? String != nil
        let protocol_ = plist["BusProtocol"] as? String ?? ""

        if isDiskImage { return nil }
        if isSynthesized {
            return DiskInfo(id: diskId, deviceNode: deviceNode, name: name,
                          volumeNames: volumeNames,
                          size: formatBytes(totalSize), sizeBytes: totalSize,
                          isExternal: false, isRemovable: false, mediaType: "Synthesized")
        }

        let mediaType: String
        if protocol_.lowercased().contains("usb") {
            mediaType = "USB"
        } else if !isInternal {
            mediaType = "External"
        } else if plist["SolidState"] as? Bool == true {
            mediaType = "SSD"
        } else {
            mediaType = "Internal"
        }

        return DiskInfo(
            id: diskId,
            deviceNode: deviceNode,
            name: name,
            volumeNames: volumeNames,
            size: formatBytes(totalSize),
            sizeBytes: totalSize,
            isExternal: !isInternal || isRemovableMedia,
            isRemovable: isExternal || isRemovableMedia,
            mediaType: mediaType
        )
    }

    /// Unmount all volumes on a disk (required before dd)
    static func unmountDisk(_ diskId: String) -> (Bool, String) {
        let result = runCommandWithStatus("/usr/sbin/diskutil", arguments: ["unmountDisk", diskId])
        return result
    }

    static func formatBytes(_ bytes: UInt64) -> String {
        let formatter = ByteCountFormatter()
        formatter.allowedUnits = [.useGB, .useMB]
        formatter.countStyle = .file
        return formatter.string(fromByteCount: Int64(bytes))
    }

    private static func runCommand(_ path: String, arguments: [String]) -> Data? {
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

    private static func runCommandWithStatus(_ path: String, arguments: [String]) -> (Bool, String) {
        let process = Process()
        let outPipe = Pipe()
        let errPipe = Pipe()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.standardOutput = outPipe
        process.standardError = errPipe

        do {
            try process.run()
            process.waitUntilExit()
            let outData = outPipe.fileHandleForReading.readDataToEndOfFile()
            let errData = errPipe.fileHandleForReading.readDataToEndOfFile()
            let output = String(data: outData, encoding: .utf8) ?? ""
            let errOutput = String(data: errData, encoding: .utf8) ?? ""
            let success = process.terminationStatus == 0
            return (success, success ? output : errOutput)
        } catch {
            return (false, error.localizedDescription)
        }
    }
}
