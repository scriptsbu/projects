# DiskCloner — Project Context for Claude

## What This Is
A macOS SwiftUI app that clones USB drives and SSDs. Built as a simple alternative to Carbon Copy Cloner, focused on duplicating bootable USB drives (Acronis, Windows PE) and occasional SSD cloning.

## Architecture

### Files
- `DiskCloner/DiskClonerApp.swift` — App entry point, About menu
- `DiskCloner/ContentView.swift` — Main UI: disk picker, clone method selector, progress panel
- `DiskCloner/CloneEngine.swift` — All cloning logic: Smart Clone, dd, ASR
- `DiskCloner/DiskInfo.swift` — Disk detection via `diskutil`, volume name extraction
- `Package.swift` — Swift Package Manager config (macOS 14+, no dependencies)

### Clone Methods
1. **Smart Clone** (`runSmartClone`) — The primary method. Erases destination as MBR FAT32, mounts both disks, rsync's files. Handles size mismatch (large source → small destination). Uses `osascript` for admin-only operations (diskutil erase) and runs rsync as current user (FAT32 volumes are user-accessible).
2. **Block Copy** (`runDDClone`) — Raw `dd` byte-for-byte copy. Needs Full Disk Access on modern macOS.
3. **ASR** (`runASRClone`) — Apple Software Restore for macOS volumes.

### Key Design Decisions
- **Single admin password prompt**: Only `diskutil eraseDisk` needs admin. rsync runs unprivileged since FAT32 volumes are user-readable on macOS.
- **No raw disk access in Smart Clone**: macOS blocks `dd` on `/dev/rdisk*` without Full Disk Access. EFI boot files (`bootmgfw.efi`, `EFI/` folder) make USBs bootable without needing MBR/VBR boot sectors.
- **macOS metadata excluded**: rsync skips `.Spotlight-V100`, `.fseventsd`, `.Trashes`, `.DS_Store` — these are macOS indexing artifacts irrelevant to bootability.
- **rsync exit code 23 = success**: Partial transfer (non-critical locked files skipped) is treated as success.
- **Volume name preserved**: Destination gets the source's volume name, sanitized for FAT32 (11 chars, uppercase).

### Disk Detection
`DiskManager.listDisks()` uses `diskutil list -plist` to enumerate disks and partitions. It:
- Skips disk0 (boot drive), disk images, and synthesized (APFS container) disks
- Extracts volume names from partition entries (including APFS volumes)
- Gets disk info via `diskutil info -plist` for each whole disk
- Classifies media type: USB, SSD, External, Internal

### UI Structure
- `ContentView` — Main view with disk pickers, method selector, size warnings, clone button
- `ProgressPanel` — Status header, progress bar, collapsible log viewer with copy button
- `DiskPickerSection` / `DiskRow` — Disk selection with Finder-style names ("DataTraveler 3.0 [ESD-USB]")

## Build & Run
```bash
swift build              # Debug build
swift build -c release   # Release build
swift run                # Build and run
```

## Packaging
```bash
# Build .pkg installer
swift build -c release
mkdir -p dist/DiskCloner.app/Contents/MacOS
cp .build/release/DiskCloner dist/DiskCloner.app/Contents/MacOS/
pkgbuild --root dist --identifier com.saronic.diskcloner --version 1.0.0 --install-location /Applications dist/DiskCloner-1.0.0.pkg
```

## Known Limitations
- Raw disk access (`dd` to `/dev/rdisk`) requires Full Disk Access in System Settings — not granted by default. Smart Clone works around this.
- Not code-signed or notarized — users may need to right-click → Open on first launch, or allow in System Settings > Privacy & Security.
- No partition-level cloning yet (only whole-disk operations).
- ASR may not work on non-macOS formatted volumes.

## Future Ideas
- Code signing + notarization for Gatekeeper
- Disk image creation (.dmg / .iso from USB)
- Partition-level clone (clone specific partitions, not whole disk)
- Verify/compare mode (hash check after clone)
- NTFS support via ntfs-3g for Windows volumes
- Drag-and-drop disk selection
- Menu bar mode for quick access
