# Disk Cloner

A simple, free macOS utility for cloning USB drives and SSDs. Built for duplicating bootable USB drives (Acronis, Windows PE, Windows installers, recovery media) and general disk cloning.

## Features

- **Smart Clone** (recommended) — Copies partition layout + files. Works when the destination is smaller than the source, as long as the actual data fits. Automatically picks FAT32 or ExFAT depending on file sizes (ExFAT for files >4GB like Windows `install.wim`).
- **Block Copy (dd)** — Byte-for-byte whole-disk clone. Requires Full Disk Access on macOS. If it fails, the app suggests using Smart Clone instead.
- **Apple Software Restore (asr)** — macOS-native volume restore for APFS/HFS+ volumes.
- Live progress log with streaming rsync output
- Automatic volume name preservation from source
- Auto-detect filesystem: FAT32 for small files, ExFAT for files >4GB
- Excludes macOS metadata (`.Spotlight-V100`, `.fseventsd`, `.Trashes`)
- Single admin password prompt per operation

## Install

### Option 1: One-liner CLI (no install needed)

```bash
curl -fsSL https://raw.githubusercontent.com/scriptsbu/projects/main/DiskCloner/diskcloner.sh | bash
```

Or download and run locally:

```bash
curl -fsSL -o diskcloner.sh https://raw.githubusercontent.com/scriptsbu/projects/main/DiskCloner/diskcloner.sh
chmod +x diskcloner.sh
./diskcloner.sh
```

### Option 2: Download the .pkg (GUI app)

Download `DiskCloner-1.0.0.pkg` from the [Releases](../../releases) page and double-click to install. The app will be placed in `/Applications/DiskCloner.app`.

### Option 3: Build GUI from source

Requires Xcode 15+ and macOS 14+.

```bash
git clone https://github.com/scriptsbu/projects.git
cd projects/DiskCloner
swift build -c release
.build/release/DiskCloner
```

## Usage

### CLI

Run the script and follow the interactive prompts:

```
╔══════════════════════════════════════╗
║         DiskCloner CLI v1.0          ║
║   Simple disk cloning for macOS      ║
╚══════════════════════════════════════╝

▸ Scanning for disks...

Available Disks:

  1)  DataTraveler 3.0 [ESD-USB]
      /dev/disk5 — 248.0 GB — USB

  2)  USB 3.2.1 FD [USB321FD]
      /dev/disk4 — 31.0 GB — USB

Select SOURCE disk [1-2]: 1
Select DESTINATION disk [1-2]: 2
Select method [1-3, default=1]: 1

⚠  WARNING: This will ERASE ALL DATA on the destination disk!
Type 'yes' to confirm: yes
```

### GUI App

1. Connect source and destination USB drives / SSDs
2. Open Disk Cloner
3. Select the **Source Disk** and **Destination Disk**
4. Choose a clone method:
   - **Smart Clone** for bootable USBs, Windows installers, smaller destinations
   - **Block Copy** for exact byte-for-byte duplicates (needs Full Disk Access)
   - **ASR** for macOS APFS/HFS+ volumes
5. Click **Start Clone**, confirm, enter your admin password once
6. Watch progress in the live log

## How Smart Clone Works

Smart Clone is designed for the common case of duplicating a bootable USB (like Acronis or Windows PE) where the source drive is large (e.g., 256GB) but the actual data is small (e.g., 600MB), and you want to clone it to a smaller drive (e.g., 32GB).

1. Scans source for files >4GB — picks **ExFAT** (for Windows installers with large `.wim` files) or **FAT32** (for everything else)
2. Erases the destination with the chosen filesystem (preserving the source volume name)
3. Mounts both drives
4. Uses `rsync` to copy all files, preserving directory structure
5. The EFI boot files (`EFI/Boot/bootx64.efi`, `bootmgfw.efi`, `Boot/BCD`) make the destination bootable on modern UEFI PCs

**Note:** macOS restricts raw disk access, so MBR/VBR boot sector copying is skipped. The cloned USB boots via EFI, which all modern PCs support. For legacy BIOS-only boot, you would need to grant Full Disk Access to the app in System Settings > Privacy & Security.

## Block Copy (dd) and Full Disk Access

Block Copy uses `dd` for raw byte-for-byte disk cloning. On modern macOS, this requires **Full Disk Access** (System Settings > Privacy & Security > Full Disk Access). If Block Copy fails, the app will suggest using Smart Clone instead — which works without any special permissions and handles most use cases.

## Requirements

- macOS 14 (Sonoma) or later
- Xcode 15+ (for building from source only)
- Admin privileges (for disk erase operations)

## License

MIT License — free to use, modify, and distribute.

## Credits

Created by Alberto Lopez-Santiago
Built with [Claude Code](https://claude.com/claude-code) (Anthropic)
