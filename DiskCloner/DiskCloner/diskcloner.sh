#!/bin/bash
# DiskCloner CLI — Interactive disk cloning tool for macOS
# https://github.com/scriptsbu/projects/
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/scriptsbu/projects/main/DiskCloner/diskcloner.sh | bash
#   or: bash diskcloner.sh
#   or: ./diskcloner.sh

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Ensure macOS
if [[ "$(uname)" != "Darwin" ]]; then
    echo -e "${RED}Error: This tool only works on macOS.${NC}"
    exit 1
fi

# Ensure running interactively (for curl | bash, reattach to tty)
if [[ ! -t 0 ]]; then
    exec < /dev/tty
fi

banner() {
    echo ""
    echo -e "${BLUE}${BOLD}╔══════════════════════════════════════╗${NC}"
    echo -e "${BLUE}${BOLD}║         DiskCloner CLI v1.0          ║${NC}"
    echo -e "${BLUE}${BOLD}║   Simple disk cloning for macOS      ║${NC}"
    echo -e "${BLUE}${BOLD}╚══════════════════════════════════════╝${NC}"
    echo ""
}

log_step() { echo -e "${CYAN}▸${NC} $1"; }
log_ok()   { echo -e "${GREEN}✓${NC} $1"; }
log_warn() { echo -e "${YELLOW}!${NC} $1"; }
log_err()  { echo -e "${RED}✗${NC} $1"; }
log_info() { echo -e "${DIM}  $1${NC}"; }

# ─── Disk Discovery ───────────────────────────────────────────────────────────

declare -a DISK_IDS=()
declare -a DISK_NAMES=()
declare -a DISK_SIZES=()
declare -a DISK_TYPES=()
declare -a DISK_VOLS=()

discover_disks() {
    DISK_IDS=()
    DISK_NAMES=()
    DISK_SIZES=()
    DISK_TYPES=()
    DISK_VOLS=()

    # Get whole-disk identifiers from diskutil
    local plist
    plist=$(diskutil list -plist 2>/dev/null)

    # Parse each disk
    local disk_ids
    disk_ids=$(echo "$plist" | plutil -extract AllDisksAndPartitions raw -o - - 2>/dev/null | head -20)

    # Simpler approach: parse diskutil list output
    for disk in $(diskutil list | grep "^/dev/disk" | awk '{print $1}' | sed 's|/dev/||'); do
        # Skip disk0 (boot drive) and synthesized disks
        [[ "$disk" == "disk0" ]] && continue

        local info
        info=$(diskutil info -plist "$disk" 2>/dev/null) || continue

        # Skip disk images and synthesized (APFS containers)
        local virtual
        virtual=$(echo "$info" | plutil -extract VirtualOrPhysical raw -o - - 2>/dev/null || echo "")
        [[ "$virtual" == "Virtual" ]] && continue

        local disk_image
        disk_image=$(echo "$info" | plutil -extract DiskImagePath raw -o - - 2>/dev/null || echo "")
        [[ -n "$disk_image" ]] && continue

        local is_internal
        is_internal=$(echo "$info" | plutil -extract Internal raw -o - - 2>/dev/null || echo "true")
        local is_removable
        is_removable=$(echo "$info" | plutil -extract RemovableMediaOrExternalDevice raw -o - - 2>/dev/null || echo "false")

        # Skip internal non-removable (likely the boot SSD)
        [[ "$is_internal" == "true" && "$is_removable" == "false" ]] && continue

        local name size protocol media_type
        name=$(echo "$info" | plutil -extract MediaName raw -o - - 2>/dev/null || echo "Untitled")
        size=$(echo "$info" | plutil -extract TotalSize raw -o - - 2>/dev/null || echo "0")
        protocol=$(echo "$info" | plutil -extract BusProtocol raw -o - - 2>/dev/null || echo "")

        if echo "$protocol" | grep -qi usb; then
            media_type="USB"
        elif [[ "$is_internal" == "false" ]]; then
            media_type="External"
        else
            media_type="Disk"
        fi

        # Get volume names from partitions
        local vols=""
        for part in "${disk}s1" "${disk}s2" "${disk}s3"; do
            local vol_name
            vol_name=$(diskutil info "$part" 2>/dev/null | grep "Volume Name" | sed 's/.*: *//' || true)
            if [[ -n "$vol_name" ]]; then
                [[ -n "$vols" ]] && vols="$vols, "
                vols="$vols$vol_name"
            fi
        done

        # Human-readable size
        local hr_size
        if (( size > 1000000000 )); then
            hr_size="$(echo "scale=1; $size / 1000000000" | bc) GB"
        elif (( size > 1000000 )); then
            hr_size="$(echo "scale=0; $size / 1000000" | bc) MB"
        else
            hr_size="$size bytes"
        fi

        DISK_IDS+=("$disk")
        DISK_NAMES+=("$name")
        DISK_SIZES+=("$hr_size")
        DISK_TYPES+=("$media_type")
        DISK_VOLS+=("$vols")
    done
}

print_disks() {
    if [[ ${#DISK_IDS[@]} -eq 0 ]]; then
        log_warn "No external disks found. Connect a USB drive and try again."
        exit 1
    fi

    echo -e "${BOLD}Available Disks (Select Source):${NC}"
    echo ""
    for i in "${!DISK_IDS[@]}"; do
        local vol_display=""
        [[ -n "${DISK_VOLS[$i]}" ]] && vol_display=" ${DIM}[${DISK_VOLS[$i]}]${NC}"
        echo -e "  ${BOLD}$((i+1)))${NC}  ${DISK_NAMES[$i]}${vol_display}"
        echo -e "      ${DIM}/dev/${DISK_IDS[$i]} — ${DISK_SIZES[$i]} — ${DISK_TYPES[$i]}${NC}"
    done
    echo ""
}

pick_disk() {
    local prompt="$1"
    local exclude="$2"
    local choice

    while true; do
        echo -ne "${CYAN}${prompt}${NC} [1-${#DISK_IDS[@]}]: "
        read -r choice
        if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#DISK_IDS[@]} )); then
            local idx=$((choice - 1))
            if [[ "${DISK_IDS[$idx]}" == "$exclude" ]]; then
                log_err "Can't select the same disk as both source and destination."
                continue
            fi
            echo "${DISK_IDS[$idx]}"
            return
        fi
        log_err "Invalid choice. Enter a number 1-${#DISK_IDS[@]}."
    done
}

# ─── Clone Methods ────────────────────────────────────────────────────────────

find_mount_point() {
    local part="$1"
    diskutil info "$part" 2>/dev/null | grep "Mount Point" | sed 's/.*: *//'
}

find_first_partition() {
    local disk="$1"
    for part in "${disk}s1" "${disk}s2" "${disk}s3"; do
        local content
        content=$(diskutil info "$part" 2>/dev/null | grep "Content (Specific)" | sed 's/.*: *//' || true)
        [[ "$content" == *"EFI"* ]] && continue
        if diskutil info "$part" &>/dev/null; then
            echo "$part"
            return
        fi
    done
    echo "${disk}s1"
}

find_largest_file() {
    local path="$1"
    find "$path" -type f -exec stat -f%z {} \; 2>/dev/null | sort -rn | head -1 || echo "0"
}

smart_clone() {
    local src_disk="$1" dst_disk="$2"
    local src_dev="/dev/$src_disk" dst_dev="/dev/$dst_disk"
    local src_part dst_part

    src_part=$(find_first_partition "$src_disk")
    dst_part=$(find_first_partition "$dst_disk")

    # Mount source to check files
    log_step "Mounting source disk..."
    diskutil mountDisk "$src_dev" &>/dev/null || true
    sleep 1

    local src_mount
    src_mount=$(find_mount_point "$src_part")
    if [[ -z "$src_mount" ]]; then
        log_err "Could not mount source. Aborting."
        return 1
    fi

    # Detect filesystem type needed
    local fs_type="FAT32"
    local max_file
    max_file=$(find_largest_file "$src_mount")
    if (( max_file > 4294967295 )); then
        fs_type="ExFAT"
        local hr_max
        hr_max="$(echo "scale=1; $max_file / 1073741824" | bc) GB"
        log_warn "File > 4GB detected ($hr_max). Using ExFAT."
    fi

    # Get volume name from source
    local src_vol_name
    src_vol_name=$(diskutil info "$src_part" 2>/dev/null | grep "Volume Name" | sed 's/.*: *//')
    [[ -z "$src_vol_name" ]] && src_vol_name="CLONED"
    # Sanitize for FAT32 (11 chars, uppercase)
    local vol_name
    vol_name=$(echo "$src_vol_name" | tr '[:lower:]' '[:upper:]' | tr ' ' '-' | tr -cd 'A-Z0-9_-' | cut -c1-11)
    [[ -z "$vol_name" ]] && vol_name="CLONED"

    echo ""
    log_step "Erasing destination as MBR $fs_type (volume: $vol_name)..."
    sudo diskutil unmountDisk "$dst_dev" &>/dev/null || true
    sudo diskutil eraseDisk "$fs_type" "$vol_name" MBRFormat "$dst_dev"

    # Mount both
    log_step "Mounting disks..."
    diskutil mountDisk "$src_dev" &>/dev/null || true
    diskutil mountDisk "$dst_dev" &>/dev/null || true
    sleep 2

    # Find mount points
    src_mount=$(find_mount_point "$src_part")
    local dst_mount
    dst_mount=$(find_mount_point "$(find_first_partition "$dst_disk")")

    if [[ -z "$src_mount" || -z "$dst_mount" ]]; then
        log_err "Could not find mount points."
        log_info "Source: $src_mount"
        log_info "Destination: $dst_mount"
        return 1
    fi

    log_info "Source:      $src_mount"
    log_info "Destination: $dst_mount"
    echo ""

    log_step "Copying files..."
    rsync -av --delete --progress \
        --exclude '.Spotlight-V100' \
        --exclude '.fseventsd' \
        --exclude '.Trashes' \
        --exclude '.DS_Store' \
        "$src_mount/" "$dst_mount/"
    local rsync_exit=$?

    if [[ $rsync_exit -ne 0 && $rsync_exit -ne 23 ]]; then
        log_err "File copy failed (rsync exit $rsync_exit)."
        return 1
    fi
    [[ $rsync_exit -eq 23 ]] && log_warn "Some non-critical files skipped (normal)."

    log_step "Syncing..."
    /bin/sync

    echo ""
    log_info "MBR/VBR boot sector copy skipped (macOS restriction)."
    log_info "USB will boot via EFI — supported by all modern PCs."
}

block_copy() {
    local src_disk="$1" dst_disk="$2"
    local src_rdev="/dev/r$src_disk" dst_rdev="/dev/r$dst_disk"

    log_step "Unmounting disks..."
    sudo diskutil unmountDisk "/dev/$dst_disk" &>/dev/null || true
    sudo diskutil unmountDisk "/dev/$src_disk" &>/dev/null || true

    echo ""
    log_step "Starting block copy: $src_rdev → $dst_rdev"
    log_info "This copies every byte. It may take a long time."
    echo ""

    if ! sudo dd if="$src_rdev" of="$dst_rdev" bs=1m status=progress 2>&1; then
        echo ""
        log_err "Block copy failed."
        log_warn "Try Smart Clone instead — it copies files without raw disk access."
        log_info "Or grant Full Disk Access: System Settings > Privacy & Security"
        return 1
    fi

    /bin/sync
}

asr_clone() {
    local src_disk="$1" dst_disk="$2"
    local src_dev="/dev/$src_disk" dst_dev="/dev/$dst_disk"

    log_step "Unmounting destination..."
    sudo diskutil unmountDisk "$dst_dev" &>/dev/null || true

    echo ""
    log_step "Starting ASR restore: $src_dev → $dst_dev"
    echo ""

    if ! sudo asr restore --source "$src_dev" --target "$dst_dev" --erase --noprompt; then
        log_err "ASR restore failed."
        return 1
    fi
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
    banner

    log_step "Scanning for disks..."
    discover_disks
    echo ""
    print_disks

    # Pick source
    local src_disk
    src_disk=$(pick_disk "Select SOURCE disk" "")
    local src_idx
    for i in "${!DISK_IDS[@]}"; do
        [[ "${DISK_IDS[$i]}" == "$src_disk" ]] && src_idx=$i
    done
    log_ok "Source: ${DISK_NAMES[$src_idx]} [${DISK_VOLS[$src_idx]:-no label}] (/dev/$src_disk)"
    echo ""

    # Pick destination
    local dst_disk
    dst_disk=$(pick_disk "Select DESTINATION disk" "$src_disk")
    local dst_idx
    for i in "${!DISK_IDS[@]}"; do
        [[ "${DISK_IDS[$i]}" == "$dst_disk" ]] && dst_idx=$i
    done
    log_ok "Destination: ${DISK_NAMES[$dst_idx]} [${DISK_VOLS[$dst_idx]:-no label}] (/dev/$dst_disk)"
    echo ""

    # Pick method
    echo -e "${BOLD}Clone Method:${NC}"
    echo -e "  ${BOLD}1)${NC}  Smart Clone ${GREEN}(recommended)${NC}"
    echo -e "      ${DIM}Copies files. Works with smaller destination. Auto FAT32/ExFAT.${NC}"
    echo -e "  ${BOLD}2)${NC}  Block Copy (dd)"
    echo -e "      ${DIM}Byte-for-byte. Same size required. May need Full Disk Access.${NC}"
    echo -e "  ${BOLD}3)${NC}  Apple Software Restore (asr)"
    echo -e "      ${DIM}macOS-native. Best for APFS/HFS+ volumes.${NC}"
    echo ""

    local method
    while true; do
        echo -ne "${CYAN}Select method${NC} [1-3, default=1]: "
        read -r method
        [[ -z "$method" ]] && method="1"
        [[ "$method" =~ ^[1-3]$ ]] && break
        log_err "Enter 1, 2, or 3."
    done
    echo ""

    # Confirm
    echo -e "${RED}${BOLD}⚠  WARNING: This will ERASE ALL DATA on the destination disk!${NC}"
    echo -e "${RED}${BOLD}   /dev/$dst_disk — ${DISK_NAMES[$dst_idx]} (${DISK_SIZES[$dst_idx]})${NC}"
    echo ""
    echo -ne "${YELLOW}Type 'yes' to confirm: ${NC}"
    local confirm
    read -r confirm
    if [[ "$confirm" != "yes" ]]; then
        echo ""
        log_warn "Aborted."
        exit 0
    fi
    echo ""

    # Run
    local start_time
    start_time=$(date +%s)

    case "$method" in
        1) smart_clone "$src_disk" "$dst_disk" ;;
        2) block_copy "$src_disk" "$dst_disk" ;;
        3) asr_clone "$src_disk" "$dst_disk" ;;
    esac

    local exit_code=$?
    local elapsed=$(( $(date +%s) - start_time ))

    echo ""
    if [[ $exit_code -eq 0 ]]; then
        log_ok "${GREEN}${BOLD}Clone completed successfully!${NC} (${elapsed}s)"
    else
        log_err "${RED}Clone failed.${NC} (${elapsed}s)"
        exit 1
    fi
}

main "$@"
