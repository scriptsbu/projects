import SwiftUI

struct ContentView: View {
    @StateObject private var engine = CloneEngine()

    @State private var disks: [DiskInfo] = []
    @State private var sourceDisk: DiskInfo?
    @State private var destDisk: DiskInfo?
    @State private var cloneMethod: CloneMethod = .smart
    @State private var isLoading = true
    @State private var showConfirmation = false

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "externaldrive.fill.badge.plus")
                    .font(.title)
                    .foregroundColor(.accentColor)
                Text("Disk Cloner")
                    .font(.title.bold())
                Spacer()
                Button(action: refreshDisks) {
                    Label("Refresh", systemImage: "arrow.clockwise")
                }
                .disabled(isCloning)
                Button(action: showAbout) {
                    Label("About", systemImage: "info.circle")
                }
                .buttonStyle(.borderless)
            }
            .padding()

            Divider()

            if isLoading {
                Spacer()
                ProgressView("Scanning disks...")
                Spacer()
            } else if disks.isEmpty {
                Spacer()
                VStack(spacing: 12) {
                    Image(systemName: "externaldrive.badge.exclamationmark")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary)
                    Text("No external disks found")
                        .font(.headline)
                    Text("Connect a USB drive or external disk and click Refresh")
                        .foregroundColor(.secondary)
                }
                Spacer()
            } else {
                ScrollView {
                    VStack(spacing: 20) {
                        // Source selection
                        DiskPickerSection(
                            title: "Source Disk",
                            icon: "arrow.up.doc.fill",
                            color: .blue,
                            disks: disks,
                            selection: $sourceDisk,
                            excludedDisk: destDisk,
                            disabled: isCloning
                        )

                        Image(systemName: "arrow.down.circle.fill")
                            .font(.title2)
                            .foregroundColor(.accentColor)

                        // Destination selection
                        DiskPickerSection(
                            title: "Destination Disk",
                            icon: "arrow.down.doc.fill",
                            color: .orange,
                            disks: disks,
                            selection: $destDisk,
                            excludedDisk: sourceDisk,
                            disabled: isCloning
                        )

                        // Clone method
                        GroupBox {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Clone Method")
                                    .font(.headline)
                                Picker("Method", selection: $cloneMethod) {
                                    ForEach(CloneMethod.allCases, id: \.self) { method in
                                        Text(method.rawValue).tag(method)
                                    }
                                }
                                .pickerStyle(.segmented)
                                .disabled(isCloning)
                                Text(cloneMethod.description)
                                    .font(.caption)
                                    .foregroundColor(.secondary)
                            }
                        }

                        // Size info/warning
                        if let src = sourceDisk, let dst = destDisk, dst.sizeBytes < src.sizeBytes {
                            if cloneMethod == .smart {
                                InfoBanner(
                                    icon: "info.circle.fill",
                                    color: .blue,
                                    text: "Destination (\(dst.size)) is smaller than source (\(src.size)). Smart Clone will work as long as the destination is larger than the actual data on the source."
                                )
                            } else {
                                InfoBanner(
                                    icon: "exclamationmark.triangle.fill",
                                    color: .red,
                                    text: "Destination (\(dst.size)) is smaller than source (\(src.size)). \(cloneMethod.rawValue) requires destination >= source size. Use Smart Clone instead."
                                )
                            }
                        }

                        // Clone button
                        if !isCloning {
                            Button(action: { showConfirmation = true }) {
                                Label("Start Clone", systemImage: "doc.on.doc.fill")
                                    .frame(maxWidth: .infinity)
                                    .padding(.vertical, 8)
                            }
                            .buttonStyle(.borderedProminent)
                            .controlSize(.large)
                            .disabled(!canClone)
                        }

                        // Progress panel — always visible when running or finished
                        if engine.status != .idle {
                            ProgressPanel(engine: engine)
                        }
                    }
                    .padding()
                }
            }
        }
        .frame(width: 700)
        .task { await loadDisks() }
        .alert("Confirm Clone", isPresented: $showConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Erase & Clone", role: .destructive) {
                startClone()
            }
        } message: {
            if let src = sourceDisk, let dst = destDisk {
                Text("This will ERASE ALL DATA on \"\(dst.displayName)\" and overwrite it with the contents of \"\(src.displayName)\".\n\nThis cannot be undone.")
            }
        }
    }

    private var isCloning: Bool {
        engine.status == .cloning || engine.status == .unmounting || engine.status == .preparing
    }

    private var canClone: Bool {
        sourceDisk != nil && destDisk != nil &&
        sourceDisk != destDisk && !isCloning
    }

    private func showAbout() {
        NSApplication.shared.orderFrontStandardAboutPanel(options: [
            NSApplication.AboutPanelOptionKey.credits: NSAttributedString(
                string: """
                A simple, free macOS disk cloning utility.

                Built for duplicating bootable USB drives (Acronis, Windows PE, etc.) \
                and cloning SSDs. Smart Clone mode allows cloning to smaller drives \
                when the actual data fits.

                Created by Alberto Lopez-Santiago
                Built with Claude Code (Anthropic)

                License: MIT — Free to use, modify, and distribute.
                https://github.com/scriptsbu/DiskCloner
                """,
                attributes: [
                    .font: NSFont.systemFont(ofSize: 11),
                    .foregroundColor: NSColor.secondaryLabelColor
                ]
            ),
            NSApplication.AboutPanelOptionKey(rawValue: "Copyright"): "2026 Alberto Lopez-Santiago"
        ])
    }

    private func loadDisks() async {
        isLoading = true
        disks = await DiskManager.listDisks()
        isLoading = false
    }

    private func refreshDisks() {
        Task { await loadDisks() }
    }

    private func startClone() {
        guard let src = sourceDisk, let dst = destDisk else { return }
        engine.clone(source: src, destination: dst, method: cloneMethod)
    }
}

// MARK: - Progress Panel

struct ProgressPanel: View {
    @ObservedObject var engine: CloneEngine

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                // Status header
                HStack(spacing: 10) {
                    statusIcon
                    VStack(alignment: .leading, spacing: 2) {
                        Text(statusTitle)
                            .font(.headline)
                        if !engine.currentStep.isEmpty && isRunning {
                            Text(engine.currentStep)
                                .font(.subheadline)
                                .foregroundColor(.secondary)
                        }
                    }
                    Spacer()
                    if isRunning {
                        Button("Cancel", role: .destructive) {
                            engine.cancel()
                        }
                        .buttonStyle(.bordered)
                        .controlSize(.small)
                    }
                }

                // Progress bar
                if isRunning {
                    ProgressView(value: engine.progress)
                        .progressViewStyle(.linear)
                    Text("\(Int(engine.progress * 100))%")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }

                // Log toggle
                if !engine.log.isEmpty {
                    Divider()
                    DisclosureGroup(
                        isExpanded: $engine.showLog,
                        content: {
                            ScrollViewReader { proxy in
                                ScrollView {
                                    VStack(alignment: .leading, spacing: 1) {
                                        ForEach(engine.log.indices, id: \.self) { i in
                                            Text(engine.log[i])
                                                .font(.system(.caption2, design: .monospaced))
                                                .foregroundColor(logLineColor(engine.log[i]))
                                                .textSelection(.enabled)
                                                .id(i)
                                        }
                                    }
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                }
                                .frame(maxHeight: 200)
                                .onChange(of: engine.log.count) {
                                    if let last = engine.log.indices.last {
                                        proxy.scrollTo(last, anchor: .bottom)
                                    }
                                }
                            }
                        },
                        label: {
                            HStack {
                                Image(systemName: "terminal.fill")
                                    .font(.caption)
                                Text("Process Log (\(engine.log.count) lines)")
                                    .font(.caption)
                                Spacer()
                                Button {
                                    NSPasteboard.general.clearContents()
                                    NSPasteboard.general.setString(engine.log.joined(separator: "\n"), forType: .string)
                                } label: {
                                    Label("Copy Log", systemImage: "doc.on.doc")
                                        .font(.caption)
                                }
                                .buttonStyle(.bordered)
                                .controlSize(.mini)
                            }
                        }
                    )
                }
            }
        }
    }

    private var isRunning: Bool {
        switch engine.status {
        case .unmounting, .preparing, .cloning: return true
        default: return false
        }
    }

    private var statusTitle: String {
        switch engine.status {
        case .idle: return "Ready"
        case .unmounting: return "Unmounting disks..."
        case .preparing: return "Preparing destination..."
        case .cloning: return "Cloning in progress..."
        case .completed: return "Clone completed!"
        case .failed(let msg): return "Failed: \(msg)"
        }
    }

    @ViewBuilder
    private var statusIcon: some View {
        switch engine.status {
        case .idle:
            Image(systemName: "circle")
                .foregroundColor(.secondary)
                .font(.title2)
        case .unmounting, .preparing, .cloning:
            ProgressView()
                .controlSize(.small)
        case .completed:
            Image(systemName: "checkmark.circle.fill")
                .foregroundColor(.green)
                .font(.title2)
        case .failed:
            Image(systemName: "xmark.circle.fill")
                .foregroundColor(.red)
                .font(.title2)
        }
    }

    private func logLineColor(_ line: String) -> Color {
        if line.contains(">> ") { return .accentColor }
        if line.contains("ERROR") { return .red }
        if line.contains("completed") || line.contains("DONE") { return .green }
        return .secondary
    }
}

// MARK: - Info Banner

struct InfoBanner: View {
    let icon: String
    let color: Color
    let text: String

    var body: some View {
        HStack(alignment: .top) {
            Image(systemName: icon)
                .foregroundColor(color)
            Text(text)
                .font(.caption)
                .foregroundColor(color == .red ? .red : .secondary)
        }
        .padding(8)
        .background(color.opacity(0.1))
        .cornerRadius(8)
    }
}

// MARK: - Disk Picker

struct DiskPickerSection: View {
    let title: String
    let icon: String
    let color: Color
    let disks: [DiskInfo]
    @Binding var selection: DiskInfo?
    let excludedDisk: DiskInfo?
    var disabled: Bool = false

    var availableDisks: [DiskInfo] {
        disks.filter { $0 != excludedDisk }
    }

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                Label(title, systemImage: icon)
                    .font(.headline)
                    .foregroundColor(color)

                if availableDisks.isEmpty {
                    Text("No disks available")
                        .foregroundColor(.secondary)
                        .italic()
                } else {
                    ForEach(availableDisks) { disk in
                        DiskRow(disk: disk, isSelected: selection == disk)
                            .onTapGesture {
                                if !disabled {
                                    selection = (selection == disk) ? nil : disk
                                }
                            }
                            .opacity(disabled ? 0.6 : 1.0)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

struct DiskRow: View {
    let disk: DiskInfo
    let isSelected: Bool

    var body: some View {
        HStack {
            Image(systemName: diskIcon)
                .font(.title2)
                .foregroundColor(diskColor)
                .frame(width: 30)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 4) {
                    Text(disk.name.isEmpty ? "Untitled" : disk.name)
                        .font(.body.bold())
                    if !disk.volumeNames.isEmpty {
                        Text("[\(disk.volumeNames.joined(separator: ", "))]")
                            .font(.body)
                            .foregroundColor(.secondary)
                    }
                }
                Text("\(disk.deviceNode) — \(disk.size) — \(disk.mediaType)")
                    .font(.caption)
                    .foregroundColor(.secondary)
            }

            Spacer()

            if isSelected {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundColor(.accentColor)
                    .font(.title3)
            }
        }
        .padding(8)
        .background(isSelected ? Color.accentColor.opacity(0.1) : Color.clear)
        .cornerRadius(8)
        .overlay(
            RoundedRectangle(cornerRadius: 8)
                .stroke(isSelected ? Color.accentColor : Color.clear, lineWidth: 1.5)
        )
    }

    private var diskIcon: String {
        switch disk.mediaType {
        case "USB": return "externaldrive.fill"
        case "SSD", "External": return "internaldrive.fill"
        default: return "internaldrive"
        }
    }

    private var diskColor: Color {
        switch disk.mediaType {
        case "USB": return .blue
        case "SSD": return .purple
        case "External": return .orange
        default: return .gray
        }
    }
}

#Preview {
    ContentView()
}
