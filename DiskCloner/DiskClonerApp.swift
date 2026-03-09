import SwiftUI

@main
struct DiskClonerApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .frame(minWidth: 700, minHeight: 520)
        }
        .windowResizability(.contentSize)
        .commands {
            CommandGroup(replacing: .appInfo) {
                Button("About Disk Cloner") {
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
            }
        }
    }
}
