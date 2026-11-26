import AppKit
import DeployerCore
import SwiftUI

/// Entry point. `SSHKeyDeployer --snapshot <outdir>` renders review screenshots and exits;
/// any other launch starts the normal app.
@main
enum Launcher {
    @MainActor
    static func main() {
        let arguments = CommandLine.arguments
        if let index = arguments.firstIndex(of: "--snapshot") {
            let directory = index + 1 < arguments.count ? arguments[index + 1] : "snapshots"
            SnapshotRenderer.run(outputDirectory: directory)
        } else {
            SSHKeyDeployerApp.main()
        }
    }
}

struct SSHKeyDeployerApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @AppStorage("theme") private var theme = AppTheme.system

    static let minimumSize = CGSize(width: 920, height: 640)

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appDelegate.model)
                .frame(minWidth: Self.minimumSize.width, minHeight: Self.minimumSize.height)
                .preferredColorScheme(theme == .system ? nil : theme == .dark ? .dark : .light)
        }
        .defaultSize(width: 1080, height: 780)
        .windowResizability(.contentMinSize)
        .commands {
            // A single-window utility: hide File > New Window.
            CommandGroup(replacing: .newItem) {}
        }
    }
}

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let model: DeployerViewModel

    override init() {
        model = DeployerViewModel()
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        // When launched from a plain executable (e.g. `swift run`) become a regular app.
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        // Never quit in the middle of a server change: cancel, roll back, then exit.
        model.shouldTerminateNow() ? .terminateNow : .terminateLater
    }
}
