import AppKit
import DeployerCore
import SwiftUI

@main
struct SSHKeyDeployerApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
    @AppStorage("theme") private var theme = AppTheme.system

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appDelegate.model)
                .frame(minWidth: 760, minHeight: 640)
                .preferredColorScheme(theme == .system ? nil : theme == .dark ? .dark : .light)
        }
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
