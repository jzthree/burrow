import Foundation

/// Watches the config file and fires a debounced callback on changes, including
/// atomic-rename saves where the inode is replaced and must be re-opened.
@MainActor
final class ConfigFileWatcher {
    private let url: URL
    private let onChange: @MainActor () -> Void
    private var source: DispatchSourceFileSystemObject?
    private var debounceTask: Task<Void, Never>?
    private var rearmTask: Task<Void, Never>?

    init(url: URL, onChange: @escaping @MainActor () -> Void) {
        self.url = url
        self.onChange = onChange
    }

    func start() {
        arm()
    }

    func stop() {
        debounceTask?.cancel()
        rearmTask?.cancel()
        source?.cancel()
        source = nil
    }

    private func arm() {
        source?.cancel()
        source = nil

        let descriptor = open(url.path, O_EVTONLY)
        guard descriptor >= 0 else {
            scheduleRearm(notify: false)
            return
        }

        let source = DispatchSource.makeFileSystemObjectSource(
            fileDescriptor: descriptor,
            eventMask: [.write, .extend, .delete, .rename],
            queue: .main
        )
        source.setCancelHandler {
            close(descriptor)
        }
        source.setEventHandler { [weak self] in
            guard let self else { return }
            let event = source.data
            if event.contains(.delete) || event.contains(.rename) {
                self.scheduleRearm(notify: true)
            } else {
                self.scheduleNotify()
            }
        }
        source.resume()
        self.source = source
    }

    private func scheduleRearm(notify: Bool) {
        rearmTask?.cancel()
        rearmTask = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .milliseconds(250))
            guard let self, !Task.isCancelled else { return }
            self.arm()
            if notify {
                self.scheduleNotify()
            } else if self.source == nil {
                self.scheduleRearm(notify: false)
            }
        }
    }

    private func scheduleNotify() {
        debounceTask?.cancel()
        debounceTask = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .milliseconds(200))
            guard let self, !Task.isCancelled else { return }
            self.onChange()
        }
    }
}
