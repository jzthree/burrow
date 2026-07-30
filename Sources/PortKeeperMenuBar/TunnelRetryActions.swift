import PortKeeperCore

extension MenuBarViewModel {
    func cancelTunnelAttempt(named name: String) {
        if TunnelSupervisor.cancelCurrentAttempt(named: name) {
            globalMessage = "Cancelled this attempt for \(name); automatic retries remain on."
        } else {
            globalMessage = "\(name) is waiting for its next retry; no SSH attempt is active."
        }
    }

    func stopRetrying(named name: String) {
        stopTunnel(named: name)
        globalMessage = "Stopped retries for \(name). Click Connect to start again."
    }
}
