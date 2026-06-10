import Darwin
import Foundation

public enum PortProbe {
    /// Blocking TCP connect probe; localhost targets answer immediately
    /// (accept or refuse), so this stays fast for readiness checks.
    public static func canConnect(host: String, port: Int) -> Bool {
        var hints = addrinfo(
            ai_flags: AI_ADDRCONFIG,
            ai_family: AF_UNSPEC,
            ai_socktype: SOCK_STREAM,
            ai_protocol: IPPROTO_TCP,
            ai_addrlen: 0,
            ai_canonname: nil,
            ai_addr: nil,
            ai_next: nil
        )

        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(host, String(port), &hints, &result)
        guard status == 0, let firstResult = result else {
            return false
        }
        defer { freeaddrinfo(firstResult) }

        var pointer: UnsafeMutablePointer<addrinfo>? = firstResult
        while let current = pointer {
            let socketFD = socket(current.pointee.ai_family, current.pointee.ai_socktype, current.pointee.ai_protocol)
            if socketFD >= 0 {
                let connectResult = connect(socketFD, current.pointee.ai_addr, current.pointee.ai_addrlen)
                close(socketFD)
                if connectResult == 0 {
                    return true
                }
            }
            pointer = current.pointee.ai_next
        }

        return false
    }
}
