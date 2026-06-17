import Darwin
import Foundation

/// Probes a SOCKS5 proxy by performing a real CONNECT with remote (proxy-side)
/// DNS resolution. ocproxy opens its listener the instant openconnect execs
/// it — before the VPN tunnel and its DNS are usable — so "the port is open"
/// is not the same as "the gateway works." This asks the proxy to resolve and
/// reach a host, which only succeeds once the VPN is genuinely ready.
public enum SOCKSProbe {
    public static func canReach(
        proxyHost: String = "127.0.0.1",
        proxyPort: Int,
        targetHost: String,
        targetPort: Int,
        timeout: TimeInterval = 6
    ) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
        guard fd >= 0 else {
            return false
        }
        defer { close(fd) }

        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(UInt16(clamping: proxyPort)).bigEndian
        addr.sin_addr.s_addr = inet_addr(proxyHost)
        let connected = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard connected == 0 else {
            return false
        }

        // Greeting: SOCKS5, one method, no auth.
        guard writeAll(fd, [0x05, 0x01, 0x00]) else { return false }
        guard let greeting = readExactly(fd, 2), greeting[0] == 0x05, greeting[1] == 0x00 else {
            return false
        }

        // CONNECT request with ATYP=domain so the proxy resolves the name.
        let hostBytes = Array(targetHost.utf8)
        guard hostBytes.count <= 255 else { return false }
        var request: [UInt8] = [0x05, 0x01, 0x00, 0x03, UInt8(hostBytes.count)]
        request.append(contentsOf: hostBytes)
        let port = UInt16(clamping: targetPort)
        request.append(UInt8(port >> 8))
        request.append(UInt8(port & 0xff))
        guard writeAll(fd, request) else { return false }

        // Reply: VER, REP, RSV, ATYP. REP==0 means the connection succeeded.
        guard let reply = readExactly(fd, 4), reply[0] == 0x05 else {
            return false
        }
        return reply[1] == 0x00
    }

    private static func writeAll(_ fd: Int32, _ bytes: [UInt8]) -> Bool {
        var sent = 0
        return bytes.withUnsafeBytes { raw -> Bool in
            while sent < bytes.count {
                let n = write(fd, raw.baseAddress!.advanced(by: sent), bytes.count - sent)
                if n <= 0 { return false }
                sent += n
            }
            return true
        }
    }

    private static func readExactly(_ fd: Int32, _ count: Int) -> [UInt8]? {
        var buffer = [UInt8](repeating: 0, count: count)
        var got = 0
        let ok = buffer.withUnsafeMutableBytes { raw -> Bool in
            while got < count {
                let n = read(fd, raw.baseAddress!.advanced(by: got), count - got)
                if n <= 0 { return false }
                got += n
            }
            return true
        }
        return ok ? buffer : nil
    }
}

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

    /// Timeout-bounded TCP connect via a non-blocking socket. Unlike the
    /// unbounded variant, this returns quickly for unroutable hosts — essential
    /// when probing an internal host (e.g. a cluster login node) that is only
    /// reachable when some VPN is up, where a blocking connect would stall for
    /// the OS default (~75s).
    public static func canConnect(host: String, port: Int, timeout: TimeInterval) -> Bool {
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
        guard getaddrinfo(host, String(port), &hints, &result) == 0, let first = result else {
            return false
        }
        defer { freeaddrinfo(first) }

        var pointer: UnsafeMutablePointer<addrinfo>? = first
        while let current = pointer {
            defer { pointer = current.pointee.ai_next }
            let fd = socket(current.pointee.ai_family, current.pointee.ai_socktype, current.pointee.ai_protocol)
            guard fd >= 0 else { continue }
            _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK)

            let rc = connect(fd, current.pointee.ai_addr, current.pointee.ai_addrlen)
            if rc == 0 {
                close(fd)
                return true
            }
            if errno != EINPROGRESS {
                close(fd)
                continue
            }
            var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let polled = poll(&pfd, 1, Int32(max(0, timeout) * 1000))
            if polled > 0 {
                var soError: Int32 = 0
                var length = socklen_t(MemoryLayout<Int32>.size)
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &length)
                close(fd)
                if soError == 0 {
                    return true
                }
            } else {
                close(fd)
            }
        }
        return false
    }
}
