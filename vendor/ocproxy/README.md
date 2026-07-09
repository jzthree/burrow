# Patched ocproxy (upstream-packet backpressure)

Stock ocproxy (cernekee/ocproxy @ master) silently DROPS upstream packets when
the `--script-tun` socketpair to openconnect is full. On macOS that socketpair
holds ~2 datagrams (net.local.dgram.recvspace = 4KB), so any upload burst
overflows it; lwIP's TCP then stalls in retransmission timeouts and uploads
collapse to ~one send-window per second (~60 KB/s measured) while downloads
run at MB/s.

`backpressure.patch` (against upstream master, 2026-07) changes the VPN-fd
write path to queue packets on EAGAIN/ENOBUFS and flush when the fd turns
writable (lossless backpressure, bounded queue), and hardens the read path
(EAGAIN is not a dead VPN; never fall through with len<0 into pbuf_alloc —
a stock bug).

Measured on the UChicago AnyConnect VPN: uploads 61 KB/s → 1.9-3.8 MB/s
(31-60x); downloads unchanged.

## Rebuild
    git clone https://github.com/cernekee/ocproxy && cd ocproxy
    git apply ../backpressure.patch
    autoreconf -fi && ./configure \
      CPPFLAGS="-I$(brew --prefix libevent)/include" \
      LDFLAGS="-L$(brew --prefix libevent)/lib" && make
    cp ocproxy ../ocproxy-macos-arm64

`ocproxy-macos-arm64` is the prebuilt binary; scripts/install-app.sh bundles
it into Burrow.app/Contents/Helpers/ocproxy, which takes precedence over any
Homebrew install (see GatewaySupport.ocproxyPath). Worth upstreaming.
