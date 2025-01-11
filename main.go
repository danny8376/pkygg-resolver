package main

import (
    "crypto/ed25519"
    "encoding/hex"
    "fmt"
    "net"
    "os"
    "os/signal"
    "runtime"
    "strings"
    "syscall"

    "github.com/spf13/pflag"
    "github.com/miekg/dns"
    "github.com/yggdrasil-network/yggdrasil-go/src/address"
)

var defaultListen = []string{
    "udp:[::]:53",
    "tcp:[::]:53",
}

var (
    listen      = pflag.StringSlice("listen", defaultListen, "listen string in proto:addr:port format")
    compress    = pflag.Bool("compress", true, "compress replies")
    soreuseport = pflag.Int("soreuseport", 0, "use SO_REUSE_PORT")
    cpu         = pflag.Int("cpu", 0, "number of cpu to use")
)

const suffix = ".pk.ygg."

func handle(w dns.ResponseWriter, r *dns.Msg) {
    var (
        rr  dns.RR
    )
    m := new(dns.Msg)
    m.SetReply(r)
    m.Compress = *compress
    m.MsgHdr.RecursionAvailable = r.MsgHdr.RecursionDesired
    if len(r.Question) != 1 {
        m.SetRcodeFormatError(m)
        m.Zero = false
        w.WriteMsg(m)
        return
    }
    q := r.Question[0]
    if q.Qtype != dns.TypeAAAA {
        w.WriteMsg(m)
        return
    }
    /* not required as we don't even handel query without suffix
    if !strings.HasSuffix(q.Name, suffix) {
        m.Rcode = dns.RcodeNameError
        w.WriteMsg(m)
        return
    }
    */
    pkstr := strings.TrimSuffix(q.Name, suffix)
    pkstr = pkstr[strings.LastIndex(pkstr, ".")+1:]
    if len(pkstr) % 2 == 1 { // make hex decode below happy
        pkstr = pkstr + "0"
    }
    var pk [ed25519.PublicKeySize]byte
    if b, err := hex.DecodeString(pkstr); err != nil {
        m.Rcode = dns.RcodeNameError
    } else {
        copy(pk[:], b)
        rr = &dns.AAAA{
            Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 86400},
            AAAA: net.IP(address.AddrForKey(pk[:])[:]),
        }
        m.Answer = append(m.Answer, rr)
    }
    w.WriteMsg(m)
}

func serve(soreuseport bool) {
    for _, l := range *listen {
        go func() {
            var split = strings.SplitN(l, ":", 2)
            println("Listening on "+split[0]+" "+split[1])
            server := &dns.Server{Addr: split[1], Net: split[0], TsigSecret: nil, ReusePort: soreuseport}
            if err := server.ListenAndServe(); err != nil {
                fmt.Printf("Failed to setup "+l+" server: %s\n", err.Error())
            }
        }()
    }
}

func main() {
    pflag.Usage = func() {
        pflag.PrintDefaults()
    }
    pflag.Parse()
    if *cpu != 0 {
        runtime.GOMAXPROCS(*cpu)
    }
    dns.HandleFunc("pk.ygg.", handle)
    if *soreuseport > 0 {
        for i := 0; i < *soreuseport; i++ {
            go serve(true)
        }
    } else {
        go serve(false)
    }
    sig := make(chan os.Signal)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
    s := <-sig
    fmt.Printf("Signal (%s) received, stopping\n", s)
}
