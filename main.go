package main

import (
    "crypto/ed25519"
    "encoding/base32"
    "encoding/hex"
    "fmt"
    "net"
    "os"
    "os/signal"
    "runtime"
    "strings"
    "syscall"

    "github.com/spf13/pflag"
    "github.com/elliotchance/orderedmap/v2"
    "github.com/miekg/dns"
    "github.com/yggdrasil-network/yggdrasil-go/src/address"
)

const zone = "pk.ygg."
const suffix = "." + zone

var (
    defaultListen = []string{
        "udp:[::]:53",
        "tcp:[::]:53",
    }
    defaultNS = []string{
        "ns"+suffix+":200::",
    }
    nsList = orderedmap.NewOrderedMap[string, net.IP]()
)

const (
    defaultRname = "go-issue-at-github-com-danny8376-ygg-resolver.not.really.email.invalid."
)

var (
    listen      = pflag.StringSlice("listen", defaultListen, "listen string in proto:addr:port format")
    rname       = pflag.String("rname", defaultRname, "RNAME in SOA response")
    ns          = pflag.StringSlice("ns", defaultNS, "NS response in either fqdn or fqdn:glue-ip format, first one will be master in SOA response")
    compress    = pflag.Bool("compress", true, "compress replies")
    soreuseport = pflag.Int("soreuseport", 0, "use SO_REUSE_PORT")
    cpu         = pflag.Int("cpu", 0, "number of cpu to use")
)

var (
    b32 = base32.StdEncoding.WithPadding(base32.NoPadding)
)

func splitAtColon(str string) (string, string) {
    split := strings.SplitN(str, ":", 2)
    if len(split) == 1 {
        return split[0], ""
    } else {
        return split[0], split[1]
    }
}

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
    if q.Name == zone {
        switch q.Qtype {
        case dns.TypeSOA:
            mns, _ := splitAtColon((*ns)[0])
            rr = &dns.SOA{
                Hdr:     dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 86400},
                Ns:      mns,
                Mbox:    *rname,
                Serial:  200,
                Refresh: 86400,
                Retry:   7200,
                Expire:  2592000,
                Minttl:  2592000,
            }
            m.Answer = append(m.Answer, rr)
        case dns.TypeNS:
            for n, a := range nsList.Iterator() {
                rr = &dns.NS{
                    Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 86400},
                    Ns:  n,
                }
                m.Answer = append(m.Answer, rr)
                if a != nil {
                    rr = &dns.AAAA{
                        Hdr:  dns.RR_Header{Name: n, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 86400},
                        AAAA: a,
                    }
                    m.Extra = append(m.Extra, rr)
                }
            }
        }
        w.WriteMsg(m)
        return
    }
    if q.Qtype != dns.TypeAAAA {
        w.WriteMsg(m)
        return
    }
    if a, glue := nsList.Get(q.Name); glue {
        rr = &dns.AAAA{
            Hdr:  dns.RR_Header{Name: zone, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 86400},
            AAAA: a,
        }
        m.Answer = append(m.Answer, rr)
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
    var pk [ed25519.PublicKeySize]byte
    nxdomain := false
    subname := strings.TrimSuffix(q.Name, suffix)
    labels := strings.Split(subname, ".")
    pkstr := labels[len(labels)-1]
    switch pkstr {
    // while this is valid partial hex... will anyone ever try to use this?
    case "b32":
        pkstr = labels[len(labels)-2]
        if b, err := b32.DecodeString(pkstr); err != nil {
            nxdomain = true
        } else {
            copy(pk[:], b)
        }
    default: // normal hex
        if len(pkstr) % 2 == 1 { // make hex decode below happy
            pkstr = pkstr + "0"
        }
        if b, err := hex.DecodeString(pkstr); err != nil {
            nxdomain = true
        } else {
            copy(pk[:], b)
        }
    }
    if nxdomain {
        m.Rcode = dns.RcodeNameError
    } else {
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
        go func(l string) {
            net, addr := splitAtColon(l)
            println("Listening on "+net+" "+addr)
            server := &dns.Server{Addr: addr, Net: net, TsigSecret: nil, ReusePort: soreuseport}
            if err := server.ListenAndServe(); err != nil {
                fmt.Printf("Failed to setup "+l+" server: %s\n", err.Error())
            }
        }(l)
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
    // TODO: properly verify ns items
    for _, i := range *ns {
        n, a := splitAtColon(i)
        if a == "" {
            nsList.Set(n, nil)
        } else {
            nsList.Set(n, net.ParseIP(a))
        }
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
