package subcommands

import (
	"context"
	"fmt"
	"os"

	"github.com/bedrock-tool/bedrocktool/handlers"
	"github.com/bedrock-tool/bedrocktool/utils/commands"
	"github.com/bedrock-tool/bedrocktool/utils/connectinfo"
	"github.com/bedrock-tool/bedrocktool/utils/packetsniff"
	"github.com/bedrock-tool/bedrocktool/utils/proxy"
	"github.com/sirupsen/logrus"
)

// SniffSettings configures the packet sniffer.
//
// The proxy settings are declared field by field instead of embedding
// proxy.ProxySettings: that struct carries a ConnectInfo, and the argument
// parser unconditionally prompts for an address when it is empty. Offline
// analysis has no server to connect to, so it must not prompt at all.
type SniffSettings struct {
	Address string `opt:"Address" flag:"address" desc:"server address to proxy, required for live sniffing"`
	Listen  string `opt:"Listen Address" flag:"listen" default:"0.0.0.0:19132" desc:"local address the client connects to"`

	Out     string `opt:"Output" flag:"out" default:"sniff.jsonl" desc:"json lines file to write observations to"`
	Max     int    `opt:"Max Packets" flag:"max" default:"2000" desc:"stop after this many probed packets, 0 for no limit"`
	Verbose bool   `opt:"Verbose" flag:"verbose" desc:"print every hypothesis that was tried"`
	Pcap    string `opt:"Pcap File" flag:"pcap" desc:"analyze an existing pcap2 capture instead of running a proxy" type:"file"`
}

// SniffCMD probes the ambiguous parts of the server to client wire format.
type SniffCMD struct{}

func (SniffCMD) Name() string {
	return "sniff"
}

func (SniffCMD) Description() string {
	return "probe item, metadata and teleport layouts in server to client packets"
}

func (SniffCMD) Settings() any {
	return new(SniffSettings)
}

func (SniffCMD) Run(ctx context.Context, settings any) error {
	s := settings.(*SniffSettings)

	writer := &packetsniff.Writer{
		Verbose: s.Verbose,
		Log:     logrus.Infof,
	}

	// Offline mode: replay a capture that was taken earlier.
	if s.Pcap != "" {
		if s.Out != "" {
			f, err := os.Create(s.Out)
			if err != nil {
				return err
			}
			defer f.Close()
			writer.Out = f
		}
		sum, n, err := packetsniff.AnalyzePcap(s.Pcap, writer, s.Max)
		if err != nil {
			return err
		}
		logrus.Infof("probed %d packets from %s", n, s.Pcap)
		fmt.Println()
		fmt.Print(sum.Text())

		verdictPath := s.Pcap + ".verdict.txt"
		if err := os.WriteFile(verdictPath, []byte(sum.Text()), 0o644); err != nil {
			return err
		}
		logrus.Infof("verdict written to %s", verdictPath)
		return nil
	}

	// Live mode: run the proxy and let a client connect to it.
	if s.Address == "" {
		return fmt.Errorf("no address given, use -address host:port or -pcap file")
	}

	p, err := proxy.New(ctx, proxy.ProxySettings{
		ConnectInfo:   &connectinfo.ConnectInfo{Value: s.Address},
		ListenAddress: s.Listen,
		Capture:       false,
		ClientCache:   true,
	})
	if err != nil {
		return err
	}
	p.AddHandler(func() *proxy.Handler {
		return handlers.NewSniffer(s.Out, s.Max, s.Verbose)
	})

	logrus.Infof("connect your client to %s, proxying to %s", s.Listen, s.Address)
	return p.Run(ctx, true)
}

func init() {
	commands.RegisterCommand(&SniffCMD{})
}
