package subcommands

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/bedrock-tool/bedrocktool/handlers"
	"github.com/bedrock-tool/bedrocktool/ui/messages"
	"github.com/bedrock-tool/bedrocktool/utils"
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
	Verbose bool   `opt:"Verbose" flag:"verbose" desc:"also record every hypothesis that was tried"`
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

// resolveOut turns a relative output path into one inside the data directory.
// The gui has no meaningful working directory, so "sniff.jsonl" would otherwise
// land next to the binary.
func resolveOut(path string) string {
	if path == "" || filepath.IsAbs(path) {
		return path
	}
	return utils.PathData(path)
}

// sendObservation bridges one probe result to the ui. The cli installs no event
// handler, so these are dropped there; the log line and the json file are the
// cli's output.
func sendObservation(o packetsniff.Observation, verbose bool) {
	event := &messages.EventSniffObservation{
		Time:      o.Time,
		Dir:       "s2c",
		Name:      o.Name,
		Length:    o.Length,
		Verdict:   packetsniff.Short(o),
		Ambiguous: o.Ambiguous,
		Matched:   o.Winner != nil && !o.Ambiguous,
	}
	if verbose {
		event.Detail = strings.Join(packetsniff.Detail(o), "\n")
	}
	messages.SendEvent(event)
}

func sendSummary(sum *packetsniff.Summary, finished bool) {
	ev := &messages.EventSniffSummary{
		Text:      sum.Conclusion(),
		Total:     sum.Total,
		Matched:   sum.Matched,
		Ambiguous: sum.Ambiguous,
		Unmatched: sum.Unmatched,
		Finished:  finished,
	}
	if finished {
		ev.Text = sum.Text()
	}
	messages.SendEvent(ev)
}

func (SniffCMD) Run(ctx context.Context, settings any) error {
	s := settings.(*SniffSettings)

	outPath := resolveOut(s.Out)
	writer := &packetsniff.Writer{
		Verbose: s.Verbose,
		Log:     logrus.Infof,
	}

	// Offline mode: replay a capture that was taken earlier.
	if s.Pcap != "" {
		if outPath != "" {
			f, err := os.Create(outPath)
			if err != nil {
				return err
			}
			defer f.Close()
			writer.Out = io.Writer(f)
		}
		sum, n, err := packetsniff.AnalyzePcap(s.Pcap, writer, s.Max, func(_ *packetsniff.Summary, o packetsniff.Observation) {
			sendObservation(o, s.Verbose)
		})
		if err != nil {
			return err
		}
		logrus.Infof("probed %d packets from %s", n, s.Pcap)
		fmt.Println()
		fmt.Print(sum.Text())
		sendSummary(sum, true)

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
		return handlers.NewSniffer(outPath, s.Max, s.Verbose)
	})

	// Publish the listen address before the proxy does any network work: the
	// proxy only reports it after authentication, and the gui page needs
	// something to show while the user is still logging in.
	messages.SendEvent(&messages.EventConnectStateUpdate{
		State:      messages.ConnectStateListening,
		ListenAddr: s.Listen,
	})
	logrus.Infof("connect your client to %s, proxying to %s", s.Listen, s.Address)
	return p.Run(ctx, true)
}

func init() {
	commands.RegisterCommand(&SniffCMD{})
}
