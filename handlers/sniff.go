package handlers

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/bedrock-tool/bedrocktool/utils/packetsniff"
	"github.com/bedrock-tool/bedrocktool/utils/proxy"
	"github.com/sandertv/gophertunnel/minecraft/protocol/packet"
	"github.com/sirupsen/logrus"
)

// sniffer writes one json line per interesting server to client packet and
// keeps a running verdict of the ambiguous parts of the wire format.
type sniffer struct {
	log     *logrus.Entry
	outPath string
	max     int
	verbose bool

	mu      sync.Mutex
	file    *os.File
	writer  *packetsniff.Writer
	summary *packetsniff.Summary
	count   int
	failed  int
}

// NewSniffer builds the proxy handler. max bounds the number of packets that
// are written, so a long play session cannot fill the disk.
func NewSniffer(outPath string, max int, verbose bool) *proxy.Handler {
	s := &sniffer{
		log:     logrus.WithField("part", "Sniffer"),
		outPath: outPath,
		max:     max,
		verbose: verbose,
		summary: packetsniff.NewSummary(),
	}

	return &proxy.Handler{
		Name: "Packet Sniffer",
		PacketRaw: func(sess *proxy.Session, header packet.Header, payload []byte, src, dst net.Addr, received time.Time) {
			// Only the server to client direction is interesting: that is what
			// a translated client receives.
			if sess.IsClient(src) {
				return
			}
			if !packetsniff.Interesting(header.PacketID) {
				return
			}
			s.observe(header.PacketID, payload, received)
		},
		OnSessionEnd: func(sess *proxy.Session, wg *sync.WaitGroup) {
			s.finish()
		},
	}
}

func (s *sniffer) observe(id uint32, payload []byte, received time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.max > 0 && s.count >= s.max {
		return
	}

	if s.file == nil {
		if err := s.open(); err != nil {
			if s.failed == 0 {
				s.log.Errorf("cannot open %s: %s", s.outPath, err)
			}
			s.failed++
			return
		}
	}

	o := packetsniff.Probe(id, payload, false, received)
	if err := s.writer.Write(o); err != nil {
		s.log.Errorf("write failed: %s", err)
		return
	}
	s.summary.Add(o)
	s.count++
}

func (s *sniffer) open() error {
	if dir := filepath.Dir(s.outPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o775); err != nil {
			return err
		}
	}
	f, err := os.Create(s.outPath)
	if err != nil {
		return err
	}
	s.file = f
	s.writer = &packetsniff.Writer{
		Out:     f,
		Log:     s.log.Infof,
		Verbose: s.verbose,
	}
	return nil
}

func (s *sniffer) finish() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.file == nil {
		if s.count == 0 {
			s.log.Warn("no packets captured")
		}
		return
	}

	lines := s.summary.Lines()
	s.log.Infof("captured %d packets, %d matched, %d ambiguous, %d unmatched",
		s.summary.Total, s.summary.Matched, s.summary.Ambiguous, s.summary.Unmatched)
	for _, l := range lines {
		s.log.Info(l)
	}
	s.log.Infof("verdict: %s", s.summary.Conclusion())

	summaryPath := s.outPath + ".summary.txt"
	body := s.summary.Text()
	if err := os.WriteFile(summaryPath, []byte(body), 0o644); err != nil {
		s.log.Errorf("cannot write summary: %s", err)
	}

	if err := s.file.Close(); err != nil {
		s.log.Errorf("close failed: %s", err)
	}
	s.log.Infof("wrote %s and %s", s.outPath, summaryPath)
}
