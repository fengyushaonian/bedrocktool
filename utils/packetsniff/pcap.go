package packetsniff

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/klauspost/compress/s2"
)

// pcap2 is the container written by the existing `capture` subcommand: a 16
// byte header, a zip of resource packs, then one s2 compressed record per
// packet. Reading it back lets the sniffer work on captures that were already
// taken, without a live server.
const (
	pcapHeaderSize = 16
	pcapRecordHead = 4 + 4 + 1 + 8
	pcapStartMagic = 0xAAAAAAAA
	pcapEndMagic   = 0xBBBBBBBB
	maxRecord      = 16 << 20
)

// PcapReader iterates the raw records of a pcap2 file. It deliberately does not
// decode packets: the payload is handed back untouched so the same probe code
// that runs against a live proxy can run against a file.
type PcapReader struct {
	f       *os.File
	Version uint32
}

// OpenPcap opens a pcap2 file and positions the reader after the pack archive.
func OpenPcap(path string) (*PcapReader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	head := make([]byte, pcapHeaderSize)
	if _, err := io.ReadFull(f, head); err != nil {
		f.Close()
		return nil, err
	}
	if string(head[:4]) != "BTCP" {
		f.Close()
		return nil, errors.New("not a pcap2 file: bad magic")
	}
	version := binary.LittleEndian.Uint32(head[4:8])
	if version < 5 {
		f.Close()
		return nil, fmt.Errorf("pcap2 version %d not supported, needs >= 5", version)
	}
	zipSize := int64(binary.LittleEndian.Uint64(head[8:16]))
	if _, err := f.Seek(pcapHeaderSize+zipSize, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return &PcapReader{f: f, Version: version}, nil
}

func (r *PcapReader) Close() error { return r.f.Close() }

// Next returns the next packet payload, its direction and its timestamp.
func (r *PcapReader) Next() (payload []byte, toServer bool, at time.Time, err error) {
	head := make([]byte, pcapRecordHead)
	if _, err = io.ReadFull(r.f, head); err != nil {
		return nil, false, time.Time{}, err
	}
	if binary.LittleEndian.Uint32(head) != pcapStartMagic {
		return nil, false, time.Time{}, errors.New("bad record magic")
	}
	size := binary.LittleEndian.Uint32(head[4:])
	toServer = head[8] == 1
	at = time.UnixMilli(int64(binary.LittleEndian.Uint64(head[9:])))
	if size > maxRecord {
		return nil, false, time.Time{}, fmt.Errorf("record too large: %d", size)
	}

	buf := make([]byte, int(size)+4)
	if _, err = io.ReadFull(r.f, buf); err != nil {
		return nil, false, time.Time{}, err
	}
	if binary.LittleEndian.Uint32(buf[size:]) != pcapEndMagic {
		return nil, false, time.Time{}, errors.New("bad record trailer")
	}
	payload, err = s2.Decode(nil, buf[:size])
	if err != nil {
		return nil, false, time.Time{}, err
	}
	return payload, toServer, at, nil
}

// SplitHeader separates the packet id from the body. A pcap2 record stores the
// header varuint followed by the body, while the live proxy hook hands both in
// separately.
func SplitHeader(data []byte) (id uint32, body []byte, err error) {
	var v uint32
	for i := 0; i < 5; i++ {
		if i >= len(data) {
			return 0, nil, errors.New("truncated header")
		}
		b := data[i]
		v |= uint32(b&0x7f) << (7 * i)
		if b&0x80 == 0 {
			// The low 10 bits are the packet id, the rest carries sub client
			// ids which are irrelevant here.
			return v & 0x3ff, data[i+1:], nil
		}
	}
	return 0, nil, errors.New("header varuint too long")
}

// AnalyzePcap probes every interesting server to client record of a capture and
// returns the aggregate verdict.
// progress, when set, is called once per probed packet with the running totals
// and the observation that was just added. It lets a live view follow an
// offline replay without buffering the whole capture first.
func AnalyzePcap(path string, w *Writer, max int, progress func(*Summary, Observation)) (*Summary, int, error) {
	r, err := OpenPcap(path)
	if err != nil {
		return nil, 0, err
	}
	defer r.Close()

	sum := NewSummary()
	count := 0
	for {
		payload, toServer, at, err := r.Next()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			break
		}
		if err != nil {
			return sum, count, err
		}
		if toServer {
			continue
		}
		id, body, err := SplitHeader(payload)
		if err != nil || !Interesting(id) {
			continue
		}
		if max > 0 && count >= max {
			break
		}
		o := Probe(id, body, toServer, at)
		if err := w.Write(o); err != nil {
			return sum, count, err
		}
		sum.Add(o)
		count++
		if progress != nil {
			progress(sum, o)
		}
	}
	return sum, count, nil
}
