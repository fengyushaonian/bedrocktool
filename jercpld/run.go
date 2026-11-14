package jercpld

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Out 是输出目标。Run 会覆盖它,单独调用打印函数时默认写 stdout。
var Out io.Writer = os.Stdout

// Options 控制一次分析。
type Options struct {
	Paths     []string // 文件或目录;目录会递归查找 .pcap2 与 session-*.log
	Mode      string   // "verdict"(默认) | "analyze" | "hex"
	PacketIDs string   // "12,13,15,19,31,32"
	Dir       string   // "c2s" | "s2c" | "both"
	JSON      bool
	Limit     int // 每个包最多展示几条样本
	HexIndex  int // hex 模式:只打印第 N 条,-1 表示不限
	HexMax    int // hex 模式:每包最多打印多少字节
}

// Run 执行一次分析并把结果写到 out。
func Run(opts Options, out io.Writer) error {
	if out != nil {
		Out = out
	}
	if len(opts.Paths) == 0 {
		return fmt.Errorf("jercpld: 需要至少一个抓包文件或目录")
	}

	files, err := collectFiles(opts.Paths)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("jercpld: 没有找到 .pcap2 或 session-*.log")
	}

	recs, warns := loadAll(files)
	for _, w := range warns {
		fmt.Fprintf(Out, "警告: %v\n", w)
	}

	switch opts.Mode {
	case "hex":
		return runHexMode(recs, opts)
	case "analyze":
		return runAnalyzeMode(files, recs, opts)
	default:
		return runVerdictMode(files, recs, opts)
	}
}

// ---------------------------------------------------------------------------
// verdict
// ---------------------------------------------------------------------------

func runVerdictMode(files []string, recs []Record, opts Options) error {
	verdicts := runVerdicts(recs)

	if opts.JSON {
		data, err := json.MarshalIndent(verdicts, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(Out, string(data))
		return nil
	}

	fmt.Fprintf(Out, "== 输入 ==\n")
	for _, f := range files {
		fmt.Fprintf(Out, "  %s\n", f)
	}
	fmt.Fprintf(Out, "  共 %d 帧\n\n", len(recs))

	for i, v := range verdicts {
		fmt.Fprintf(Out, "== 判定 %d/%d:%s ==\n", i+1, len(verdicts), v.Key)
		fmt.Fprintf(Out, "问题:%s\n", v.Question)
		fmt.Fprintf(Out, "结论:%s  [置信度 %s,样本 %d]\n", v.Answer, v.Confidence, v.Samples)
		if len(v.Evidence) > 0 {
			fmt.Fprintf(Out, "证据:\n")
			for _, e := range v.Evidence {
				fmt.Fprintf(Out, "  - %s\n", e)
			}
		}
		fmt.Fprintln(Out)
	}
	return nil
}

// ---------------------------------------------------------------------------
// analyze
// ---------------------------------------------------------------------------

func runAnalyzeMode(files []string, recs []Record, opts Options) error {
	want, err := parseIDList(opts.PacketIDs)
	if err != nil {
		return err
	}
	dir := opts.Dir
	if dir == "" {
		dir = "both"
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 8
	}

	filtered := filterRecords(recs, want, dir)

	fmt.Fprintf(Out, "== 输入 ==\n")
	for _, f := range files {
		fmt.Fprintf(Out, "  %s\n", f)
	}
	fmt.Fprintf(Out, "  共 %d 帧(过滤后 %d 帧)\n\n", len(recs), len(filtered))

	if len(filtered) == 0 {
		fmt.Fprintln(Out, "没有匹配的包。检查 -ids / -dir,或确认抓包时确实产生了这些包。")
		return nil
	}

	fmt.Fprintf(Out, "== 包分布 ==\n")
	printDistribution(filtered)
	fmt.Fprintf(Out, "\n== 样本 ==\n")
	printSamples(filtered, limit)
	return nil
}

type idCount struct {
	ID    uint32 `json:"id"`
	Name  string `json:"name"`
	C2S   int    `json:"c2s"`
	S2C   int    `json:"s2c"`
	Total int    `json:"total"`
}

func printDistribution(recs []Record) {
	byID := map[uint32]*idCount{}
	for _, r := range recs {
		ic, ok := byID[r.ID]
		if !ok {
			ic = &idCount{ID: r.ID, Name: pktName(r.ID)}
			byID[r.ID] = ic
		}
		if r.ToServer {
			ic.C2S++
		} else {
			ic.S2C++
		}
		ic.Total++
	}

	ids := make([]int, 0, len(byID))
	for id := range byID {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)

	fmt.Fprintf(Out, "  %-4s %-22s %6s %6s\n", "id", "名称", "c2s", "s2c")
	for _, id := range ids {
		ic := byID[uint32(id)]
		name := ic.Name
		if name == "" {
			name = "(unknown)"
		}
		fmt.Fprintf(Out, "  %-4d %-22s %6d %6d\n", ic.ID, name, ic.C2S, ic.S2C)
	}
}

func printSamples(recs []Record, limit int) {
	shown := map[uint32]int{}
	for _, r := range recs {
		if shown[r.ID] >= limit {
			continue
		}
		shown[r.ID]++

		fmt.Fprintf(Out, "\n  [%s] #%d %s id=%d len=%d\n", r.Dir(), r.Index, pktName(r.ID), r.ID, len(r.Payload))

		switch r.ID {
		case PktMobEquipment, PktMobArmorEquipment:
			printEquipSample(r)
		case PktMovePlayer:
			printMoveSample(r)
		case PktAddItemEntity:
			printAddItemSample(r)
		default:
			fmt.Fprintf(Out, "    (无专用解析器)\n")
		}
	}
}

func printEquipSample(r Record) {
	for _, spec := range []ItemSpec{spec1001, spec2168} {
		c := NewCursor(r.Payload)
		il, ac, err := parseEquipByID(r.ID, c, spec)
		tail := c.Remaining()
		status := "OK"
		if err != nil {
			status = "ERR " + err.Error()
		}
		fmt.Fprintf(Out, "    %-5s item=%dB air=%d tail=%d %s\n", spec.Label+":", il, ac, tail, status)
	}
}

func printMoveSample(r Record) {
	for _, tc := range []struct {
		label    string
		optional bool
	}{
		{"switch", false},
		{"option", true},
	} {
		c := NewCursor(r.Payload)
		mode, _, err := parseMovePlayer(c, tc.optional)
		tail := c.Remaining()
		status := "OK"
		if err != nil {
			status = "ERR " + err.Error()
		}
		fmt.Fprintf(Out, "    %-7s mode=%d tail=%d %s\n", tc.label+":", mode, tail, status)
	}
}

func printAddItemSample(r Record) {
	for _, pair := range []struct {
		is ItemSpec
		ms MetaSpec
	}{
		{spec1001, meta1001},
		{spec2168, meta2168},
	} {
		c := NewCursor(r.Payload)
		il, air, err := parseAddItemEntity(c, pair.is, pair.ms)
		tail := c.Remaining()
		status := "OK"
		if err != nil {
			status = "ERR " + err.Error()
		}
		fmt.Fprintf(Out, "    %-5s item=%dB air=%v tail=%d %s\n", pair.is.Label+":", il, air, tail, status)
	}
}

// ---------------------------------------------------------------------------
// hex
// ---------------------------------------------------------------------------

func runHexMode(recs []Record, opts Options) error {
	idFilter := uint32(0)
	if opts.PacketIDs != "" {
		want, err := parseIDList(opts.PacketIDs)
		if err != nil {
			return err
		}
		if len(want) == 1 {
			for id := range want {
				idFilter = id
			}
		}
	}
	max := opts.HexMax
	if max <= 0 {
		max = 256
	}

	printed := 0
	for _, r := range recs {
		if idFilter != 0 && r.ID != idFilter {
			continue
		}
		if opts.HexIndex >= 0 && r.Index != opts.HexIndex {
			continue
		}
		fmt.Fprintf(Out, "[%s] #%d %s id=%d len=%d ts=%d\n", r.Dir(), r.Index, pktName(r.ID), r.ID, len(r.Payload), r.Timestamp)
		fmt.Fprint(Out, hexDump(r.Payload, max))
		fmt.Fprintln(Out)
		printed++
	}
	if printed == 0 {
		fmt.Fprintln(Out, "没有匹配的包。")
	}
	return nil
}

func hexDump(b []byte, max int) string {
	origLen := len(b)
	truncated := false
	if len(b) > max {
		b = b[:max]
		truncated = true
	}
	var sb strings.Builder
	for i := 0; i < len(b); i += 16 {
		end := i + 16
		if end > len(b) {
			end = len(b)
		}
		fmt.Fprintf(&sb, "  %04x  ", i)
		for j := i; j < end; j++ {
			fmt.Fprintf(&sb, "%02x ", b[j])
		}
		for j := end; j < i+16; j++ {
			sb.WriteString("   ")
		}
		sb.WriteString(" |")
		for j := i; j < end; j++ {
			ch := b[j]
			if ch < 0x20 || ch > 0x7e {
				ch = '.'
			}
			sb.WriteByte(ch)
		}
		sb.WriteString("|\n")
	}
	if truncated {
		fmt.Fprintf(&sb, "  ... 已截断(原长 %d 字节)\n", origLen)
	}
	return sb.String()
}

// ---------------------------------------------------------------------------
// 通用工具
// ---------------------------------------------------------------------------

func collectFiles(args []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}

	add := func(p string) {
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		if !seen[abs] {
			seen[abs] = true
			out = append(out, p)
		}
	}

	for _, a := range args {
		info, err := os.Stat(a)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			add(a)
			continue
		}
		err = filepath.WalkDir(a, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			lower := strings.ToLower(d.Name())
			if strings.HasSuffix(lower, ".pcap2") {
				add(p)
				return nil
			}
			if strings.HasSuffix(lower, ".log") && strings.Contains(lower, "session-") {
				add(p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	sort.Strings(out)
	return out, nil
}

// loadAll 按后缀分派:.pcap2 走二进制格式,其余走 JERCPLD 文本日志。
func loadAll(files []string) ([]Record, []error) {
	var recs []Record
	var warns []error

	for _, f := range files {
		var r []Record
		var err error
		if strings.HasSuffix(strings.ToLower(f), ".pcap2") {
			r, err = ReadPcap2(f)
		} else {
			r, err = ReadJERCPLDLog(f)
		}
		if err != nil {
			warns = append(warns, fmt.Errorf("%s: %w", f, err))
		}
		recs = append(recs, r...)
	}
	return recs, warns
}

func filterRecords(recs []Record, want map[uint32]bool, dir string) []Record {
	var out []Record
	for _, r := range recs {
		if len(want) > 0 && !want[r.ID] {
			continue
		}
		switch dir {
		case "c2s":
			if !r.ToServer {
				continue
			}
		case "s2c":
			if r.ToServer {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

func parseIDList(s string) (map[uint32]bool, error) {
	out := map[uint32]bool{}
	s = strings.TrimSpace(s)
	if s == "" {
		return out, nil
	}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("无效包 ID %q: %w", part, err)
		}
		out[uint32(n)] = true
	}
	return out, nil
}
