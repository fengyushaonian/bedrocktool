package subcommands

import (
	"context"
	"os"

	"github.com/bedrock-tool/bedrocktool/jercpld"
	"github.com/bedrock-tool/bedrocktool/utils/commands"
)

// AnalyzeSettings 是 analyze 子命令的参数。
//
// 它读 bedrocktool 自己抓的 .pcap2,也读 JERCPLD 的 session-*.log,
// 用 1001 / 2168 两套 schema 交叉解析同一段字节,判定
// docs/PROTOCOL_1001.md 第八节列出的三个待确认项。
type AnalyzeSettings struct {
	Path      string `opt:"Capture Path" flag:"path" desc:"pcap2 file, session-*.log, or a directory (default: captures)"`
	Mode      string `opt:"Mode" flag:"mode" default:"verdict" desc:"verdict | analyze | hex"`
	PacketIDs string `opt:"Packet IDs" flag:"ids" default:"12,13,15,19,31,32" desc:"comma separated packet ids"`
	Dir       string `opt:"Direction" flag:"dir" default:"both" desc:"c2s | s2c | both"`
	JSON      bool   `opt:"JSON" flag:"json" desc:"machine readable output"`
	Limit     int    `opt:"Sample Limit" flag:"limit" default:"8" desc:"max samples per packet in analyze mode"`
	HexIndex  int    `opt:"Hex Index" flag:"hex-index" default:"-1" desc:"hex mode: only the Nth record, -1 = all"`
	HexMax    int    `opt:"Hex Max Bytes" flag:"hex-max" default:"256" desc:"hex mode: max bytes per packet"`
}

// AnalyzeCMD 是 analyze 子命令。
type AnalyzeCMD struct{}

func (AnalyzeCMD) Name() string {
	return "analyze"
}

func (AnalyzeCMD) Description() string {
	return "analyze captures and judge 1001 vs 2168 wire differences"
}

func (AnalyzeCMD) Settings() any {
	return new(AnalyzeSettings)
}

func (AnalyzeCMD) Run(_ context.Context, settings any) error {
	s := settings.(*AnalyzeSettings)

	path := s.Path
	if path == "" {
		path = "captures"
	}

	return jercpld.Run(jercpld.Options{
		Paths:     []string{path},
		Mode:      s.Mode,
		PacketIDs: s.PacketIDs,
		Dir:       s.Dir,
		JSON:      s.JSON,
		Limit:     s.Limit,
		HexIndex:  s.HexIndex,
		HexMax:    s.HexMax,
	}, os.Stdout)
}

func init() {
	commands.RegisterCommand(&AnalyzeCMD{})
}
