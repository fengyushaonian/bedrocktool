// Package sniff renders the live output of the packet sniffer: one row per
// probed server to client packet, plus the running verdict.
package sniff

import (
	"fmt"
	"image"
	"image/color"
	"os"
	"strings"
	"sync"
	"time"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"gioui.org/x/component"
	"github.com/bedrock-tool/bedrocktool/ui/gui/guim"
	"github.com/bedrock-tool/bedrocktool/ui/gui/pages"
	"github.com/bedrock-tool/bedrocktool/ui/messages"
	"github.com/bedrock-tool/bedrocktool/utils"
	"github.com/sirupsen/logrus"
)

type (
	C = layout.Context
	D = layout.Dimensions
)

const ID = "sniff"

// maxRows bounds what the page keeps. A long session can produce tens of
// thousands of packets and every row costs memory; the oldest are dropped and
// the counters stay exact because they come from the summary, not the rows.
const maxRows = 4000

var (
	colorOK      = color.NRGBA{R: 0x4c, G: 0xc0, B: 0x6a, A: 0xff}
	colorWarn    = color.NRGBA{R: 0xff, G: 0xb3, B: 0x00, A: 0xff}
	colorBad     = color.NRGBA{R: 0xe5, G: 0x39, B: 0x35, A: 0xff}
	colorMuted   = color.NRGBA{R: 0x8a, G: 0x8a, B: 0x8a, A: 0xff}
	colorHeading = color.NRGBA{R: 0x8e, G: 0x31, B: 0xeb, A: 0xff}
)

type row struct {
	at        time.Time
	name      string
	length    int
	verdict   string
	ambiguous bool
	matched   bool
}

type Page struct {
	g guim.Guim

	mu       sync.Mutex
	rows     []row
	total    int
	matched  int
	ambig    int
	unmatch  int
	text     string
	finished bool
	dropped  int

	list    widget.List
	verdict widget.List
	back    widget.Clickable
	save    widget.Clickable
	follow  widget.Bool

	// savedPath is shown in the verdict panel after an export, so the user can
	// find the file without reading the log window.
	savedPath string

	// listen is the address the client has to connect to, taken from the proxy
	// start event so the empty state can show it instead of "see the popup".
	listen string
}

func New(g guim.Guim) pages.Page {
	p := &Page{
		g:    g,
		list: widget.List{List: layout.List{Axis: layout.Vertical, ScrollToEnd: true}},
		verdict: widget.List{
			List: layout.List{Axis: layout.Vertical},
		},
	}
	p.follow.Value = true
	return p
}

var _ pages.Page = &Page{}

func (p *Page) ID() string { return ID }

func (p *Page) NavItem() component.NavItem {
	return component.NavItem{Name: "Sniffer"}
}

func (p *Page) Actions(th *material.Theme) []component.AppBarAction {
	return []component.AppBarAction{
		{
			Layout: func(gtx C, bg, fg color.NRGBA) D {
				if p.back.Clicked(gtx) {
					p.g.ExitSubcommand()
				}
				btn := material.Button(th, &p.back, "Stop")
				return layout.UniformInset(4).Layout(gtx, btn.Layout)
			},
		},
		{
			Layout: func(gtx C, bg, fg color.NRGBA) D {
				if p.save.Clicked(gtx) {
					p.export()
				}
				btn := material.Button(th, &p.save, "Save report")
				return layout.UniformInset(4).Layout(gtx, btn.Layout)
			},
		},
	}
}

func (p *Page) Overflow() []component.OverflowAction { return nil }

// export writes the verdict next to the json log, which is where a user would
// look for it after a capture, and tells them where it went.
func (p *Page) export() {
	p.mu.Lock()
	body := p.text
	p.mu.Unlock()
	if body == "" {
		logrus.Info("nothing to save yet, wait for the capture to finish")
		return
	}
	name := fmt.Sprintf("sniff-report-%s.txt", time.Now().Format("20060102-150405"))
	path := utils.PathData(name)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		logrus.Errorf("cannot write %s: %s", path, err)
		return
	}
	logrus.Infof("report written to %s", path)

	p.mu.Lock()
	p.savedPath = path
	p.mu.Unlock()
}

func (p *Page) Layout(gtx C, th *material.Theme) D {
	p.mu.Lock()
	total, matched, ambig, unmatch := p.total, p.matched, p.ambig, p.unmatch
	text, finished, saved, listen := p.text, p.finished, p.savedPath, p.listen
	p.mu.Unlock()

	return layout.UniformInset(8).Layout(gtx, func(gtx C) D {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx C) D {
				return p.layoutHeader(gtx, th, total, matched, ambig, unmatch, finished)
			}),
			layout.Flexed(1, func(gtx C) D {
				if total == 0 {
					hint := "Start the capture, then join a world."
					if listen != "" {
						hint = "Connect your client to " + listen + ", then join a world."
					}
					if finished {
						hint = "Nothing matched. The capture had no server to client packets of interest."
					}
					return layout.Center.Layout(gtx, func(gtx C) D {
						return layout.Flex{Axis: layout.Vertical, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(material.H6(th, "Waiting for packets").Layout),
							layout.Rigid(func(gtx C) D {
								return layout.Inset{Top: unit.Dp(8)}.Layout(gtx, func(gtx C) D {
									l := material.Label(th, th.TextSize, hint)
									l.Color = colorMuted
									return l.Layout(gtx)
								})
							}),
						)
					})
				}
				return panel(gtx, component.WithAlpha(th.Fg, 10), func(gtx C) D {
					return layout.UniformInset(6).Layout(gtx, func(gtx C) D {
						return p.layoutRows(gtx, th)
					})
				})
			}),
			layout.Rigid(func(gtx C) D {
				return p.layoutVerdict(gtx, th, text, finished, saved)
			}),
		)
	})
}

func (p *Page) layoutHeader(gtx C, th *material.Theme, total, matched, ambig, unmatch int, finished bool) D {
	status := "capturing"
	if finished {
		status = "finished"
	}

	return layout.Inset{Bottom: unit.Dp(8)}.Layout(gtx, func(gtx C) D {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx C) D {
				return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
					layout.Rigid(func(gtx C) D {
						l := material.H6(th, "Packet sniffer")
						return l.Layout(gtx)
					}),
					layout.Rigid(func(gtx C) D {
						return layout.Inset{Left: unit.Dp(10)}.Layout(gtx, func(gtx C) D {
							return p.chip(gtx, th, status, colorHeading)
						})
					}),
				)
			}),
			layout.Rigid(func(gtx C) D {
				return layout.Inset{Top: unit.Dp(6)}.Layout(gtx, func(gtx C) D {
					return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
						layout.Rigid(func(gtx C) D { return p.stat(gtx, th, "packets", total, th.Palette.Fg) }),
						layout.Rigid(func(gtx C) D { return p.stat(gtx, th, "matched", matched, colorOK) }),
						layout.Rigid(func(gtx C) D { return p.stat(gtx, th, "ambiguous", ambig, colorWarn) }),
						layout.Rigid(func(gtx C) D { return p.stat(gtx, th, "unmatched", unmatch, colorBad) }),
					)
				})
			}),
		)
	})
}

func (p *Page) stat(gtx C, th *material.Theme, label string, value int, c color.NRGBA) D {
	return layout.Inset{Right: unit.Dp(14)}.Layout(gtx, func(gtx C) D {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx C) D {
				v := material.Label(th, th.TextSize*1.4, fmt.Sprint(value))
				v.Color = c
				return v.Layout(gtx)
			}),
			layout.Rigid(func(gtx C) D {
				l := material.Label(th, th.TextSize*0.85, label)
				l.Color = colorMuted
				return l.Layout(gtx)
			}),
		)
	})
}

func (p *Page) chip(gtx C, th *material.Theme, text string, c color.NRGBA) D {
	return component.Surface(&material.Theme{Palette: material.Palette{Bg: component.WithAlpha(c, 40)}}).
		Layout(gtx, func(gtx C) D {
			return layout.Inset{Top: unit.Dp(2), Bottom: unit.Dp(2), Left: unit.Dp(8), Right: unit.Dp(8)}.Layout(gtx, func(gtx C) D {
				l := material.Label(th, th.TextSize*0.85, text)
				l.Color = c
				return l.Layout(gtx)
			})
		})
}

func (p *Page) layoutRows(gtx C, th *material.Theme) D {
	p.mu.Lock()
	rows := make([]row, len(p.rows))
	copy(rows, p.rows)
	p.mu.Unlock()

	// ScrollToEnd also aligns short content to the bottom, which would leave a
	// gap under the header, so only follow once the rows overflow the viewport.
	p.list.List.ScrollToEnd = p.follow.Value && len(rows)*gtx.Dp(23) > gtx.Constraints.Max.Y

	nameW := gtx.Dp(140)
	lenW := gtx.Dp(52)

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx C) D {
			return layout.Inset{Bottom: unit.Dp(4)}.Layout(gtx, func(gtx C) D {
				return layout.Flex{Axis: layout.Horizontal}.Layout(gtx,
					layout.Rigid(func(gtx C) D { return p.headCell(gtx, th, "packet", nameW) }),
					layout.Rigid(func(gtx C) D { return p.headCell(gtx, th, "len", lenW) }),
					layout.Flexed(1, func(gtx C) D { return p.headCell(gtx, th, "verdict", 0) }),
				)
			})
		}),
		layout.Flexed(1, func(gtx C) D {
			return material.List(th, &p.list).Layout(gtx, len(rows), func(gtx C, i int) D {
				return p.layoutRow(gtx, th, rows[i], nameW, lenW)
			})
		}),
	)
}

func (p *Page) headCell(gtx C, th *material.Theme, text string, width int) D {
	if width > 0 {
		gtx.Constraints.Min.X = width
		gtx.Constraints.Max.X = width
	}
	l := material.Label(th, th.TextSize*0.85, text)
	l.Color = colorMuted
	return l.Layout(gtx)
}

func (p *Page) layoutRow(gtx C, th *material.Theme, r row, nameW, lenW int) D {
	c := th.Palette.Fg
	switch {
	case r.ambiguous:
		c = colorWarn
	case !r.matched:
		c = colorBad
	}

	return layout.Inset{Top: unit.Dp(1), Bottom: unit.Dp(1)}.Layout(gtx, func(gtx C) D {
		return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
			layout.Rigid(func(gtx C) D {
				gtx.Constraints.Min.X = nameW
				gtx.Constraints.Max.X = nameW
				l := material.Label(th, th.TextSize, r.name)
				l.Color = c
				l.MaxLines = 1
				l.Truncator = "…"
				return l.Layout(gtx)
			}),
			layout.Rigid(func(gtx C) D {
				gtx.Constraints.Min.X = lenW
				gtx.Constraints.Max.X = lenW
				l := material.Label(th, th.TextSize, fmt.Sprint(r.length))
				l.Color = colorMuted
				l.MaxLines = 1
				return l.Layout(gtx)
			}),
			layout.Flexed(1, func(gtx C) D {
				l := material.Label(th, th.TextSize, r.verdict)
				l.Color = c
				l.MaxLines = 1
				l.Truncator = "…"
				return l.Layout(gtx)
			}),
		)
	})
}

func (p *Page) layoutVerdict(gtx C, th *material.Theme, text string, finished bool, saved string) D {
	p.mu.Lock()
	follow := p.follow.Value
	p.mu.Unlock()

	lines := []string{}
	if text != "" {
		lines = strings.Split(strings.TrimSpace(text), "\n")
	}

	return layout.Inset{Top: unit.Dp(8)}.Layout(gtx, func(gtx C) D {
		// component.Surface sizes itself from the minimum constraint and the
		// stack inside it resets that, so it collapses to the width of the
		// label. Record the content, then paint a full width panel behind it.
		return panel(gtx, component.WithAlpha(th.Fg, 28), func(gtx C) D {
			return layout.UniformInset(8).Layout(gtx, func(gtx C) D {
				return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
					layout.Rigid(func(gtx C) D {
						return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
							layout.Rigid(func(gtx C) D {
								l := material.Label(th, th.TextSize*0.85, "VERDICT")
								l.Color = colorMuted
								return l.Layout(gtx)
							}),
							layout.Rigid(func(gtx C) D {
								return layout.Inset{Left: unit.Dp(12)}.Layout(gtx, func(gtx C) D {
									return material.CheckBox(th, &p.follow, "follow packets").Layout(gtx)
								})
							}),
						)
					}),
					layout.Rigid(func(gtx C) D {
						if saved == "" {
							return D{}
						}
						return layout.Inset{Top: unit.Dp(4)}.Layout(gtx, func(gtx C) D {
							l := material.Label(th, th.TextSize*0.85, "saved to "+saved)
							l.Color = colorOK
							return l.Layout(gtx)
						})
					}),
					layout.Rigid(func(gtx C) D {
						return layout.Inset{Top: unit.Dp(4)}.Layout(gtx, func(gtx C) D {
							if len(lines) == 0 {
								l := material.Label(th, th.TextSize, "waiting for the first packet")
								l.Color = colorMuted
								return l.Layout(gtx)
							}
							// The finished report is longer than the live one, so the
							// panel grows instead of clipping its last line.
							if finished {
								gtx.Constraints.Max.Y = gtx.Dp(210)
							} else {
								gtx.Constraints.Max.Y = gtx.Dp(90)
							}
							p.verdict.List.ScrollToEnd = !finished && follow
							return material.List(th, &p.verdict).Layout(gtx, len(lines), func(gtx C, i int) D {
								l := material.Label(th, th.TextSize, lines[i])
								if strings.HasPrefix(lines[i], "verdict:") {
									l.Color = colorHeading
								}
								return l.Layout(gtx)
							})
						})
					}),
				)
			})
		})
	})
}

func (p *Page) HaveFinishScreen() bool { return true }

func (p *Page) HandleEvent(event any) error {
	switch event := event.(type) {
	case *messages.EventSniffObservation:
		p.mu.Lock()
		p.rows = append(p.rows, row{
			at:        event.Time,
			name:      event.Name,
			length:    event.Length,
			verdict:   event.Verdict,
			ambiguous: event.Ambiguous,
			matched:   event.Matched,
		})
		if len(p.rows) > maxRows {
			cut := len(p.rows) - maxRows
			p.rows = append(p.rows[:0], p.rows[cut:]...)
			p.dropped += cut
		}
		p.mu.Unlock()

	case *messages.EventConnectStateUpdate:
		if event.ListenAddr != "" {
			p.mu.Lock()
			p.listen = event.ListenAddr
			p.mu.Unlock()
		}

	case *messages.EventSniffSummary:
		p.mu.Lock()
		p.total = event.Total
		p.matched = event.Matched
		p.ambig = event.Ambiguous
		p.unmatch = event.Unmatched
		if event.Text != "" {
			p.text = event.Text
		}
		p.finished = event.Finished
		p.mu.Unlock()
	}
	return nil
}

// panel paints a rounded background behind w and reports the full available
// width, so a short content row still produces a panel spanning the page.
func panel(gtx C, bg color.NRGBA, w layout.Widget) D {
	macro := op.Record(gtx.Ops)
	dims := w(gtx)
	call := macro.Stop()

	width := gtx.Constraints.Max.X
	rect := image.Rect(0, 0, width, dims.Size.Y)
	defer clip.RRect{Rect: rect, NE: 8, NW: 8, SE: 8, SW: 8}.Push(gtx.Ops).Pop()
	paint.Fill(gtx.Ops, bg)

	call.Add(gtx.Ops)
	return D{Size: image.Pt(width, dims.Size.Y)}
}
