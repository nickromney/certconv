package tui

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

type lineSegment struct {
	width  int
	render func(maxWidth int) string
}

func fixedLineSegment(rendered string) lineSegment {
	width := lipgloss.Width(rendered)
	return lineSegment{
		width: width,
		render: func(maxWidth int) string {
			if maxWidth < width {
				return ""
			}
			return rendered
		},
	}
}

func styledTextSegment(text string, style lipgloss.Style) lineSegment {
	width := lipgloss.Width(text)
	return lineSegment{
		width: width,
		render: func(maxWidth int) string {
			if maxWidth <= 0 {
				return ""
			}
			return style.Render(truncateEndWidth(text, maxWidth))
		},
	}
}

func labeledValueSegment(label string, value string, labelStyle lipgloss.Style, valueStyle lipgloss.Style) lineSegment {
	labelWidth := lipgloss.Width(label)
	valueWidth := lipgloss.Width(value)
	fullWidth := labelWidth + valueWidth

	return lineSegment{
		width: fullWidth,
		render: func(maxWidth int) string {
			if maxWidth <= 0 {
				return ""
			}
			if maxWidth <= labelWidth {
				return labelStyle.Render(trimWidth(label, maxWidth))
			}
			valueMax := maxWidth - labelWidth
			return labelStyle.Render(label) + valueStyle.Render(truncateEndWidth(value, valueMax))
		},
	}
}

func fitPrefixSegments(segments []lineSegment, width int, sep string) (string, int) {
	if width <= 0 || len(segments) == 0 {
		return "", 0
	}

	sepWidth := lipgloss.Width(sep)
	var out []string
	used := 0

	for _, seg := range segments {
		avail := width - used
		if len(out) > 0 {
			avail -= sepWidth
		}
		if avail <= 0 {
			break
		}

		rendered := seg.render(avail)
		if rendered == "" {
			break
		}
		renderedWidth := lipgloss.Width(rendered)
		if len(out) > 0 {
			used += sepWidth
		}
		out = append(out, rendered)
		used += renderedWidth
		if renderedWidth < seg.width {
			break
		}
	}

	return strings.Join(out, sep), used
}

func fitSuffixSegments(segments []lineSegment, width int, sep string) (string, int) {
	if width <= 0 || len(segments) == 0 {
		return "", 0
	}

	sepWidth := lipgloss.Width(sep)
	var out []string
	used := 0

	for i := len(segments) - 1; i >= 0; i-- {
		seg := segments[i]
		avail := width - used
		if len(out) > 0 {
			avail -= sepWidth
		}
		if avail <= 0 {
			break
		}

		rendered := seg.render(avail)
		if rendered == "" {
			continue
		}
		renderedWidth := lipgloss.Width(rendered)
		if len(out) > 0 {
			used += sepWidth
		}
		out = append([]string{rendered}, out...)
		used += renderedWidth
		if renderedWidth < seg.width {
			break
		}
	}

	return strings.Join(out, sep), used
}

func truncateEndWidth(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= width {
		return s
	}
	if width <= 3 {
		return trimWidth(s, width)
	}

	ellipsis := "..."
	limit := width - lipgloss.Width(ellipsis)
	if limit <= 0 {
		return trimWidth(ellipsis, width)
	}

	var b strings.Builder
	for _, r := range s {
		next := b.String() + string(r)
		if lipgloss.Width(next) > limit {
			break
		}
		b.WriteRune(r)
	}
	return b.String() + ellipsis
}

func trimWidth(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(s) <= width {
		return s
	}

	var b strings.Builder
	for _, r := range s {
		next := b.String() + string(r)
		if lipgloss.Width(next) > width {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}
