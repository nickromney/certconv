package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// renderGrid renders a lazygit-style 3-pane grid with shared borders:
// [1] left full-height, [2] top-right, [3] bottom-right.
//
// Dimensions:
// - total width/height are for the pane area only (status bar excluded)
// - fileW and infoH include the shared separator column/row
// - rightW = totalW - fileW + 1
// - contentH = totalH - infoH + 1
func renderGrid(
	totalW, totalH int,
	fileW, rightW, infoH, contentH int,
	leftBody, topBody, bottomBody []string,
	focused PaneID,
	topTitle string,
	bottomTitle string,
) string {
	if totalW <= 0 || totalH <= 0 {
		return ""
	}

	leftActive := focused == PaneFiles
	topActive := focused == PaneInfo
	bottomActive := focused == PaneContent

	// Border style: active pane borders are bold and use the same color as pane
	// text for accessibility (color alone is not sufficient for color-blind
	// users; bold provides a weight cue, and matching text color ensures the
	// focused pane reads as a unified block).
	borderStyle := func(active bool) lipgloss.Style {
		if active {
			return paneBorderActiveStyle
		}
		return paneBorderInactiveStyle
	}

	labelStyle := func(active bool) lipgloss.Style {
		if active {
			return paneHeaderActiveStyle
		}
		return paneHeaderInactiveStyle
	}

	// Shared edges belong to the focused pane: a corner/separator is active
	// if any pane whose perimeter includes that edge is focused.
	topLeftCorner := leftActive                       // ┌ top-left corner belongs to pane 1 only
	topSep := leftActive || topActive                 // ┬ shared by pane 1 top-right + pane 2 top-left
	botSep := leftActive || bottomActive              // ┴ shared by pane 1 bottom-right + pane 3 bottom-left
	leftVBar := leftActive                            // │ left edge of pane 1 only
	sepVBarTop := leftActive || topActive             // │ between pane 1 and pane 2
	sepVBarBot := leftActive || bottomActive          // │ between pane 1 and pane 3
	rightVBarTop := topActive                         // │ right edge of pane 2
	rightVBarBot := bottomActive                      // │ right edge of pane 3
	midSep := leftActive || topActive || bottomActive // ├ junction of all three
	midFill := topActive || bottomActive              // ─ horizontal separator between pane 2 and pane 3
	midRight := topActive || bottomActive             // ┤ right end of separator (pane 2 bottom / pane 3 top)
	botLeftCorner := leftActive                       // └ bottom-left corner belongs to pane 1 only

	// Inner widths/heights.
	leftInnerW := max(0, fileW-2)
	rightInnerW := max(0, rightW-2)
	leftInnerH := max(0, totalH-2)
	topInnerH := max(0, infoH-2)
	botInnerH := max(0, contentH-2)

	leftBody = padLines(leftBody, leftInnerH, leftInnerW)
	topBody = padLines(topBody, topInnerH, rightInnerW)
	bottomBody = padLines(bottomBody, botInnerH, rightInnerW)

	leftLabelRaw := fmt.Sprintf("[1]-%s-", "Files")
	topLabelRaw := fmt.Sprintf("[2]-%s-", topTitle)
	botLabelRaw := fmt.Sprintf("[3]-%s-", bottomTitle)

	var out []string

	// Top border line: ┌ ... ┬ ... ┐
	{
		leftLabelFit := fitLabelRaw(leftLabelRaw, leftInnerW)
		topLabelFit := fitLabelRaw(topLabelRaw, rightInnerW)

		leftFill := max(0, leftInnerW-lipgloss.Width(leftLabelFit))
		rightFill := max(0, rightInnerW-lipgloss.Width(topLabelFit))

		line := borderStyle(topLeftCorner).Render("┌") +
			labelStyle(leftActive).Render(leftLabelFit) +
			borderStyle(leftActive).Render(strings.Repeat("─", leftFill)) +
			borderStyle(topSep).Render("┬") +
			labelStyle(topActive).Render(topLabelFit) +
			borderStyle(topActive).Render(strings.Repeat("─", rightFill)) +
			borderStyle(topActive).Render("┐")
		out = append(out, padWidth(line, totalW))
	}

	// Top content rows.
	for i := 0; i < topInnerH; i++ {
		line := borderStyle(leftVBar).Render("│") +
			leftBody[i] +
			borderStyle(sepVBarTop).Render("│") +
			topBody[i] +
			borderStyle(rightVBarTop).Render("│")
		out = append(out, padWidth(line, totalW))
	}

	// Shared horizontal separator row (bottom pane top border) with label: ... ├ ... ┤
	{
		leftRow := strings.Repeat(" ", leftInnerW)
		if topInnerH < len(leftBody) {
			leftRow = leftBody[topInnerH]
		}

		botLabelFit := fitLabelRaw(botLabelRaw, rightInnerW)
		rightFill := max(0, rightInnerW-lipgloss.Width(botLabelFit))

		line := borderStyle(leftVBar).Render("│") +
			leftRow +
			borderStyle(midSep).Render("├") +
			labelStyle(bottomActive).Render(botLabelFit) +
			borderStyle(midFill).Render(strings.Repeat("─", rightFill)) +
			borderStyle(midRight).Render("┤")
		out = append(out, padWidth(line, totalW))
	}

	// Bottom content rows.
	for i := 0; i < botInnerH; i++ {
		leftIdx := topInnerH + 1 + i
		leftRow := strings.Repeat(" ", leftInnerW)
		if leftIdx >= 0 && leftIdx < len(leftBody) {
			leftRow = leftBody[leftIdx]
		}

		line := borderStyle(leftVBar).Render("│") +
			leftRow +
			borderStyle(sepVBarBot).Render("│") +
			bottomBody[i] +
			borderStyle(rightVBarBot).Render("│")
		out = append(out, padWidth(line, totalW))
	}

	// Bottom border line: └ ... ┴ ... ┘
	{
		line := borderStyle(botLeftCorner).Render("└") +
			borderStyle(leftActive).Render(strings.Repeat("─", leftInnerW)) +
			borderStyle(botSep).Render("┴") +
			borderStyle(bottomActive).Render(strings.Repeat("─", rightInnerW)) +
			borderStyle(bottomActive).Render("┘")
		out = append(out, padWidth(line, totalW))
	}

	out = padExact(out, totalH)
	return strings.Join(out, "\n")
}

func fitLabelRaw(label string, innerW int) string {
	if innerW <= 0 {
		return ""
	}
	if lipgloss.Width(label) <= innerW {
		return label
	}
	r := []rune(label)
	for len(r) > 0 && lipgloss.Width(string(r)) > innerW {
		r = r[:len(r)-1]
	}
	return string(r)
}

func padLines(lines []string, height int, width int) []string {
	lines = padExact(lines, height)
	out := make([]string, 0, height)
	for _, l := range lines {
		out = append(out, padWidth(l, width))
	}
	return out
}

func padExact(lines []string, height int) []string {
	if height < 0 {
		height = 0
	}
	if len(lines) > height {
		return lines[:height]
	}
	for len(lines) < height {
		lines = append(lines, "")
	}
	return lines
}

func padWidth(s string, width int) string {
	if width <= 0 {
		return ""
	}
	// lipgloss safely handles ANSI when constraining widths.
	return lipgloss.NewStyle().Width(width).MaxWidth(width).Render(s)
}
