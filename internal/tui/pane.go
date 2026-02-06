package tui

// PaneID identifies which pane is focused.
type PaneID int

const (
	PaneFiles PaneID = iota
	PaneInfo
	PaneContent
	paneCount // sentinel for wrapping
)

func (p PaneID) Next() PaneID {
	return (p + 1) % paneCount
}

func (p PaneID) Prev() PaneID {
	return (p - 1 + paneCount) % paneCount
}

func (p PaneID) String() string {
	switch p {
	case PaneFiles:
		return "Files"
	case PaneInfo:
		return "Info"
	case PaneContent:
		return "Content"
	default:
		return "?"
	}
}
