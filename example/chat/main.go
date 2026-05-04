package main

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/rakunlabs/alan"
	"github.com/rakunlabs/chu"
	"github.com/rakunlabs/chu/loader/loaderenv"
	"github.com/rakunlabs/into"
)

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

type Config struct {
	alan.Config `cfg:",squash"`
	Name        string `cfg:"name" json:"name"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire Protocol - Messages sent over the network
// ─────────────────────────────────────────────────────────────────────────────

type ChatMessage struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

// ─────────────────────────────────────────────────────────────────────────────
// Bubble Tea Messages (internal events)
// ─────────────────────────────────────────────────────────────────────────────

type msgReceived struct {
	chatMsg ChatMessage
	from    *net.UDPAddr
	time    time.Time
}

type msgPeerJoined struct {
	addr *net.UDPAddr
}

type msgPeerLeft struct {
	addr *net.UDPAddr
}

type msgReady struct{}

type msgError struct {
	err error
}

// ─────────────────────────────────────────────────────────────────────────────
// Display Message - For rendering in the UI
// ─────────────────────────────────────────────────────────────────────────────

type displayMessage struct {
	time     time.Time
	name     string
	text     string
	fromAddr string
	isSystem bool
	isOwn    bool
}

// ─────────────────────────────────────────────────────────────────────────────
// Theme - OpenCode/TokyoNight inspired colors
// ─────────────────────────────────────────────────────────────────────────────

var (
	// Base colors - simple white/grey palette
	colorBorder    = lipgloss.Color("#444444")
	colorText      = lipgloss.Color("#ffffff") // White
	colorTextMuted = lipgloss.Color("#888888") // Grey

	// Peer colors for distinguishing different peers
	peerColors = []lipgloss.Color{
		lipgloss.Color("#888888"), // grey
		lipgloss.Color("#aaaaaa"), // light grey
		lipgloss.Color("#666666"), // dark grey
		lipgloss.Color("#999999"), // medium grey
		lipgloss.Color("#bbbbbb"), // lighter grey
		lipgloss.Color("#777777"), // another grey
	}
)

// ─────────────────────────────────────────────────────────────────────────────
// Styles - OpenCode inspired
// ─────────────────────────────────────────────────────────────────────────────

var (
	// Header bar
	headerStyle = lipgloss.NewStyle().
			Foreground(colorText).
			Padding(0, 1)

	headerTitleStyle = lipgloss.NewStyle().
				Foreground(colorText).
				Bold(true)

	headerStatusStyle = lipgloss.NewStyle().
				Foreground(colorTextMuted)

	// Messages panel (no border, just padding)
	messagesPanelStyle = lipgloss.NewStyle().
				Padding(0, 1)

	// Peer list panel (left border only to separate from chat)
	peerPanelStyle = lipgloss.NewStyle().
			Border(lipgloss.Border{Left: "│"}).
			BorderForeground(colorBorder).
			Padding(0, 1).
			MarginLeft(1)

	peerTitleStyle = lipgloss.NewStyle().
			Foreground(colorText).
			Bold(true)

	peerCountStyle = lipgloss.NewStyle().
			Foreground(colorTextMuted)

	peerItemStyle = lipgloss.NewStyle().
			Foreground(colorText)

	// Input area (top border only)
	inputPanelStyle = lipgloss.NewStyle().
			Border(lipgloss.Border{Top: "─"}).
			BorderForeground(colorBorder).
			Padding(0, 1)

	// Footer/help bar (right aligned)
	footerStyle = lipgloss.NewStyle().
			Foreground(colorTextMuted).
			Padding(0, 1).
			Align(lipgloss.Right)

	// White for key, grey for description
	footerKeyStyle = lipgloss.NewStyle().
			Foreground(colorText)

	footerDescStyle = lipgloss.NewStyle().
			Foreground(colorTextMuted)

	// Message styles
	timestampStyle = lipgloss.NewStyle().
			Foreground(colorTextMuted)

	systemMsgStyle = lipgloss.NewStyle().
			Foreground(colorTextMuted).
			Italic(true)

	ownNameStyle = lipgloss.NewStyle().
			Foreground(colorText).
			Bold(true)

	messageTextStyle = lipgloss.NewStyle().
				Foreground(colorText)
)

// ─────────────────────────────────────────────────────────────────────────────
// Model - Bubble Tea state
// ─────────────────────────────────────────────────────────────────────────────

type model struct {
	// Alan instance
	alan   *alan.Alan
	ctx    context.Context
	cancel context.CancelFunc

	// User info
	myName string

	// UI state
	messages []displayMessage
	peers    []*net.UDPAddr
	textarea textarea.Model
	viewport viewport.Model

	// Dimensions
	width  int
	height int

	// State flags
	ready    bool
	quitting bool
	err      error
}

const (
	peerListWidth = 24
	inputHeight   = 3
	headerHeight  = 1
	footerHeight  = 1
	minWidth      = 60
	minHeight     = 15
)

func newModel(a *alan.Alan, myName string, ctx context.Context, cancel context.CancelFunc) model {
	// Create textarea for input
	ta := textarea.New()
	ta.Placeholder = "Type a message..."
	ta.Focus()
	ta.CharLimit = 500
	ta.SetWidth(40)
	ta.SetHeight(1)
	ta.ShowLineNumbers = false
	ta.FocusedStyle.CursorLine = lipgloss.NewStyle()
	ta.FocusedStyle.Base = lipgloss.NewStyle().Foreground(colorText)
	ta.FocusedStyle.Placeholder = lipgloss.NewStyle().Foreground(colorTextMuted)
	ta.BlurredStyle.Base = lipgloss.NewStyle().Foreground(colorText)
	ta.BlurredStyle.Placeholder = lipgloss.NewStyle().Foreground(colorTextMuted)
	ta.KeyMap.InsertNewline.SetEnabled(false)

	// Create viewport for messages
	vp := viewport.New(40, 10)
	vp.SetContent("")

	return model{
		alan:     a,
		ctx:      ctx,
		cancel:   cancel,
		myName:   myName,
		textarea: ta,
		viewport: vp,
		messages: []displayMessage{},
		peers:    []*net.UDPAddr{},
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Bubble Tea Interface
// ─────────────────────────────────────────────────────────────────────────────

func (m model) Init() tea.Cmd {
	return tea.Batch(
		textarea.Blink,
		m.waitForReady(),
	)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEsc:
			m.quitting = true
			m.cancel()
			return m, tea.Quit

		case tea.KeyEnter:
			text := strings.TrimSpace(m.textarea.Value())
			if text != "" && m.ready {
				// Send message to all peers
				chatMsg := ChatMessage{Name: m.myName, Text: text}
				data, _ := json.Marshal(chatMsg)
				m.alan.Send("", data)

				// Add to local display
				m.messages = append(m.messages, displayMessage{
					time:  time.Now(),
					name:  m.myName,
					text:  text,
					isOwn: true,
				})
				m.updateViewport()

				// Clear input
				m.textarea.Reset()
			}
			return m, nil
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.updateDimensions()
		return m, nil

	case msgReady:
		m.ready = true
		m.peers = m.alan.Peers()
		m.messages = append(m.messages, displayMessage{
			time:     time.Now(),
			text:     fmt.Sprintf("Connected as %s", m.myName),
			isSystem: true,
		})
		m.updateViewport()
		return m, nil

	case msgReceived:
		m.messages = append(m.messages, displayMessage{
			time:     msg.time,
			name:     msg.chatMsg.Name,
			text:     msg.chatMsg.Text,
			fromAddr: msg.from.String(),
			isOwn:    false,
		})
		m.updateViewport()
		return m, nil

	case msgPeerJoined:
		m.peers = m.alan.Peers()
		m.messages = append(m.messages, displayMessage{
			time:     time.Now(),
			text:     fmt.Sprintf("%s joined", msg.addr.IP),
			isSystem: true,
		})
		m.updateViewport()
		return m, nil

	case msgPeerLeft:
		m.peers = m.alan.Peers()
		m.messages = append(m.messages, displayMessage{
			time:     time.Now(),
			text:     fmt.Sprintf("%s left", msg.addr.IP),
			isSystem: true,
		})
		m.updateViewport()
		return m, nil

	case msgError:
		m.err = msg.err
		return m, tea.Quit
	}

	// Handle textarea updates
	m.textarea, cmd = m.textarea.Update(msg)
	cmds = append(cmds, cmd)

	// Handle viewport updates (scrolling)
	m.viewport, cmd = m.viewport.Update(msg)
	cmds = append(cmds, cmd)

	return m, tea.Batch(cmds...)
}

func (m model) View() string {
	if m.err != nil {
		return lipgloss.NewStyle().
			Foreground(colorText).
			Padding(1, 2).
			Render(fmt.Sprintf("Error: %v\n\nPress any key to exit.", m.err))
	}

	if m.width < minWidth || m.height < minHeight {
		return lipgloss.NewStyle().
			Foreground(colorTextMuted).
			Padding(1, 2).
			Render(fmt.Sprintf("Terminal too small. Need at least %dx%d", minWidth, minHeight))
	}

	// Build the layout
	header := m.renderHeader()
	content := m.renderContent()
	input := m.renderInput()
	footer := m.renderFooter()

	return lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		content,
		input,
		footer,
	)
}

// ─────────────────────────────────────────────────────────────────────────────
// Render Components
// ─────────────────────────────────────────────────────────────────────────────

func (m *model) renderHeader() string {
	title := headerTitleStyle.Render("Alan Chat")

	var status string
	if m.ready {
		status = headerStatusStyle.Render(fmt.Sprintf(" - %s - %d peers", m.myName, len(m.peers)))
	} else {
		status = headerStatusStyle.Render(" - connecting...")
	}

	left := title + status
	padding := max(m.width-lipgloss.Width(left)-2, 0)

	return headerStyle.Width(m.width).Render(left + strings.Repeat(" ", padding))
}

func (m *model) renderContent() string {
	contentHeight := max(m.height-headerHeight-inputHeight-footerHeight-2, 5)
	messagesWidth := max(m.width-peerListWidth-4, 20)

	// Messages panel (no border)
	messagesPanel := messagesPanelStyle.
		Width(messagesWidth).
		Height(contentHeight).
		Render(m.viewport.View())

	// Peer list panel (left border separator)
	peerPanel := m.renderPeerList(contentHeight)

	return lipgloss.JoinHorizontal(lipgloss.Top, messagesPanel, peerPanel)
}

func (m *model) renderPeerList(height int) string {
	title := peerTitleStyle.Render("Peers")
	count := peerCountStyle.Render(fmt.Sprintf(" (%d)", len(m.peers)))
	header := title + count

	var lines []string
	lines = append(lines, header)
	lines = append(lines, "") // Empty line after header

	if len(m.peers) == 0 {
		lines = append(lines, lipgloss.NewStyle().Foreground(colorTextMuted).Italic(true).Render("waiting..."))
	} else {
		for _, p := range m.peers {
			color := getPeerColor(p.String())
			bullet := lipgloss.NewStyle().Foreground(color).Render("●")
			addr := p.IP.String()
			if len(addr) > peerListWidth-8 {
				addr = addr[:peerListWidth-11] + "..."
			}
			lines = append(lines, fmt.Sprintf("%s %s", bullet, peerItemStyle.Render(addr)))
		}
	}

	content := strings.Join(lines, "\n")
	return peerPanelStyle.
		Width(peerListWidth).
		Height(height).
		Render(content)
}

func (m *model) renderInput() string {
	return inputPanelStyle.
		Width(m.width - 2).
		Render(m.textarea.View())
}

func (m *model) renderFooter() string {
	keys := []struct {
		key  string
		desc string
	}{
		{"enter", "send"},
		{"↑↓", "scroll"},
		{"esc", "quit"},
	}

	var parts []string
	for _, k := range keys {
		part := footerKeyStyle.Render(k.key) + " " + footerDescStyle.Render(k.desc)
		parts = append(parts, part)
	}

	help := strings.Join(parts, "  ")
	return footerStyle.Width(m.width).Render(help)
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper Methods
// ─────────────────────────────────────────────────────────────────────────────

func (m *model) updateDimensions() {
	contentHeight := max(m.height-headerHeight-inputHeight-footerHeight-2, 5)
	messagesWidth := max(m.width-peerListWidth-4, 20)

	m.viewport.Width = messagesWidth
	m.viewport.Height = contentHeight
	m.textarea.SetWidth(m.width - 8)

	m.updateViewport()
}

func (m *model) updateViewport() {
	var lines []string
	for _, msg := range m.messages {
		lines = append(lines, m.formatMessage(msg))
	}
	content := strings.Join(lines, "\n")
	m.viewport.SetContent(content)
	m.viewport.GotoBottom()
}

func (m *model) formatMessage(msg displayMessage) string {
	timestamp := timestampStyle.Render(msg.time.Format("15:04"))

	if msg.isSystem {
		return fmt.Sprintf("%s  %s", timestamp, systemMsgStyle.Render("● "+msg.text))
	}

	var nameStyle lipgloss.Style
	if msg.isOwn {
		nameStyle = ownNameStyle
	} else {
		nameStyle = lipgloss.NewStyle().Bold(true).Foreground(getPeerColor(msg.fromAddr))
	}

	name := nameStyle.Render(msg.name)
	text := messageTextStyle.Render(msg.text)

	return fmt.Sprintf("%s  %s: %s", timestamp, name, text)
}

func (m model) waitForReady() tea.Cmd {
	return func() tea.Msg {
		<-m.alan.Ready()
		return msgReady{}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Color Helpers
// ─────────────────────────────────────────────────────────────────────────────

func getPeerColor(addr string) lipgloss.Color {
	if addr == "" {
		return peerColors[0]
	}
	h := fnv.New32a()
	h.Write([]byte(addr))
	return peerColors[h.Sum32()%uint32(len(peerColors))]
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

func main() {
	into.Init(
		run,
		into.WithMsgf("alan TUI chat"),
	)
}

func run(ctx context.Context) error {
	// Default config
	cfg := Config{
		Config: alan.Config{
			DNSAddr: "alan-chat.local",
			Port:    5000,
			Security: alan.SecurityConfig{
				Key:     []byte("alan-chat-default-key"),
				Enabled: true,
			},
		},
		Name: "",
	}

	// Load config from environment
	if err := chu.Load(ctx, "alan", &cfg, chu.WithLoaderOption(
		loaderenv.New(
			loaderenv.WithPrefix("ALAN_"),
		)),
	); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	slog.Info("config loaded", "cfg", chu.MarshalMap(cfg))

	// Default name to hostname if not set
	if cfg.Name == "" {
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "user"
		}

		cfg.Name = hostname
	}

	// Create Alan instance
	a, err := alan.New(cfg.Config)
	if err != nil {
		return fmt.Errorf("failed to create Alan: %w", err)
	}

	// Create cancellable context for graceful shutdown
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Create Bubble Tea program
	m := newModel(a, cfg.Name, ctx, cancel)
	p := tea.NewProgram(m, tea.WithAltScreen())

	// Set up Alan callbacks to send events to Bubble Tea
	a.OnPeerJoin(func(addr *net.UDPAddr) {
		p.Send(msgPeerJoined{addr: addr})
	})

	a.OnPeerLeave(func(addr *net.UDPAddr) {
		p.Send(msgPeerLeft{addr: addr})
	})

	// Start Alan in background
	var errAlan error
	a.Handle("", func(ctx context.Context, msg alan.Message) {
		var chatMsg ChatMessage
		if err := json.Unmarshal(msg.Data, &chatMsg); err != nil {
			return // Ignore malformed messages
		}

		p.Send(msgReceived{
			chatMsg: chatMsg,
			from:    msg.Addr,
			time:    time.Now(),
		})
	})
	go func() {
		errAlan = a.Start(ctx)
		if errAlan != nil && ctx.Err() == nil {
			p.Send(msgError{err: errAlan})
		}
	}()

	// Run Bubble Tea (blocking)
	if _, err := p.Run(); err != nil {
		return fmt.Errorf("bubble tea error: %w", err)
	}

	// Graceful shutdown
	a.Stop()

	return errAlan
}
