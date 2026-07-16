package tui

import (
	"fmt"
	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type Model struct {
	Provider, Zone string
	Status         string
	quitting       bool
}

func New(provider, zone string) Model {
	return Model{Provider: provider, Zone: zone, Status: "Run `labdns discover` to refresh service state."}
}
func (m Model) Init() tea.Cmd { return nil }
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if k, ok := msg.(tea.KeyMsg); ok {
		switch k.String() {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "?":
			m.Status = "D Discover  P Plan  A Apply  V Verify  Q Quit"
		}
	}
	return m, nil
}
func (m Model) View() string {
	if m.quitting {
		return ""
	}
	title := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("86")).Render("LabDNS ─ Internal DNS")
	return fmt.Sprintf("%s\n\nProvider        %s\nZone            %s\nStatus          %s\n\n[D] Discover  [P] Plan  [A] Apply  [V] Verify  [?] Help  [Q] Quit\n", title, m.Provider, m.Zone, m.Status)
}
