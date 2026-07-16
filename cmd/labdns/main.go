package main

import (
	"context"
	"encoding/json"
	"fmt"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/labdns/labdns/internal/app"
	"github.com/labdns/labdns/internal/config"
	"github.com/labdns/labdns/internal/dns"
	"github.com/labdns/labdns/internal/tui"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"os"
	"time"
)

type options struct {
	configPath     string
	json           bool
	nonInteractive bool
	approve        bool
	dryRun         bool
}

func main() {
	o := &options{configPath: "labdns.yaml"}
	root := &cobra.Command{Use: "labdns", Short: "Automatic internal DNS management for homelabs", SilenceUsage: true}
	root.PersistentFlags().StringVar(&o.configPath, "config", o.configPath, "configuration file")
	root.PersistentFlags().BoolVar(&o.json, "json", false, "machine-readable output")
	root.PersistentFlags().BoolVar(&o.nonInteractive, "non-interactive", false, "disable prompts")
	root.PersistentFlags().BoolVar(&o.dryRun, "dry-run", false, "plan but do not mutate")
	root.AddCommand(initCmd(o), withApp(o, "discover", func(ctx context.Context, a *app.App, args []string) (any, error) { return a.Discover(ctx) }), withApp(o, "plan", func(ctx context.Context, a *app.App, args []string) (any, error) { return a.CreatePlan(ctx) }), applyCmd(o), withApp(o, "verify", func(ctx context.Context, a *app.App, args []string) (any, error) {
		p, e := a.CreatePlan(ctx)
		if e != nil {
			return nil, e
		}
		return a.Provider.Verify(ctx, p.Desired)
	}), withApp(o, "database verify", func(ctx context.Context, a *app.App, args []string) (any, error) {
		return map[string]string{"status": "ok"}, a.Store.IntegrityCheck()
	}), tuiCmd(o))
	if e := root.Execute(); e != nil {
		fmt.Fprintln(os.Stderr, "labdns:", e)
		os.Exit(exitCode(e))
	}
}
func load(o *options) (*app.App, error) {
	c, e := config.Load(o.configPath)
	if e != nil {
		return nil, e
	}
	return app.New(c)
}
func withApp(o *options, use string, run func(context.Context, *app.App, []string) (any, error)) *cobra.Command {
	return &cobra.Command{Use: use, RunE: func(cmd *cobra.Command, args []string) error {
		a, e := load(o)
		if e != nil {
			return e
		}
		defer a.Close()
		ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
		defer cancel()
		v, e := run(ctx, a, args)
		if e != nil {
			return e
		}
		return printResult(v, o.json)
	}}
}
func initCmd(o *options) *cobra.Command {
	return &cobra.Command{Use: "init", RunE: func(cmd *cobra.Command, args []string) error {
		c := config.Default()
		b, e := yaml.Marshal(c)
		if e != nil {
			return e
		}
		if _, e = os.Stat(o.configPath); e == nil {
			return fmt.Errorf("refusing to overwrite existing config %s", o.configPath)
		}
		if e = os.WriteFile(o.configPath, b, 0600); e != nil {
			return e
		}
		return printResult(map[string]string{"config": o.configPath}, o.json)
	}}
}
func applyCmd(o *options) *cobra.Command {
	c := withApp(o, "apply", func(ctx context.Context, a *app.App, args []string) (any, error) {
		p, e := a.CreatePlan(ctx)
		if e != nil {
			return nil, e
		}
		if o.dryRun {
			return p, nil
		}
		if o.nonInteractive && !o.approve {
			return nil, fmt.Errorf("non-interactive apply requires --approve")
		}
		return a.Apply(ctx, p)
	})
	c.Flags().BoolVar(&o.approve, "approve", false, "approve non-interactive changes")
	return c
}
func tuiCmd(o *options) *cobra.Command {
	return &cobra.Command{Use: "tui", RunE: func(cmd *cobra.Command, args []string) error {
		c, e := config.Load(o.configPath)
		if e != nil {
			return e
		}
		_, e = tea.NewProgram(tui.New(c.Provider.Type, c.Domain.Zone), tea.WithAltScreen()).Run()
		return e
	}}
}
func printResult(v any, jsonOutput bool) error {
	if jsonOutput {
		b, e := json.MarshalIndent(v, "", "  ")
		if e != nil {
			return e
		}
		fmt.Println(string(b))
		return nil
	}
	b, e := yaml.Marshal(v)
	if e != nil {
		return e
	}
	fmt.Print(string(b))
	return nil
}
func exitCode(e error) int {
	if e == nil {
		return 0
	}
	s := e.Error()
	if s == "" {
		return 1
	}
	if contains(s, "invalid DNS zone") || contains(s, "only version") {
		return 2
	}
	if contains(s, "Docker") {
		return 3
	}
	if contains(s, "authentication") {
		return 10
	}
	if contains(s, "conflict") {
		return 9
	}
	if contains(s, "verification") {
		return 8
	}
	return 1
}
func contains(s, x string) bool {
	for i := 0; i+len(x) <= len(s); i++ {
		if s[i:i+len(x)] == x {
			return true
		}
	}
	return false
}

var _ dns.RecordType
