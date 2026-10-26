package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/labdns/labdns/internal/app"
	"github.com/labdns/labdns/internal/config"
	"github.com/labdns/labdns/internal/dns"
	"github.com/labdns/labdns/internal/tui"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
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
	root.AddCommand(
		initCmd(o),
		withApp(o, "discover", func(ctx context.Context, a *app.App, args []string) (any, error) { return a.Discover(ctx) }),
		withApp(o, "plan", func(ctx context.Context, a *app.App, args []string) (any, error) { return a.CreatePlan(ctx) }),
		applyCmd(o),
		withApp(o, "verify", func(ctx context.Context, a *app.App, args []string) (any, error) {
			p, e := a.CreatePlan(ctx)
			if e != nil {
				return nil, e
			}
			return a.Provider.Verify(ctx, p.Desired)
		}),
		withApp(o, "database verify", func(ctx context.Context, a *app.App, args []string) (any, error) {
			return map[string]string{"status": "ok"}, a.Store.IntegrityCheck()
		}),
		providersCmd(o),
		doctorCmd(o),
		repairCmd(o),
		staleCmd(o),
		pruneCmd(o),
		adoptCmd(o),
		backupCmd(o),
		exportCmd(o),
		daemonCmd(o),
		tuiCmd(o),
	)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if e := root.ExecuteContext(ctx); e != nil {
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
func providersCmd(o *options) *cobra.Command {
	return &cobra.Command{Use: "providers", Short: "List supported DNS providers", RunE: func(cmd *cobra.Command, args []string) error {
		return printResult([]map[string]string{
			{"type": "pihole", "name": "Pi-hole", "records": "A"},
			{"type": "adguard", "name": "AdGuard Home", "records": "A, AAAA, CNAME"},
			{"type": "technitium", "name": "Technitium DNS Server", "records": "A, AAAA, CNAME, PTR, SRV, TXT"},
			{"type": "rfc2136", "name": "RFC 2136 dynamic DNS", "records": "A, AAAA, CNAME, PTR, SRV, TXT"},
			{"type": "hostsfile", "name": "Hosts file", "records": "A, AAAA"},
		}, o.json)
	}}
}
func doctorCmd(o *options) *cobra.Command {
	return &cobra.Command{Use: "doctor", Short: "Check configuration, state and provider health", RunE: func(cmd *cobra.Command, args []string) error {
		a, e := load(o)
		if e != nil {
			return e
		}
		defer a.Close()
		ctx, cancel := context.WithTimeout(cmd.Context(), 60*time.Second)
		defer cancel()
		report := a.Doctor(ctx)
		if e = printResult(report, o.json); e != nil {
			return e
		}
		if !report.OK {
			return fmt.Errorf("doctor found one or more critical issues")
		}
		return nil
	}}
}
func repairCmd(o *options) *cobra.Command {
	return withApp(o, "repair", func(ctx context.Context, a *app.App, args []string) (any, error) {
		return a.Repair(ctx, time.Now().UTC().Add(-time.Hour))
	})
}
func staleCmd(o *options) *cobra.Command {
	var olderThan time.Duration
	c := withApp(o, "stale", func(ctx context.Context, a *app.App, args []string) (any, error) {
		grace := olderThan
		if grace == 0 {
			grace = a.Config.Reconciliation.StaleGracePeriod
		}
		return a.Stale(ctx, time.Now().UTC().Add(-grace))
	})
	c.Flags().DurationVar(&olderThan, "older-than", 0, "only list records stale for at least this long (defaults to reconciliation.stale_grace_period)")
	return c
}
func pruneCmd(o *options) *cobra.Command {
	var olderThan time.Duration
	c := withApp(o, "prune", func(ctx context.Context, a *app.App, args []string) (any, error) {
		grace := olderThan
		if grace == 0 {
			grace = a.Config.Reconciliation.StaleGracePeriod
		}
		stale, e := a.Stale(ctx, time.Now().UTC().Add(-grace))
		if e != nil {
			return nil, e
		}
		if o.dryRun {
			return stale, nil
		}
		if !o.approve {
			return nil, fmt.Errorf("prune requires --approve")
		}
		res, records, e := a.Prune(ctx, time.Now().UTC().Add(-grace))
		if e != nil {
			return nil, e
		}
		return map[string]any{"result": res, "deleted": records}, nil
	})
	c.Flags().DurationVar(&olderThan, "older-than", 0, "delete records stale for at least this long (defaults to reconciliation.stale_grace_period)")
	c.Flags().BoolVar(&o.approve, "approve", false, "approve deletion")
	return c
}
func adoptCmd(o *options) *cobra.Command {
	var typ string
	var serviceID string
	c := withApp(o, "adopt", func(ctx context.Context, a *app.App, args []string) (any, error) {
		if len(args) != 1 {
			return nil, fmt.Errorf("adopt requires exactly one record name")
		}
		rt := dns.RecordType(strings.ToUpper(typ))
		return a.Adopt(ctx, args[0], rt, serviceID)
	})
	c.Flags().StringVar(&typ, "type", "", "record type (A, AAAA, CNAME, PTR, SRV, TXT)")
	c.Flags().StringVar(&serviceID, "service-id", "manual", "service identity stored with ownership")
	return c
}
func backupCmd(o *options) *cobra.Command {
	var output string
	c := withApp(o, "backup", func(ctx context.Context, a *app.App, args []string) (any, error) {
		if output == "" {
			return nil, fmt.Errorf("backup requires --output")
		}
		if e := a.Backup(output); e != nil {
			return nil, e
		}
		return map[string]string{"backup": output, "status": "ok"}, nil
	})
	c.Flags().StringVar(&output, "output", "", "destination database file")
	return c
}
func exportCmd(o *options) *cobra.Command {
	var output, format string
	c := withApp(o, "export", func(ctx context.Context, a *app.App, args []string) (any, error) {
		data, e := a.Export()
		if e != nil {
			return nil, e
		}
		if output == "" {
			return data, nil
		}
		if format == "" {
			format = strings.TrimPrefix(strings.ToLower(filepath.Ext(output)), ".")
		}
		if format == "" || format == "json" {
			b, e := json.MarshalIndent(data, "", "  ")
			if e != nil {
				return nil, e
			}
			b = append(b, '\n')
			return map[string]string{"export": output, "status": "ok"}, os.WriteFile(output, b, 0600)
		}
		if format != "yaml" && format != "yml" {
			return nil, fmt.Errorf("unsupported export format %q; use json or yaml", format)
		}
		b, e := yaml.Marshal(data)
		if e != nil {
			return nil, e
		}
		return map[string]string{"export": output, "status": "ok"}, os.WriteFile(output, b, 0600)
	})
	c.Flags().StringVar(&output, "output", "", "destination file (prints to stdout when omitted)")
	c.Flags().StringVar(&format, "format", "", "json or yaml (defaults to the output extension)")
	return c
}
func daemonCmd(o *options) *cobra.Command {
	var once bool
	c := &cobra.Command{Use: "daemon", Short: "Run periodic reconciliation", RunE: func(cmd *cobra.Command, args []string) error {
		for {
			a, e := load(o)
			if e != nil {
				return e
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Minute)
			plan, e := a.CreatePlan(ctx)
			if e == nil && a.Config.Reconciliation.AutomaticUpdates {
				actionable := false
				for _, c := range plan.Changes {
					if c.Type != dns.ChangeNoChange {
						actionable = true
					}
				}
				if actionable {
					if _, e = a.Apply(ctx, plan); e != nil {
						cancel()
						a.Close()
						return e
					}
				}
			}
			if e == nil && a.Config.Reconciliation.AutomaticDeletes {
				if _, _, e = a.Prune(ctx, time.Now().UTC().Add(-a.Config.Reconciliation.StaleGracePeriod)); e != nil {
					cancel()
					a.Close()
					return e
				}
			}
			cancel()
			a.Close()
			if e != nil {
				return e
			}
			if once {
				return printResult(map[string]string{"status": "ok"}, o.json)
			}
			select {
			case <-cmd.Context().Done():
				return nil
			case <-time.After(a.Config.Reconciliation.Interval):
			}
		}
	}}
	c.Flags().BoolVar(&once, "once", false, "run one reconciliation pass and exit")
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
	if contains(s, "doctor") {
		return 4
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
