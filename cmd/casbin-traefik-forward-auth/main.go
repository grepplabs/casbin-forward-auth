package main

import (
	"flag"

	"github.com/grepplabs/casbin-traefik-forward-auth/internal/config"
	"github.com/grepplabs/casbin-traefik-forward-auth/internal/server"
	"github.com/grepplabs/loggo/zlog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

var cfg config.Config

func main() {
	root := &cobra.Command{
		Use:   "server",
		Short: "casbin-traefik-forward-auth",
		Run: func(cmd *cobra.Command, args []string) {
			run()
		},
	}
	config.BindFlagsToViper(root)

	// server flags
	root.Flags().StringVar(&cfg.Server.Addr, "server-addr", ":8080", "Server listen address.")

	// auth flags
	root.Flags().StringVar(&cfg.Auth.RouteConfigPath, "auth-route-config-path", "", "Path to the config YAML file containing route authorization rules.")

	// casbin flags
	root.Flags().StringVar(&cfg.Casbin.Model, "casbin-model", "rbac_model.conf", "Path or reference to the Casbin model (e.g. file:///etc/casbin/model.conf or rbac_model.conf from embedded FS).")
	root.Flags().StringVar(&cfg.Casbin.Adapter, "casbin-adapter", "kube", "Casbin adapter. One of: file, kube.")
	root.Flags().DurationVar(&cfg.Casbin.AutoLoadPolicyInterval, "casbin-autoload-interval", 0, "Interval for automatically reloading Casbin policies (e.g. 30s, 1m). Set to 0 to disable.")
	/// casbin file adapter
	root.Flags().StringVar(&cfg.Casbin.AdapterFile.PolicyPath, "casbin-adapter-file-policy-path", "examples/rbac_policy.csv", "Path to the policy file.")
	/// casbin  kube adapter
	root.Flags().BoolVar(&cfg.Casbin.AdapterKube.DisableInformer, "casbin-adapter-kube-disable-informer", false, "Disable the Casbin Kubernetes informer.")
	root.Flags().StringVar(&cfg.Casbin.AdapterKube.Context, "casbin-adapter-kube-config-context", "", "Name of the Kubernetes context to use from the kubeconfig file.")
	root.Flags().StringVar(&cfg.Casbin.AdapterKube.Namespace, "casbin-adapter-kube-config-namespace", "default", "Kubernetes namespace where Casbin policies are stored.")
	root.Flags().StringVar(&cfg.Casbin.AdapterKube.Path, "casbin-adapter-kube-config-path", "", "Path to the kubeconfig file.")

	// Merge stdlib flags into pflag (so Cobra can see them)
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

	if err := root.Execute(); err != nil {
		zlog.Fatalw("execution error", "error", err)
	}
}

func run() {
	zlog.Infof("running")
	err := server.Start(cfg)
	if err != nil {
		zlog.Fatalw("problem running server", "error", err)
	}
}
