package config

import (
	"fmt"
	"log"
	"strings"

	"github.com/grepplabs/loggo/zlog"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func BindFlagsToViper(cmd *cobra.Command) {
	cobra.OnInitialize(func() {
		viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
		viper.AutomaticEnv()

		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			zlog.Fatalw("unable to bind flags to viper", "error", err)
		}
		if err := viper.BindPFlags(cmd.PersistentFlags()); err != nil {
			zlog.Fatalw("unable to bind persistent flags to viper", "error", err)
		}
		setFromViper := func(fs *pflag.FlagSet) {
			fs.VisitAll(func(f *pflag.Flag) {
				if !f.Changed && viper.IsSet(f.Name) {
					if err := fs.Set(f.Name, fmt.Sprint(viper.Get(f.Name))); err != nil {
						log.Fatalf("Unable to set flag %q from viper: %v", f.Name, err)
					}
				}
			})
		}
		setFromViper(cmd.Flags())
		setFromViper(cmd.PersistentFlags())
	})
}
