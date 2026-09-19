package main

import (
	"os"
	"strings"
)

// normalizeLegacyFlags converts single-dash long flags (like `-serve :8700` or `-demo`)
// into standard double-dash flags (`--serve :8700`, `--demo`) for seamless compatibility
// with Render deploy scripts, standard Go flag syntax, and POSIX style.
func normalizeLegacyFlags(args []string) []string {
	if len(args) <= 1 {
		return args
	}
	out := make([]string, len(args))
	out[0] = args[0]
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
			// Single dash with a multi-character flag name (e.g. -serve, -demo, -config, -audit)
			name := arg[1:]
			if eqIdx := strings.Index(name, "="); eqIdx != -1 {
				flagName := name[:eqIdx]
				if len(flagName) > 1 {
					out[i] = "--" + name
					continue
				}
			} else if len(name) > 1 {
				out[i] = "--" + name
				continue
			}
		}
		out[i] = arg
	}
	return out
}

func main() {
	os.Args = normalizeLegacyFlags(os.Args)
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
