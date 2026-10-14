package cmd

import (
	"encoding/json"
	"fmt"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"veribib/internal/hayagriva"
)

func newScanCmd() *cobra.Command {
	var asJSON bool
	c := &cobra.Command{
		Use:   "scan <bibliography.yaml>",
		Short: "List the references in a Hayagriva file and the URLs that would be archived",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var bibfile = "bibliography.yml"
			if len(args) > 0 {
				bibfile = args[0]
			}

			refs, err := hayagriva.Parse(bibfile)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			if asJSON {
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(refs)
			}

			tw := tabwriter.NewWriter(out, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "KEY\tTYPE\tURL")
			withURL := 0
			for _, r := range refs {
				u := r.URL
				if u == "" {
					u = "-"
				} else {
					withURL++
				}

				fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Key, r.Type, u)
			}

			tw.Flush()
			fmt.Fprintf(out, "\n%d references: %d with a URL, %d without (will be skipped)\n",
				len(refs), withURL, len(refs)-withURL)
			return nil
		},
	}

	c.Flags().BoolVar(&asJSON, "json", false, "output JSON")
	return c
}
