package cmd

import (
	"fmt"

	"github.com/organicveggie/psychic-tribble/build"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Long:  `Version prints the build information for this binarry.`,
	Run:   runVersion,
}

func init() {
	rootCmd.AddCommand(versionCmd)
}

func runVersion(cmd *cobra.Command, args []string) {
	fmt.Println("Version:\t", build.Version)
	fmt.Println("Commit:\t\t", build.Commit)
	fmt.Println("Build Date:\t", build.Date)
	fmt.Println("Build User:\t", build.BuiltBy)
}
