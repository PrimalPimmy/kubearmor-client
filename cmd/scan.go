// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package cmd

import (
	"github.com/kubearmor/kubearmor-client/scan"
	"github.com/spf13/cobra"
)

var scanOptions scan.Options

// scanCmd represents the summary command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Risk Scanning",
	Long:  `Discovery engine keeps the telemetry information from the policy enforcement engines and the karmor connects to it to provide this as observability data`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := scan.Scan(client, scanOptions); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)

	scanCmd.Flags().StringVar(&scanOptions.GRPC, "gRPC", "", "gRPC server information")
	scanCmd.Flags().StringVarP(&scanOptions.Labels, "labels", "l", "", "Labels")
	scanCmd.Flags().StringVarP(&scanOptions.Namespace, "namespace", "n", "", "Namespace")
	scanCmd.Flags().StringVarP(&scanOptions.PodName, "pod", "p", "", "PodName")
	scanCmd.Flags().StringVarP(&scanOptions.Type, "type", "t", scan.DefaultReqType, "Summary filter type : process|file|network ")
	scanCmd.Flags().StringVar(&scanOptions.ClusterName, "cluster", "", "Cluster name")
	scanCmd.Flags().StringVar(&scanOptions.ContainerName, "container", "", "Container name")
	scanCmd.Flags().StringVarP(&scanOptions.Output, "output", "o", "", "Export Summary Data in JSON (karmor summary -o json)")
	scanCmd.Flags().BoolVar(&scanOptions.RevDNSLookup, "rev-dns-lookup", false, "Reverse DNS Lookup")
	scanCmd.Flags().BoolVar(&scanOptions.Aggregation, "agg", false, "Aggregate destination files/folder path")
}
