// Package scan to scan for risks
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"

	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubearmor/kubearmor-client/k8s"
	"github.com/kubearmor/kubearmor-client/utils"
	"github.com/mgutz/ansi"
	"github.com/olekukonko/tablewriter"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/strings/slices"
)

func main() {
	clientset, err := k8s.ConnectK8sClient()

	pods, err := clientset.K8sClientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}

	fmt.Printf("There are %d pods in the cluster\n", len(pods.Items))
	for _, Pods := range pods.Items {
		for _, volume := range Pods.Spec.Volumes {
			if volume.Projected != nil {
				if volume.Projected.Sources != nil {
					for _, v := range volume.Projected.Sources {
						if v.ServiceAccountToken != nil {
							// fmt.Println("SA Token is mounted")
							p = append(p, Pods.Name)
						}
						// fmt.Print("\n", v.ServiceAccountToken.Path)

					}
				}
			}
		}
	}

	GetFileSummary(clientset)

	// -, err := GetFileSummary(clientset)
	// if err != nil {
	// 	panic(err)
	// }

}

type Options struct {
	PodName     string
	GRPC        string
	Type        string
	Aggregation bool
}

var p []string
var FileHeader = []string{"Severity", "Risk", "Pod Name"}
var port int64 = 9089
var matchLabels = map[string]string{"app": "discovery-engine"}
var DefaultReqType = "process,file,network"

func GetFileSummary(c *k8s.Client) ([]string, error) {
	var o Options
	// var flag bool

	gRPC := ""
	targetSvc := "discovery-engine"
	if o.GRPC != "" {
		gRPC = o.GRPC
	} else {
		if val, ok := os.LookupEnv("DISCOVERY_SERVICE"); ok {
			gRPC = val
		} else {
			pf, err := utils.InitiatePortForward(c, port, port, matchLabels, targetSvc)
			if err != nil {
				return nil, err
			}
			gRPC = "localhost:" + strconv.FormatInt(pf.LocalPort, 10)
		}
	}

	data := &opb.Request{
		// Label:         o.Labels,
		// NameSpace:     o.Namespace,
		PodName: o.PodName,
		// ClusterName:   o.ClusterName,
		// ContainerName: o.ContainerName,
		// Aggregate:     o.Aggregation,
	}

	// create a client
	conn, err := grpc.Dial(gRPC, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, errors.New("could not connect to the server. Possible troubleshooting:\n- Check if discovery engine is running\n- kubectl get po -n accuknox-agents")
	}
	defer conn.Close()

	client := opb.NewObservabilityClient(conn)
	podNameResp, err := client.GetPodNames(context.Background(), data)
	if err != nil {
		return nil, err
	}

	for _, podname := range podNameResp.PodName {
		var files []string
		var pods []string
		if podname == "" {
			continue
		}
		sumResp, err := client.Summary(context.Background(), &opb.Request{
			PodName:   podname,
			Type:      DefaultReqType,
			Aggregate: false,
		})

		for _, fileData := range sumResp.FileData {
			files = append(files, fileData.Destination)
		}
		if err != nil {
			return nil, err
		}
		// fmt.Println(slices.Contains(files, "/var/run/secrets/kubernetes.io/serviceaccount/token"))
		if !slices.Contains(files, "/var/run/secrets/kubernetes.io/serviceaccount/token") {
			pods = append(pods, podname)

			arc := ansi.ColorFunc("red")
			FileData := [][]string{}
			if slices.Contains(p, podname) {
				fileStrSlice := []string{}
				fileStrSlice = append(fileStrSlice, arc("HIGH"))
				fileStrSlice = append(fileStrSlice, "Service Account Token is mounted but not used")
				fileStrSlice = append(fileStrSlice, podname)
				FileData = append(FileData, fileStrSlice)
				WriteTable(FileHeader, FileData)

			}

		}

	}

	return nil, err
}

func WriteTable(header []string, data [][]string) {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(header)
	table.SetRowLine(true)
	table.SetRowSeparator("-")
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	for _, v := range data {
		table.Append(v)
	}
	table.Render()
}

func sliceToSet(mySlice []string) mapset.Set[string] {
	mySet := mapset.NewSet[string]()
	for _, ele := range mySlice {
		mySet.Add(ele)
	}
	return mySet
}
