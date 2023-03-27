// Package scan to scan for risks
package scan

import (
	"context"
	"errors"
	"fmt"
	v1 "k8s.io/api/core/v1"
	"os"
	"regexp"
	"strconv"

	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/kubearmor/kubearmor-client/k8s"
	"github.com/kubearmor/kubearmor-client/utils"
	"github.com/olekukonko/tablewriter"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/strings/slices"
)

type volmount struct {
	Mounts  string
	Podname []string
}

var p volmount

type vol struct {
	Total []volmount
}

func (vol *vol) addmount(item volmount) []volmount {
	vol.Total = append(vol.Total, item)
	return vol.Total
}

//func mount(Pods *v1.PodList) {
//	for _, pods := range Pods.Items {
//		for _, p := range pods.Spec.Containers {
//			for _, name := range p.VolumeMounts {
//				pod := volmount{
//					Podname: pods.Name,
//					Mounts:  name.MountPath,
//				}
//
//
//			}
//		}
//	}
//	b, err := json.MarshalIndent(dets, "", "    ")
//	if err != nil {
//		fmt.Println(err)
//		return
//	}
//	fmt.Println(string(b), "\n\n\n\n\n")

func CheckVolSource(volume v1.Volume) interface{} {
	switch {

	case volume.HostPath != nil:
		return func() interface{} { return volume.HostPath.Path }
	case volume.EmptyDir != nil:
		return func() interface{} { return "emptyDir" }
	case volume.ConfigMap != nil:
		return func() interface{} { return volume.ConfigMap.LocalObjectReference.Name }
	case volume.Secret != nil:
		return func() interface{} { return volume.Secret.SecretName }
	case volume.PersistentVolumeClaim != nil:
		return func() interface{} { return volume.PersistentVolumeClaim.ClaimName }
	case volume.GitRepo != nil:
		return func() interface{} { return volume.GitRepo.Repository }
	case volume.DownwardAPI != nil:
		return func() interface{} { return "downwardAPI" }
	case volume.AzureFile != nil:
		return func() interface{} { return volume.AzureFile.ShareName }
	case volume.AzureDisk != nil:
		return func() interface{} { return volume.AzureDisk.DiskName }
	case volume.FC != nil:
		return func() interface{} { return volume.FC.TargetWWNs }
	case volume.Flocker != nil:
		return func() interface{} { return volume.Flocker.DatasetName }
	case volume.CephFS != nil:
		return func() interface{} { return volume.CephFS.Monitors[0] }
	case volume.Cinder != nil:
		return func() interface{} { return volume.Cinder.VolumeID }
	default:
		return nil
	}
}

func Scan(c *k8s.Client, o Options) error {
	clientset, err := k8s.ConnectK8sClient()
	if err != nil {
		return err
	}

	pods, err := clientset.K8sClientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return err
	}

	fmt.Printf("There are %d Pods in the cluster\n", len(pods.Items))
	//mount(pods, dets)
	for _, Pods := range pods.Items {
		for _, volume := range Pods.Spec.Volumes {
			volSource := CheckVolSource(volume)
			fmt.Print(volSource)
			if volSource == volume.Projected {
				if volume.Projected.Sources != nil {
					for _, v := range volume.Projected.Sources {
						if v.ServiceAccountToken != nil {
							// fmt.Println("SA Token is mounted")
							p.Podname = append(p.Podname, Pods.Name)
						}
						// fmt.Print("\n", v.ServiceAccountToken.Path)

					}
				}

			} else {
			}
		}
	}

	GetFileSummary(c, o)
	return nil
	// -, err := GetFileSummary(clientset)
	// if err != nil {
	// 	panic(err)
	// }

}

type Options struct {
	GRPC          string
	Labels        string
	Namespace     string
	PodName       string
	ClusterName   string
	ContainerName string
	Type          string
	Output        string
	RevDNSLookup  bool
	Aggregation   bool
}

var FileHeader = []string{"Accessed By", "Mount Path", "Pod Name", "Last Accessed", "Status"}
var port int64 = 9089
var matchLabels = map[string]string{"app": "discovery-engine"}
var DefaultReqType = "process,file,network"

func GetFileSummary(c *k8s.Client, o Options) ([]string, error) {
	// var flag bool
	var s string
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
		Label:         o.Labels,
		NameSpace:     o.Namespace,
		PodName:       o.PodName,
		ClusterName:   o.ClusterName,
		ContainerName: o.ContainerName,
		Aggregate:     o.Aggregation,
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
	FileData := [][]string{}
	for _, podname := range podNameResp.PodName {
		var fi []string
		var pods []string
		if podname == "" {
			continue
		}
		sumResp, err := client.Summary(context.Background(), &opb.Request{
			PodName:   podname,
			Type:      DefaultReqType,
			Aggregate: false,
		})

		if err != nil {
			return nil, err
		}
		// fmt.Println(slices.Contains(files, "/var/run/secrets/kubernetes.io/serviceaccount/token"))
		r, _ := regexp.Compile("\\/run\\/secrets\\/kubernetes.io\\/serviceaccount\\/[^\\/]+\\/token")
		for _, a := range sumResp.FileData {
			if r.MatchString(a.Destination) {
				s = r.FindString(a.Destination)
			}
		}
		//fmt.Print(slices.Contains(file, s), "\n")
		//fmt.Print(s, "\n")
		for _, fileData := range sumResp.FileData {
			fi = append(fi, fileData.Destination)
		}

		for _, f := range sumResp.FileData {

			if f.Destination == s {
				pods = append(pods, podname)

				if slices.Contains(p.Podname, podname) {
					fileStrSlice := []string{}
					fileStrSlice = append(fileStrSlice, f.Source)
					fileStrSlice = append(fileStrSlice, s)
					fileStrSlice = append(fileStrSlice, podname)
					fileStrSlice = append(fileStrSlice, f.UpdatedTime)
					fileStrSlice = append(fileStrSlice, f.Status)
					FileData = append(FileData, fileStrSlice)
				}
			}

		}

		if slices.Contains(fi, s) == false {
			pods = append(pods, podname)
			if slices.Contains(p.Podname, podname) {
				fileStrSlice := []string{}
				fileStrSlice = append(fileStrSlice, "-")
				fileStrSlice = append(fileStrSlice, s)
				fileStrSlice = append(fileStrSlice, podname)
				fileStrSlice = append(fileStrSlice, "-")
				fileStrSlice = append(fileStrSlice, "-")
				FileData = append(FileData, fileStrSlice)
				//WriteTable(FileHeader, FileData)

			}
		}

	}
	WriteTable(FileHeader, FileData)

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
