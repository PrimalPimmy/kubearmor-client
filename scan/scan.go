// Package scan to scan for risks
package scan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/accuknox/auto-policy-discovery/src/cluster"
	obs "github.com/accuknox/auto-policy-discovery/src/observability"
	"path/filepath"

	//"github.com/accuknox/auto-policy-discovery/src/cluster"
	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
	"github.com/kubearmor/kubearmor-client/k8s"
	"github.com/kubearmor/kubearmor-client/utils"
	"github.com/olekukonko/tablewriter"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/slices"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

type Volmount struct {
	Mounts    []string
	Podname   string
	MountType string
}

var po []Volmount

func gRPCConnection(c *k8s.Client, o Options) (*grpc.ClientConn, error) {
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
	// create a client
	conn, err := grpc.Dial(gRPC, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, errors.New("could not connect to the server. Possible troubleshooting:\n- Check if discovery engine is running\n- kubectl get po -n accuknox-agents")
	}
	return conn, err

}

func Scan(c *k8s.Client, o Options) error {

	client, err := k8s.ConnectK8sClient()

	podList, err := client.K8sClientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	fmt.Printf("There are %d Pods in the cluster\n", len(podList.Items))

	data := &opb.Request{
		Label:         o.Labels,
		NameSpace:     o.Namespace,
		PodName:       o.PodName,
		ClusterName:   o.ClusterName,
		ContainerName: o.ContainerName,
		Aggregate:     o.Aggregation,
	}
	// create a client
	//var sumResponses []*opb.Response

	conn, err := gRPCConnection(c, o)
	if err != nil {
		return errors.New("could not connect to the server. Possible troubleshooting:\n- Check if discovery engine is running\n- kubectl get po -n accuknox-agents")
	}

	// create a client
	defer conn.Close()
	Sumclient := opb.NewObservabilityClient(conn)
	if err != nil {
		fmt.Println(err)
	}
	Res, err := Sumclient.Scan(context.Background(), data)
	if err != nil {
		//fmt.Println(err, "ERRRRRRRRRRROR")
	}
	b, err := json.MarshalIndent(Res, "", "    ")
	fmt.Print(string(b))
	FileData := [][]string{}

	for _, file := range Res.FileResp {
		fileStrSlice := []string{}
		fileStrSlice = append(fileStrSlice, file.Source)
		fileStrSlice = append(fileStrSlice, file.MountPath)
		fileStrSlice = append(fileStrSlice, Res.PodName)
		fileStrSlice = append(fileStrSlice, file.UpdatedTime)
		fileStrSlice = append(fileStrSlice, file.Status)
		fileStrSlice = append(fileStrSlice, file.Severity)
		FileData = append(FileData, fileStrSlice)
	}

	WriteTable(FileHeader, FileData)
	return err
}
func Checkmount(Pods *v1.PodList) []Volmount {
	var pod Volmount
	for _, pods := range Pods.Items {
		var mount []string
		for _, p := range pods.Spec.Containers {
			for _, name := range p.VolumeMounts {
				mount = append(mount, name.MountPath)
				pod = Volmount{Podname: pods.Name, Mounts: mount}
			}

		}
		po = append(po, pod)
	}
	return po
}

type containerMountPathServiceAccountToken struct {
	podName          string
	podNamespace     string
	containerName    string
	saTokenMountPath string
}

func ShouldSATokenBeAutoMounted() bool {
	client := cluster.ConnectK8sClient()

	podList, err := client.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})

	if err != nil {
		log.Warn().Msg(err.Error())
		return true
	}

	if len(podList.Items) > 0 {
		// Only inspect the first pod in the list as deployment pods have same behavior
		pod := podList.Items[0]
		containersSATokenMountPath, err := getSATokenMountPath(&pod)
		if err != nil && strings.Contains(err.Error(), "service account token not mounted") {
			log.Warn().Msg(err.Error())
			return false
		}
		var sumResponses []*opb.Response
		for _, container := range pod.Spec.Containers {
			sumResp, err := obs.GetSummaryData(&opb.Request{
				PodName:       pod.Name,
				NameSpace:     pod.Namespace,
				ContainerName: container.Name,
				Type:          "process,file",
			})
			if err != nil {
				log.Warn().Msg(err.Error())
				return true
			}
			log.Info().Msg(sumResp.String())
			sumResponses = append(sumResponses, sumResp)
		}
		return serviceAccountTokenUsed(containersSATokenMountPath, sumResponses)
	} else {
		log.Warn().Msg("No pods found for the given labels")
	}

	return true
}

func getSATokenMountPath(pod *v1.Pod) ([]containerMountPathServiceAccountToken, error) {
	volumes := pod.Spec.Volumes
	var tokenPath string
	var projectedVolumeName string
	var result = make([]containerMountPathServiceAccountToken, 0)
	for _, volume := range volumes {
		if volume.Projected != nil {
			for _, projectedSources := range volume.Projected.Sources {
				serviceAccountToken := projectedSources.ServiceAccountToken
				if serviceAccountToken != nil {
					tokenPath = serviceAccountToken.Path
					projectedVolumeName = volume.Name
					break
				}
			}
		}
	}

	if tokenPath == "" || projectedVolumeName == "" {
		return result,
			fmt.Errorf("service account token not mounted for %s in namespace %s", pod.Name, pod.Namespace)
	}

	containers := pod.Spec.Containers
	for _, container := range containers {
		volumeMounts := container.VolumeMounts
		for _, volumeMount := range volumeMounts {
			if volumeMount.Name == projectedVolumeName {
				result = append(result, containerMountPathServiceAccountToken{
					podName:          pod.Name,
					podNamespace:     pod.Namespace,
					containerName:    container.Name,
					saTokenMountPath: volumeMount.MountPath + string(filepath.Separator) + tokenPath,
				})
			}
		}
	}
	return result, nil
}

func serviceAccountTokenUsed(containersSATokenMountPath []containerMountPathServiceAccountToken, sumResponses []*opb.Response) bool {
	serviceAccountTokenUsed := false
	for _, containerSATokenMountPath := range containersSATokenMountPath {
		for _, sumResp := range sumResponses {
			for _, fileData := range sumResp.FileData {
				if sumResp.ContainerName == containerSATokenMountPath.containerName {
					// Even if one container uses the service account token, we should allow auto mounting
					if matchesSATokenPath(containerSATokenMountPath.saTokenMountPath, fileData.Destination) {
						serviceAccountTokenUsed = true
						break
					}
				}
			}
		}
	}
	return serviceAccountTokenUsed
}

func matchesSATokenPath(saTokenPath, sumRespPath string) bool {
	sumRespPathParts := strings.Split(sumRespPath, string(filepath.Separator))
	pattern := "..[0-9]{4}_[0-9]{2}_[0-9]{2}.*"
	sumRespPathPartsWithoutDoubleDot := removeMatchingElements(sumRespPathParts, pattern)
	sumpRespPathWithoutDoubleDot := strings.Join(sumRespPathPartsWithoutDoubleDot, string(filepath.Separator))
	if strings.HasSuffix(saTokenPath, sumpRespPathWithoutDoubleDot) {
		return true
	}
	return false
}

func removeMatchingElements(slice []string, pattern string) []string {
	r := regexp.MustCompile(pattern)
	result := make([]string, 0)

	for _, s := range slice {
		if !r.MatchString(s) {
			result = append(result, s)
		}
	}

	return result
}

func removeDuplicates(res []Resp) []Resp {
	encountered := map[Resp]bool{}
	result := []Resp{}

	for _, person := range res {
		if encountered[person] == true {
			// Do not add duplicate person
		} else {
			encountered[person] = true
			result = append(result, person)
		}
	}

	return result
}

func VolumeUsed(sumResp []*opb.Response, pod *v1.PodList) []Resp {
	p := Checkmount(pod)
	var result []Resp
	var fi []string
	var re Resp
	FileData := [][]string{}
	for _, mounts := range p {

		for _, sum := range sumResp {
			for _, fileData := range sum.FileData {
				fi = append(fi, fileData.Destination)
			}
			for _, file := range sum.FileData {
				r, _ := regexp.Compile("\\/run\\/secrets\\/kubernetes.io\\/serviceaccount\\/[^\\/]+\\/token")
				//fmt.Println(matchesSATokenPath())
				if slices.Contains(mounts.Mounts, file.Destination) && mounts.Podname == sum.PodName {
					result = append(result, Resp{
						PodName:       sum.PodName,
						ClusterName:   sum.ClusterName,
						Namespace:     sum.Namespace,
						Label:         sum.Label,
						ContainerName: sum.ContainerName,
						Source:        file.Source,
						MountPath:     file.Destination,
						UpdatedTime:   file.UpdatedTime,
						Status:        file.Status,
					})

				} else if r.MatchString(file.Destination) {
					result = append(result, Resp{
						PodName:       sum.PodName,
						ClusterName:   sum.ClusterName,
						Namespace:     sum.Namespace,
						Label:         sum.Label,
						ContainerName: sum.ContainerName,
						Source:        file.Source,
						MountPath:     file.Destination,
						UpdatedTime:   file.UpdatedTime,
						Status:        file.Status,
					})
				}

			}
			for _, m := range mounts.Mounts {
				if !slices.Contains(fi, m) && mounts.Podname == sum.PodName {
					fmt.Println(m)
					re = Resp{
						PodName:       sum.PodName,
						ClusterName:   sum.ClusterName,
						Namespace:     sum.Namespace,
						Label:         sum.Label,
						ContainerName: sum.ContainerName,
						Source:        "-",
						MountPath:     m,
						UpdatedTime:   "-",
						Severity:      "VERY HIGH",
						Status:        "-",
					}
					result = append(result, re)

					//fileStrSlice := []string{}
					//fileStrSlice = append(fileStrSlice, "-")
					//fileStrSlice = append(fileStrSlice, m)
					//fileStrSlice = append(fileStrSlice, sum.PodName)
					//fileStrSlice = append(fileStrSlice, "-")
					//fileStrSlice = append(fileStrSlice, "-")
					//AssessmentFileData = append(AssessmentFileData, fileStrSlice)
				}
			}
		}
	}

	for i := 0; i < len(result); i++ {
		if (Resp{}) == result[i] {
			result = append(result[:i], result[i+1:]...)
			i--
		}
	}
	result = removeDuplicates(result)
	//fmt.Println(result)

	for _, r := range result {
		fileStrSlice := []string{}
		fileStrSlice = append(fileStrSlice, r.Source)
		fileStrSlice = append(fileStrSlice, r.MountPath)
		fileStrSlice = append(fileStrSlice, r.PodName)
		fileStrSlice = append(fileStrSlice, r.UpdatedTime)
		fileStrSlice = append(fileStrSlice, r.Status)
		fileStrSlice = append(fileStrSlice, r.Severity)
		FileData = append(FileData, fileStrSlice)
	}
	WriteTable(FileHeader, FileData)
	return result
}

func myFunc(volSource v1.VolumeSource) (error, reflect.Type) {
	v := reflect.ValueOf(volSource)
	var reqVolume reflect.Value
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if !field.IsNil() {
			reqVolume = field
			break
			//		}
		}
		if reqVolume.CanConvert(reflect.TypeOf(&v1.ProjectedVolumeSource{})) {
			fmt.Println("HER")
			projectedVol := reqVolume.Interface().(*v1.ProjectedVolumeSource)
			fmt.Println(projectedVol)
		}
		fmt.Println(reqVolume)
	}
	return nil, reqVolume.Type()
}

//
//// TODO: Container metadata, volume type, VolumeSource, other table data
//

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

var FileHeader = []string{"Accessed By", "Mount Path", "Pod Name", "Last Accessed", "Status", "Severity"}
var port int64 = 9089
var matchLabels = map[string]string{"app": "discovery-engine"}
var DefaultReqType = "process,file,network"

type Resp struct {
	PodName       string
	ClusterName   string
	Namespace     string
	Label         string
	ContainerName string
	Source        string
	MountPath     string
	UpdatedTime   string
	Status        string
	Severity      string
}

// WriteTable function
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
