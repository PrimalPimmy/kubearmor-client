package scan

import (
	"context"
	"fmt"
	"github.com/accuknox/auto-policy-discovery/src/cluster"
	opb "github.com/accuknox/auto-policy-discovery/src/protobuf/v1/observability"
	"github.com/rs/zerolog/log"
	"golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"reflect"
	"strings"
)

func MountedSummary(namespace string, in *opb.Request) ([]*opb.Response, error) {
	client := cluster.ConnectK8sClient()

	podList, err := client.CoreV1().Pods(namespace).List(context.TODO(), metav1.ListOptions{})
	fmt.Printf("There are %d Pods in the cluster\n", len(podList.Items))

	if err != nil {
		log.Warn().Msg(err.Error())
		return nil, err
	}

	if len(podList.Items) > 0 {
		pod := podList.Items[0]
		//containersSATokenMountPath, err := getSATokenMountPath(&pod)
		if err != nil && strings.Contains(err.Error(), "service account token not mounted") {
			log.Warn().Msg(err.Error())
			return nil, err
		}
		var sumResponses []*opb.Response
		for _, container := range pod.Spec.Containers {
			in = &opb.Request{
				PodName:       pod.Name,
				NameSpace:     pod.Namespace,
				ContainerName: container.Name,
				Type:          "process,file,network",
			}
			sumResp, err := GetSummaryData(in)
			if err != nil {
				print("ERRRRRRRRRRRRRRRRRROR")
				log.Warn().Msg(err.Error())
				return nil, err
			}
			log.Info().Msg(sumResp.String())
			sumResponses = append(sumResponses, sumResp)
		}
		VolumeUsed(sumResponses, podList)
		return sumResponses, nil
	} else {
		log.Warn().Msg("No pods found for the given labels")
	}

	return nil, err
}

func VolumeUsed(sumResp []*opb.Response, pod *corev1.PodList) []Resp {
	p := Checkmount(pod)
	var result []Resp
	for _, mounts := range p {
		for _, sum := range sumResp {
			for _, file := range sum.FileData {
				if slices.Contains(mounts.Mounts, file.Destination) {
					result = append(result, Resp{
						PodName:       mounts.Podname,
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

		}
	}
	return result
}

//func GetData(namespace string, deploymentName string) ([]*Resp, error) {
//	var res []*Resp
//	client := cluster.ConnectK8sClient()
//	deployments := client.AppsV1().Deployments(namespace)
//	deployment, err := deployments.Get(context.TODO(), deploymentName, v1.GetOptions{})
//	deploymentMatchLabels := deployment.Spec.Selector.MatchLabels
//
//	pods, err := client.CoreV1().Pods(namespace).List(context.TODO(), v1.ListOptions{
//		LabelSelector: libs.LabelMapToString(deploymentMatchLabels),
//	})
//
//	fmt.Printf("There are %d Pods in the mentioned deployment\n", len(pods.Items))
//
//	if err != nil {
//		return nil, err
//	}
//
//	PodList := Checkmount(pods)
//	// We get Pods along with all their volume mounts
//
//}

type Volmount struct {
	Mounts  []string
	Podname string
}

var po []Volmount

type vol struct {
	Total []Volmount
}

func (vol *vol) addmount(item Volmount) []Volmount {
	vol.Total = append(vol.Total, item)
	return vol.Total
}

func Checkmount(Pods *corev1.PodList) []Volmount {
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

func MountType(volSource corev1.VolumeSource) (error, reflect.Type) {
	v := reflect.ValueOf(volSource)
	var reqVolume reflect.Value
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if !field.IsNil() {
			reqVolume = field
			break
		}
	}
	if reqVolume.CanConvert(reflect.TypeOf(&corev1.ProjectedVolumeSource{})) {
		fmt.Println("HER")
		projectedVol := reqVolume.Interface().(*corev1.ProjectedVolumeSource)
		fmt.Println(projectedVol)
	}
	fmt.Println(reqVolume)
	return nil, reqVolume.Type()
}

// TODO: Container metadata, volume type, VolumeSource, other table data

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
}

//func GetFileSummary(o Options) ([]*Resp, error) {
//	// var flag
//	var res []*Resp
//	var s string
//
//	data := &opb.Request{
//		Label:         o.Labels,
//		NameSpace:     o.Namespace,
//		PodName:       o.PodName,
//		ClusterName:   o.ClusterName,
//		ContainerName: o.ContainerName,
//		Aggregate:     o.Aggregation,
//	}
//
//	// create a client
//
//	podNameResp, err := GetPodNames(data)
//	if err != nil {
//		return nil, err
//	}
//	//FileData := [][]string{}
//	for _, podname := range podNameResp.PodName {
//		if podname == "" {
//			continue
//		}
//		sumResp, _ := GetSummaryData(&opb.Request{
//			PodName:   podname,
//			Type:      DefaultReqType,
//			Aggregate: false,
//		})
//
//		for _, f := range sumResp.FileData {
//
//			re := &Resp{
//				PodName:       podname,
//				ClusterName:   sumResp.ClusterName,
//				Namespace:     sumResp.Namespace,
//				Label:         sumResp.Label,
//				ContainerName: sumResp.ContainerName,
//				Source:        f.Source,
//				MountPath:     s,
//				UpdatedTime:   f.UpdatedTime,
//				Status:        f.Status,
//			}
//
//			res = append(res, re)
//		}
//
//	}
//
//	return res, err
//}
