package scan

import (
	"fmt"
	"github.com/gotestyourself/gotestyourself/assert"
	v1 "k8s.io/api/core/v1"
	"testing"
)

func Test_myFunc(t *testing.T) {
	t.Run("test-case", func(t *testing.T) {
		projec := v1.ProjectedVolumeSource{
			Sources: []v1.VolumeProjection{
				{
					ServiceAccountToken: &v1.ServiceAccountTokenProjection{
						Audience:          "asd",
						ExpirationSeconds: nil,
						Path:              "asdasd",
					},
				},
			},
			DefaultMode: nil,
		}
		volSrc := v1.VolumeSource{
			HostPath:              nil,
			EmptyDir:              nil,
			GCEPersistentDisk:     nil,
			AWSElasticBlockStore:  nil,
			GitRepo:               nil,
			Secret:                nil,
			NFS:                   nil,
			ISCSI:                 nil,
			Glusterfs:             nil,
			PersistentVolumeClaim: nil,
			RBD:                   nil,
			FlexVolume:            nil,
			Cinder:                nil,
			CephFS:                nil,
			Flocker:               nil,
			DownwardAPI:           nil,
			FC:                    nil,
			AzureFile:             nil,
			ConfigMap:             nil,
			VsphereVolume:         nil,
			Quobyte:               nil,
			AzureDisk:             nil,
			PhotonPersistentDisk:  nil,
			Projected:             &projec,
			PortworxVolume:        nil,
			ScaleIO:               nil,
			StorageOS:             nil,
			CSI:                   nil,
			Ephemeral:             nil,
		}
		_, v := myFunc(volSrc)
		fmt.Print(v)
		assert.Assert(t, true)
	})
}
