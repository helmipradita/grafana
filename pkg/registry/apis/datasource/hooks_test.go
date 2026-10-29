package datasource

import (
	"testing"

	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	datasourceV0 "github.com/grafana/grafana/pkg/apis/datasource/v0alpha1"
	"github.com/grafana/grafana/pkg/services/datasources/permissioncleanup"
	"github.com/grafana/grafana/pkg/services/datasources/permissioncleanup/permissioncleanuptest"
)

func TestAfterDeleteCleansUpResourcePermission(t *testing.T) {
	enabled := permissioncleanuptest.Permission{Namespace: "stacks-2", UID: "ds-uid"}
	disabled := permissioncleanuptest.Permission{Namespace: "stacks-1", UID: "ds-uid"}
	permissioncleanuptest.EnableFlag(t, enabled.Namespace)
	client := permissioncleanuptest.NewClient(enabled, disabled)
	b := &DataSourceAPIBuilder{}
	b.SetPermissionCleaner(permissioncleanup.New(permissioncleanuptest.ClientFunc(client), nil, nil))

	for _, p := range []permissioncleanuptest.Permission{enabled, disabled} {
		b.afterDelete(&datasourceV0.DataSource{ObjectMeta: metav1.ObjectMeta{Namespace: p.Namespace, Name: p.UID}}, nil)
	}

	require.False(t, permissioncleanuptest.Exists(t, client, enabled))
	require.True(t, permissioncleanuptest.Exists(t, client, disabled), "the flag is off for this namespace")
}
