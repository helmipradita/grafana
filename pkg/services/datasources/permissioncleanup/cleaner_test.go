package permissioncleanup_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	k8stesting "k8s.io/client-go/testing"

	"github.com/grafana/grafana/pkg/services/datasources/permissioncleanup"
	"github.com/grafana/grafana/pkg/services/datasources/permissioncleanup/permissioncleanuptest"
)

func TestResourcePermissionName(t *testing.T) {
	require.Equal(t, "datasource.grafana.app-datasources-abc", permissioncleanup.ResourcePermissionName("abc"))
}

func TestCleaner_Enabled(t *testing.T) {
	permissioncleanuptest.EnableFlag(t, "org-2")
	ctx := context.Background()

	var disabled *permissioncleanup.Cleaner
	require.False(t, disabled.Enabled(ctx, "org-2"))

	licensed := true
	c := permissioncleanup.New(nil, func() bool { return licensed }, nil)
	require.True(t, c.Enabled(ctx, "org-2"))
	require.False(t, c.Enabled(ctx, "org-1"), "the flag is evaluated for the datasource's namespace")

	licensed = false
	require.False(t, c.Enabled(ctx, "org-2"))
}

func TestCleaner_Delete(t *testing.T) {
	deleted := permissioncleanuptest.Permission{Namespace: "org-2", UID: "ds-uid"}
	otherTenant := permissioncleanuptest.Permission{Namespace: "org-1", UID: "ds-uid"}

	t.Run("deletes the canonical permission in the datasource's namespace only", func(t *testing.T) {
		client := permissioncleanuptest.NewClient(deleted, otherTenant)
		c := permissioncleanup.New(permissioncleanuptest.ClientFunc(client), nil, nil)

		c.Delete(context.Background(), deleted.Namespace, deleted.UID)

		require.False(t, permissioncleanuptest.Exists(t, client, deleted))
		require.True(t, permissioncleanuptest.Exists(t, client, otherTenant))
	})

	t.Run("a missing permission and a repeated delete are no-ops", func(t *testing.T) {
		client := permissioncleanuptest.NewClient(otherTenant)
		c := permissioncleanup.New(permissioncleanuptest.ClientFunc(client), nil, nil)

		c.Delete(context.Background(), deleted.Namespace, deleted.UID)
		c.Delete(context.Background(), deleted.Namespace, deleted.UID)

		require.True(t, permissioncleanuptest.Exists(t, client, otherTenant))
	})

	t.Run("runs after the caller's context is cancelled", func(t *testing.T) {
		client := permissioncleanuptest.NewClient(deleted)
		c := permissioncleanup.New(permissioncleanuptest.ClientFunc(client), nil, nil)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		c.DeleteAfterCommit(ctx, deleted.Namespace, deleted.UID)

		require.False(t, permissioncleanuptest.Exists(t, client, deleted))
	})

	t.Run("failures are not returned", func(t *testing.T) {
		client := permissioncleanuptest.NewClient(deleted)
		client.PrependReactor("delete", "resourcepermissions", func(k8stesting.Action) (bool, runtime.Object, error) {
			return true, nil, errors.New("iam unavailable")
		})

		for _, c := range []*permissioncleanup.Cleaner{
			permissioncleanup.New(permissioncleanuptest.ClientFunc(client), nil, nil),
			permissioncleanup.New(func(context.Context) (dynamic.NamespaceableResourceInterface, error) {
				return nil, errors.New("rest config unavailable")
			}, nil, nil),
			permissioncleanup.NewStandalone(nil),
		} {
			c.Delete(context.Background(), deleted.Namespace, deleted.UID)
		}

		require.True(t, permissioncleanuptest.Exists(t, client, deleted))
	})
}
