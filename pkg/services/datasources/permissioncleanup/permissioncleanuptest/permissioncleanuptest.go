// Package permissioncleanuptest provides fakes for tests of datasource permission cleanup.
package permissioncleanuptest

import (
	"context"
	"sync"
	"testing"

	"github.com/open-feature/go-sdk/openfeature"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	iamv0 "github.com/grafana/grafana/apps/iam/pkg/apis/iam/v0alpha1"
	"github.com/grafana/grafana/pkg/services/datasources/permissioncleanup"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
)

var flagMu sync.Mutex

type namespaceFlagProvider struct {
	openfeature.NoopProvider
	namespaces map[string]bool
}

func (p namespaceFlagProvider) BooleanEvaluation(_ context.Context, flag string, defaultValue bool, evalCtx openfeature.FlattenedContext) openfeature.BoolResolutionDetail {
	if flag != featuremgmt.FlagKubernetesAuthzDatasourceResourcePermissions {
		return openfeature.BoolResolutionDetail{Value: defaultValue}
	}
	ns, _ := evalCtx[openfeature.TargetingKey].(string)
	return openfeature.BoolResolutionDetail{Value: p.namespaces[ns]}
}

// EnableFlag turns kubernetesAuthzDatasourceResourcePermissions on for the given namespaces only,
// for the duration of the test.
func EnableFlag(t testing.TB, namespaces ...string) {
	t.Helper()
	flagMu.Lock()
	enabled := make(map[string]bool, len(namespaces))
	for _, ns := range namespaces {
		enabled[ns] = true
	}
	require.NoError(t, openfeature.SetProviderAndWait(namespaceFlagProvider{namespaces: enabled}))
	t.Cleanup(func() {
		_ = openfeature.SetProviderAndWait(openfeature.NoopProvider{})
		flagMu.Unlock()
	})
}

// Permission is a datasource ResourcePermission held by the fake IAM client.
type Permission struct {
	Namespace string
	UID       string
}

// NewClient returns a fake IAM client holding the given ResourcePermissions.
func NewClient(permissions ...Permission) *dynamicfake.FakeDynamicClient {
	gvr := iamv0.ResourcePermissionInfo.GroupVersionResource()
	objs := make([]runtime.Object, 0, len(permissions))
	for _, p := range permissions {
		objs = append(objs, &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": iamv0.ResourcePermissionInfo.GroupVersion().String(),
			"kind":       iamv0.ResourcePermissionInfo.GroupVersionKind().Kind,
			"metadata": map[string]any{
				"namespace": p.Namespace,
				"name":      permissioncleanup.ResourcePermissionName(p.UID),
			},
		}})
	}
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{gvr: iamv0.ResourcePermissionInfo.GroupVersionKind().Kind + "List"}, objs...)
}

// ClientFunc returns a permissioncleanup.ClientFunc serving client.
func ClientFunc(client dynamic.Interface) permissioncleanup.ClientFunc {
	return func(context.Context) (dynamic.NamespaceableResourceInterface, error) {
		return client.Resource(iamv0.ResourcePermissionInfo.GroupVersionResource()), nil
	}
}

// Exists reports whether client still holds the ResourcePermission.
func Exists(t testing.TB, client dynamic.Interface, p Permission) bool {
	t.Helper()
	_, err := client.Resource(iamv0.ResourcePermissionInfo.GroupVersionResource()).Namespace(p.Namespace).
		Get(context.Background(), permissioncleanup.ResourcePermissionName(p.UID), metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return false
	}
	require.NoError(t, err)
	return true
}
