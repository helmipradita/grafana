// Package permissioncleanup deletes a datasource's IAM ResourcePermission after the datasource is deleted.
package permissioncleanup

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/open-feature/go-sdk/openfeature"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"

	authlib "github.com/grafana/authlib/types"
	iamv0 "github.com/grafana/grafana/apps/iam/pkg/apis/iam/v0alpha1"
	"github.com/grafana/grafana/pkg/apimachinery/identity"
	datasourceV0 "github.com/grafana/grafana/pkg/apis/datasource/v0alpha1"
	"github.com/grafana/grafana/pkg/bus"
	"github.com/grafana/grafana/pkg/infra/features"
	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/infra/tracing"
	"github.com/grafana/grafana/pkg/services/apiserver"
	"github.com/grafana/grafana/pkg/services/featuremgmt"
	"github.com/grafana/grafana/pkg/services/sqlstore"
)

var tracer = otel.Tracer("github.com/grafana/grafana/pkg/services/datasources/permissioncleanup")

var errClientNotConfigured = errors.New("IAM resource permission client is not configured")

// ResourcePermissionName returns the name of the ResourcePermission holding a datasource's permissions.
// Every datasource plugin type shares the datasource.grafana.app group.
func ResourcePermissionName(uid string) string {
	return fmt.Sprintf("%s-%s-%s", datasourceV0.GROUP, datasourceV0.DataSourceResourceInfo.GroupResource().Resource, uid)
}

// ClientFunc returns the IAM ResourcePermission client. A nil client means none is configured.
type ClientFunc func(ctx context.Context) (dynamic.NamespaceableResourceInterface, error)

// Cleaner deletes datasource ResourcePermissions through the IAM API when
// kubernetesAuthzDatasourceResourcePermissions is enabled. A nil *Cleaner is valid and never enabled,
// leaving permission cleanup to the legacy SQL path.
type Cleaner struct {
	client   ClientFunc
	licensed func() bool
	logger   log.Logger
}

// New returns a Cleaner. licensed may be nil when no license gates the IAM path. events, when set,
// receives cleanups queued by DeleteAfterCommit; it must be the bus the SQL store publishes on.
func New(client ClientFunc, licensed func() bool, events bus.Bus) *Cleaner {
	c := &Cleaner{
		client:   client,
		licensed: licensed,
		logger:   log.New("datasources.permissioncleanup"),
	}
	if events != nil {
		events.AddEventListener(c.onCommitted)
	}
	return c
}

// ProvideDisabled is used where the IAM API cannot serve datasource ResourcePermissions,
// keeping the legacy SQL cleanup.
func ProvideDisabled() *Cleaner {
	return nil
}

// NewStandalone returns a Cleaner using an injected IAM client, for services without SQL transactions.
func NewStandalone(client *dynamic.NamespaceableResourceInterface) *Cleaner {
	return New(func(context.Context) (dynamic.NamespaceableResourceInterface, error) {
		if client == nil {
			return nil, nil
		}
		return *client, nil
	}, nil, nil)
}

// RestConfigClient builds the IAM client lazily: the loopback rest config is not ready while
// API groups are registered. Failures are not cached.
func RestConfigClient(restConfigProvider apiserver.RestConfigProvider) ClientFunc {
	var (
		mu     sync.Mutex
		client dynamic.NamespaceableResourceInterface
	)
	return func(ctx context.Context) (dynamic.NamespaceableResourceInterface, error) {
		mu.Lock()
		defer mu.Unlock()
		if client != nil {
			return client, nil
		}
		cfg, err := restConfigProvider.GetRestConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("get rest config: %w", err)
		}
		dyn, err := dynamic.NewForConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("create dynamic client: %w", err)
		}
		client = dyn.Resource(iamv0.ResourcePermissionInfo.GroupVersionResource())
		return client, nil
	}
}

// Enabled reports whether the IAM API owns permission cleanup for datasources in namespace.
// The flag is evaluated for namespace so background callers do not use an unrelated tenant.
func (c *Cleaner) Enabled(ctx context.Context, namespace string) bool {
	if c == nil {
		return false
	}
	if c.licensed != nil && !c.licensed() {
		return false
	}
	ctx = openfeature.MergeTransactionContext(ctx, openfeature.NewEvaluationContext(namespace, map[string]any{
		features.NamespaceKey: namespace,
	}))
	return openfeature.NewDefaultClient().Boolean(ctx, featuremgmt.FlagKubernetesAuthzDatasourceResourcePermissions, false, openfeature.TransactionContext(ctx))
}

type datasourcePermissionCleanup struct {
	namespace string
	uid       string
}

// DeleteAfterCommit runs Delete once the outermost SQL transaction in ctx commits, and never on rollback.
// Without a transaction it runs Delete immediately.
func (c *Cleaner) DeleteAfterCommit(ctx context.Context, namespace, uid string) {
	if sess := sqlstore.SessionFromContext(ctx); sess != nil {
		sess.PublishAfterCommit(&datasourcePermissionCleanup{namespace: namespace, uid: uid})
		return
	}
	c.Delete(ctx, namespace, uid)
}

func (c *Cleaner) onCommitted(ctx context.Context, event *datasourcePermissionCleanup) error {
	c.Delete(ctx, event.namespace, event.uid)
	return nil
}

// Delete removes the datasource's ResourcePermission. It is best effort: a missing permission counts as
// deleted and other failures are logged, never returned, so they cannot fail the datasource deletion.
func (c *Cleaner) Delete(ctx context.Context, namespace, uid string) {
	name := ResourcePermissionName(uid)
	ctx, span := tracer.Start(context.WithoutCancel(ctx), "permissioncleanup.Delete", trace.WithAttributes(
		attribute.String("namespace", namespace),
		attribute.String("datasource_uid", uid),
		attribute.String("resource_permission", name),
	))
	defer span.End()

	if err := c.delete(ctx, namespace, name); err != nil {
		_ = tracing.Error(span, err)
		c.logger.FromContext(ctx).Error("Failed to delete datasource resource permission",
			"namespace", namespace, "uid", uid, "resourcePermission", name, "error", err)
	}
}

func (c *Cleaner) delete(ctx context.Context, namespace, name string) error {
	ns, err := authlib.ParseNamespace(namespace)
	if err != nil {
		return fmt.Errorf("parse namespace: %w", err)
	}
	client, err := c.client(ctx)
	if err != nil {
		return fmt.Errorf("get IAM resource permission client: %w", err)
	}
	if client == nil {
		return errClientNotConfigured
	}

	// Cleanup follows a deletion the caller was already allowed to make; it must not
	// require the caller to also manage the datasource's permissions.
	ctx = identity.WithServiceIdentityContext(ctx, ns.OrgID)
	err = client.Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	return nil
}
