import time
from functools import partial as p
from textwrap import dedent

import pytest
from kubernetes import client
from tests.helpers.assertions import has_datapoint, has_dim_prop, has_dim_tag
from tests.helpers.kubernetes.fakeapiserver import fake_k8s_api_server
from tests.helpers.util import ensure_always, run_agent, wait_for

pytestmark = [pytest.mark.kubernetes_cluster, pytest.mark.perf_test]


def test_large_kubernetes_clusters():
    pod_count = 5000
    with fake_k8s_api_server(print_logs=True) as [fake_k8s_client, k8s_envvars]:
        pod_names = []
        uids = []

        v1_client = client.CoreV1Api(fake_k8s_client)
        for i in range(0, pod_count):
            name = f"pod-{i}"
            pod_names.append(name)

            uid = f"abcdefg{i}"
            uids.append(uid)

            v1_client.create_namespaced_pod(
                body={
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": name, "uid": uid, "namespace": "default", "labels": {"app": "my-app"}},
                    "spec": {},
                },
                namespace="default",
            )

        with run_agent(
            dedent(
                f"""
          writer:
            maxRequests: 100
            propertiesMaxRequests: 100
            propertiesHistorySize: 10000
          monitors:
           - type: internal-metrics
             intervalSeconds: 1
           - type: kubernetes-cluster
             alwaysClusterReporter: true
             intervalSeconds: 10
             kubernetesAPI:
                skipVerify: true
                authType: none
        """
            ),
            profile=True,
            debug=False,
            extra_env=k8s_envvars,
        ) as [backend, _, _, pprof_client]:
            assert wait_for(p(has_datapoint, backend, dimensions={"kubernetes_pod_name": "pod-0"}))
            assert wait_for(p(has_datapoint, backend, dimensions={"kubernetes_pod_name": "pod-4999"}))

            def has_all_pod_datapoints():
                for name in pod_names:
                    if not has_datapoint(backend, dimensions={"kubernetes_pod_name": name}):
                        return False
                return True

            def has_all_pod_properties():
                for uid in uids:
                    if not has_dim_prop(
                        backend, dim_name="kubernetes_pod_uid", dim_value=uid, prop_name="app", prop_value="my-app"
                    ):
                        return False
                return True

            assert wait_for(has_all_pod_datapoints, interval_seconds=2)
            assert wait_for(has_all_pod_properties, interval_seconds=2)

            for name in pod_names:
                v1_client.delete_namespaced_pod(name=name, namespace="default", body={})

            time.sleep(10)
            backend.reset_datapoints()

            def has_no_pod_datapoints():
                for name in pod_names:
                    if has_datapoint(backend, dimensions={"kubernetes_pod_name": name}):
                        return False
                return True

            assert ensure_always(has_no_pod_datapoints, interval_seconds=2)

            pprof_client.save_goroutines()
            assert (
                backend.datapoints_by_metric["sfxagent.go_num_goroutine"][-1].value.intValue < 100
            ), "too many goroutines"

            assert (
                backend.datapoints_by_metric["sfxagent.go_heap_alloc"][-1].value.intValue < 200 * 1024 * 1024
            ), "too much memory used"


# pylint: disable=too-many-locals
def test_large_kubernetes_cluster_service_tags():
    pod_count = 5000
    service_count = 25
    with fake_k8s_api_server(print_logs=True) as [fake_k8s_client, k8s_envvars]:
        pod_names = []
        uids = []
        service_names = []

        v1_client = client.CoreV1Api(fake_k8s_client)
        ## create pods
        for i in range(0, pod_count):
            name = f"pod-{i}"
            pod_names.append(name)

            uid = f"abcdefg{i}"
            uids.append(uid)

            v1_client.create_namespaced_pod(
                body={
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": name, "uid": uid, "namespace": "default", "labels": {"app": "my-app"}},
                    "spec": {},
                },
                namespace="default",
            )
        ## create services
        for i in range(0, service_count):
            service_name = f"service-{i}"
            service_names.append(service_name)
            v1_client.create_namespaced_service(
                body={
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": {"name": service_name, "uid": f"serviceUID{i}", "namespace": "default"},
                    "spec": {"selector": {"app": "my-app"}, "type": "LoadBalancer"},
                },
                namespace="default",
            )

        with run_agent(
            dedent(
                f"""
          writer:
            maxRequests: 100
            propertiesMaxRequests: 100
            propertiesHistorySize: 10000
          monitors:
           - type: internal-metrics
             intervalSeconds: 1
           - type: kubernetes-cluster
             alwaysClusterReporter: true
             intervalSeconds: 10
             kubernetesAPI:
                skipVerify: true
                authType: none
        """
            ),
            profile=True,
            debug=False,
            extra_env=k8s_envvars,
        ) as [backend, _, _, pprof_client]:
            assert wait_for(p(has_datapoint, backend, dimensions={"kubernetes_pod_name": "pod-0"}))
            assert wait_for(p(has_datapoint, backend, dimensions={"kubernetes_pod_name": "pod-4999"}))

            # assert wait_for(missing_service_tags, interval_seconds=2)

            def has_all_service_tags():
                for uid in uids:
                    for s_name in service_names:
                        if not has_dim_tag(
                            backend,
                            dim_name="kubernetes_pod_uid",
                            dim_value=uid,
                            tag_value=f"kubernetes_service_{s_name}",
                        ):
                            return False
                return True

            def has_all_pod_datapoints():
                for name in pod_names:
                    if not has_datapoint(backend, dimensions={"kubernetes_pod_name": name}):
                        return False
                return True

            def has_all_pod_properties():
                for uid in uids:
                    if not has_dim_prop(
                        backend, dim_name="kubernetes_pod_uid", dim_value=uid, prop_name="app", prop_value="my-app"
                    ):
                        return False
                return True

            assert wait_for(has_all_pod_datapoints, interval_seconds=2)
            assert wait_for(has_all_pod_properties, interval_seconds=2)
            assert wait_for(has_all_service_tags, interval_seconds=2)

            ## delete all services and make sure no pods have service tags
            for s_name in service_names:
                v1_client.delete_namespaced_service(name=s_name, namespace="default", body={})

            def missing_service_tags():
                for uid in uids:
                    for s_name in service_names:
                        if has_dim_tag(
                            backend,
                            dim_name="kubernetes_pod_uid",
                            dim_value=uid,
                            tag_value=f"kubernetes_service_{s_name}",
                        ):
                            return False
                return True

            assert wait_for(missing_service_tags, interval_seconds=2, timeout_seconds=60)

            pprof_client.save_goroutines()
            assert (
                backend.datapoints_by_metric["sfxagent.go_num_goroutine"][-1].value.intValue < 100
            ), "too many goroutines"

            assert (
                backend.datapoints_by_metric["sfxagent.go_heap_alloc"][-1].value.intValue < 200 * 1024 * 1024
            ), "too much memory used"


# pylint: disable=too-many-locals
def test_large_k8s_cluster_deployment_prop():
    """
    Creates 50 replica sets with 100 pods per replica set.
    Check that the deployment name is being synced to
    kubernetes_pod_uid, which is taken off the replica set's
    owner references.
    """
    dp_count = 50
    pods_per_dp = 100
    with fake_k8s_api_server(print_logs=True) as [fake_k8s_client, k8s_envvars]:
        v1_client = client.CoreV1Api(fake_k8s_client)
        v1beta1_client = client.ExtensionsV1beta1Api(fake_k8s_client)

        ## create small subset of resources in a different namespace to get baseline of heap usage
        v1_client.create_namespace(body={"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "dev"}})
        for i in range(0, 10):
            v1_client.create_namespaced_pod(
                body={
                    "apiVersion": "v1",
                    "kind": "Pod",
                    "metadata": {"name": f"pod-{i}", "uid": f"abcpod{i}", "namespace": "dev"},
                    "spec": {},
                },
                namespace="dev",
            )

        with run_agent(
            dedent(
                f"""
          writer:
            maxRequests: 100
            propertiesMaxRequests: 100
            propertiesHistorySize: 10000
          monitors:
           - type: internal-metrics
             intervalSeconds: 1
           - type: kubernetes-cluster
             alwaysClusterReporter: true
             intervalSeconds: 10
             kubernetesAPI:
                skipVerify: true
                authType: none
        """
            ),
            profile=True,
            debug=False,
            extra_env=k8s_envvars,
        ) as [backend, _, _, pprof_client]:
            assert wait_for(p(has_datapoint, backend, dimensions={"kubernetes_pod_name": "pod-0"}))
            assert wait_for(p(has_datapoint, backend, dimensions={"kubernetes_pod_name": "pod-9"}))

            ## get heap baseline heap usage
            time.sleep(10)
            pprof_client.save_goroutines()
            heap_usage_baseline = backend.datapoints_by_metric["sfxagent.go_heap_alloc"][-1].value.intValue

            ## create 50 replica sets with 100 pods each
            replicaSets = {}
            for i in range(0, dp_count):
                dp_name = f"dp-{i}"
                dp_uid = f"dpuid{i}"
                rs_name = dp_name + "-replicaset"
                rs_uid = dp_uid + "-rs"
                replicaSets[rs_uid] = {
                    "dp_name": dp_name,
                    "dp_uid": dp_uid,
                    "rs_name": rs_name,
                    "rs_uid": rs_uid,
                    "pod_uids": [],
                    "pod_names": [],
                }

                v1beta1_client.create_namespaced_replica_set(
                    body={
                        "apiVersion": "extensions/v1beta1",
                        "kind": "ReplicaSet",
                        "metadata": {
                            "name": rs_name,
                            "uid": rs_uid,
                            "namespace": "default",
                            "ownerReferences": [{"kind": "Deployment", "name": dp_name, "uid": dp_uid}],
                        },
                        "spec": {},
                        "status": {},
                    },
                    namespace="default",
                )

                for j in range(0, pods_per_dp):
                    pod_name = f"pod-{rs_name}-{j}"
                    pod_uid = f"abcdef{i}-{j}"
                    replicaSets[rs_uid]["pod_uids"].append(pod_uid)
                    replicaSets[rs_uid]["pod_names"].append(pod_name)
                    v1_client.create_namespaced_pod(
                        body={
                            "apiVersion": "v1",
                            "kind": "Pod",
                            "metadata": {
                                "name": pod_name,
                                "uid": pod_uid,
                                "namespace": "default",
                                "labels": {"app": "my-app"},
                                "ownerReferences": [{"kind": "ReplicaSet", "name": rs_name, "uid": rs_uid}],
                            },
                            "spec": {},
                        },
                        namespace="default",
                    )

            def has_all_deployment_props():
                for _, rs in replicaSets.items():
                    for pod_uid in rs["pod_uids"]:
                        if not has_dim_prop(
                            backend,
                            dim_name="kubernetes_pod_uid",
                            dim_value=pod_uid,
                            prop_name="deployment",
                            prop_value=rs["dp_name"],
                        ):
                            return False
                        if not has_dim_prop(
                            backend,
                            dim_name="kubernetes_pod_uid",
                            dim_value=pod_uid,
                            prop_name="deployment_uid",
                            prop_value=rs["dp_uid"],
                        ):
                            return False
                    return True

            def has_all_replicaSet_props():
                for _, rs in replicaSets.items():
                    for pod_uid in rs["pod_uids"]:
                        if not has_dim_prop(
                            backend,
                            dim_name="kubernetes_pod_uid",
                            dim_value=pod_uid,
                            prop_name="replicaSet",
                            prop_value=rs["rs_name"],
                        ):
                            return False
                        if not has_dim_prop(
                            backend,
                            dim_name="kubernetes_pod_uid",
                            dim_value=pod_uid,
                            prop_name="replicaSet_uid",
                            prop_value=rs["rs_uid"],
                        ):
                            return False
                    return True

            assert wait_for(p(has_datapoint, backend, dimensions={"kubernetes_pod_name": "pod-dp-0-replicaset-0"}))
            assert wait_for(p(has_datapoint, backend, dimensions={"kubernetes_pod_name": "pod-dp-49-replicaset-99"}))

            assert wait_for(has_all_deployment_props, interval_seconds=2)

            for _, rs in replicaSets.items():
                v1beta1_client.delete_namespaced_replica_set(name=rs["rs_name"], namespace="default", body={})
                for pod_name in rs["pod_names"]:
                    v1_client.delete_namespaced_pod(name=pod_name, namespace="default", body={})

            def go_routines():
                pprof_client.save_goroutines()
                return backend.datapoints_by_metric["sfxagent.go_num_goroutine"][-1].value.intValue < 100

            assert wait_for(go_routines, interval_seconds=2, timeout_seconds=60)

            def heap_baselined():
                pprof_client.save_goroutines()
                heap_usage = backend.datapoints_by_metric["sfxagent.go_heap_alloc"][-1].value.intValue
                print("-------------------------")
                print(heap_usage_baseline)
                print(heap_usage)
                return (
                    backend.datapoints_by_metric["sfxagent.go_heap_alloc"][-1].value.intValue
                    < 1.25 * heap_usage_baseline
                )

            assert wait_for(heap_baselined, interval_seconds=2, timeout_seconds=60)
