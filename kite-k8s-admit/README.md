# Kite Admission Controller

The Kite Admission Controller is a general-purpose Kubernetes [mutating admission webhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#mutatingadmissionwebhook) designed to apply user-defined [JSON patches](https://datatracker.ietf.org/doc/html/rfc6902) to new Pods as they are scheduled in the cluster. 

It is used in the Kite project to inject [Init Containers](https://kubernetes.io/docs/concepts/workloads/pods/init-containers/) into Pods for pre-start metric collection.


## Configuration File


The admission controller requires a configuration file in YAML or JSON format to specify patching rules.

Each rule consists of an optional label selector and a list of JSON patches to apply to Pods that match the selector.


- selectors: Define inclusion and exclusion criteria based on pod labels.
  - include: Apply patches to Pods with these labels. If empty, all Pods are included.
  - exclude: Do not apply patches to Pods with these labels. Exclude takes precedence over include.
- patches: List of JSON patch operations specifying the modifications to apply.
  - op: Type of operation (e.g., `add`).
  - path: Target path in the pod spec in [JSON Pointer](https://datatracker.ietf.org/doc/html/rfc6901) format.
  - value: Value for the operation.


> 💡 Note: Normally, JSON patches cannot modify values that don’t exist in the document. However, the admission controller will automatically create necessary fields if they are missing, so you can use the `add` operation freely without concern for field existence.

### Example 1: Injecting KUBE_POD_NAME into every Container

To inject the `KUBE_POD_NAME` environment variable into a container, this configuration can be used:

```yaml
# config.yaml
rules: 
- selectors: {}
  patches:
  - op: add
    path: /spec/containers/0/env/-
    value:
      name: KUBE_POD_NAME
      valueFrom:
        fieldRef:
          fieldPath: metadata.name
```

This will add the `KUBE_POD_NAME` environment variable to the first container in each pod's container list.


### Example 2: Injecting a volume mount into specific Pods

```yaml
# config.yaml
rules:
- selectors:
    include:
      matchLabels:
        app: my-app
  patches:
    - op: add
      path: /spec/containers/0/volumeMounts/-
      value:
        name: my-volume
        mountPath: /path/to/mount
    - op: add
      path: /spec/volumes/-
      value:
        name: my-volume
        emptyDir: {}
```

## Deployment

See the k8s manifest for the [admission_controller](../manifests/admission_controller.yaml) for how to deploy it.
