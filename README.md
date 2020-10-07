# CKS

## Cluster Setup – 10%

### Use Network security policies to restrict cluster level access

```bash
kubectl explain NetworkPolicy.spec
```

### Use CIS benchmark to review the security configuration of Kubernetes components (etcd, kubelet, kubedns, kubeapi)

???

### Properly set up Ingress objects with security control

```yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: ingress
  annotations:
    nginx.org/rewrites: "serviceName=srvmdex rewrite=/"
    ingress.kubernetes.io/ssl-redirect: "false"
    kubernetes.io/ingress.class: {{ .Values.ingressclass }}
    nginx.org/websocket-services: "srvcmps-websocketservice"
spec:
  tls:
  - hosts:
      {{- range .Values.ingresshosts }}
        - {{ . | quote }}
      {{- end }}
    secretName: ingresswildcardcert
  rules:
  - host: {{ .Values.ingresshostinternal | quote }}
    http:
      paths:
      - path: /
        backend:
          serviceName: srvcmps
          servicePort: 80
```

### Protect node metadata and endpoints

<https://kubernetes.io/blog/2016/03/how-container-metadata-changes-your-point-of-view/>

### Minimize use of, and access to, GUI elements

<https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/>

### Verify platform binaries before deploying

```bash
echo -n "bla" | sha256sum
cat <binary> | sha256sum
cat <binary> | sha512sum
```

<https://kubernetes.io/docs/setup/release/notes/#client-binaries>

<https://kubernetes.io/docs/tasks/tools/install-kubectl/>

```bash
curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl"
curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.19.0/bin/linux/amd64/kubectl
```

## Cluster Hardening – 15%

### Restrict access to Kubernetes API

<https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/>

### Use Role Based Access Controls to minimize exposure

<https://kubernetes.io/docs/reference/access-authn-authz/rbac/>

### Exercise caution in using service accounts e.g. disable defaults, minimize permissions on newly created ones

<https://kubernetes.io/docs/tasks/tools/install-kubectl/>

<https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/>

```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: build-robot
automountServiceAccountToken: false
```

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: my-pod
spec:
  serviceAccountName: build-robot
  automountServiceAccountToken: false
```

### Update Kubernetes frequently

<https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/>

<https://kubernetes.io/docs/setup/release/notes/#client-binaries>

## System Hardening – 15%

### Minimize host OS footprint (reduce attack surface)

### Minimize IAM roles

### Minimize external access to the network

- set loadbalancer to ClusterIP
- network policies

### Appropriately use kernel hardening tools such as AppArmor, seccomp

<https://kubernetes.io/docs/tutorials/clusters/apparmor/>
<https://kubernetes.io/docs/tutorials/clusters/seccomp/>

Example pod with audit.json

```bash
apiVersion: v1
kind: Pod
metadata:
  name: audit-pod
  labels:
    app: audit-pod
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: profiles/audit.json
  containers:
  - name: test-container
    image: hashicorp/http-echo:0.2.3
    args:
    - "-text=just made some syscalls!"
    securityContext:
      allowPrivilegeEscalation: false
```

path in pod yaml must be relative, to kubelet seccomp folder

```bash
/var/lib/kubelet/seccomp/profiles/audit.json
```

audit.json

```bash
{
    "defaultAction": "SCMP_ACT_LOG"
}
```

trigger the pod (curl ip:5678) and check the logs `tail -f /var/log/syslog | grep 'http-echo'`

## Minimize Microservice Vulnerabilities – 20%

### Setup appropriate OS level security domains e.g. using PSP, OPA, security contexts

POD SECURITY POLICY

```yaml
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: example
spec:
  privileged: false  # Don't allow privileged pods!
  # The rest fills in some required fields.
  seLinux:
    rule: RunAsAny
  supplementalGroups:
    rule: RunAsAny
  runAsUser:
    rule: RunAsAny
  fsGroup:
    rule: RunAsAny
  volumes:
  - '*'
```

http://blog.tundeoladipupo.com/2019/06/01/Kubernetes,-PodSecurityPolicy-and-Kubeadm/

OPEN POLICY AGENT

SECURITY CONTEXT

<https://kubernetes.io/docs/tasks/configure-pod-container/security-context/>

`kubectl explain pod.spec.securityContext`

`kubectl explain pod.spec.containers.securityContext`
  
Settings in spec.containers.securityContex override spec.containers.securityContext

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: security-context-demo
spec:
  securityContext:
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
  volumes:
  - name: sec-ctx-vol
    emptyDir: {}
  containers:
  - name: sec-ctx-demo
    image: busybox
    command: [ "sh", "-c", "sleep 1h" ]
    volumeMounts:
    - name: sec-ctx-vol
      mountPath: /data/demo
    securityContext:
      allowPrivilegeEscalation: false
```

### Manage Kubernetes secrets

<https://kubernetes.io/docs/concepts/configuration/secret/>

`kubectl create secret generic NAME --from-literal=KEY=VALUE`
`kubectl create secret generic NAME --from-file=KEY=file.txt`
`kubectl create secret generic NAME --from-env-file=file.env`

file.env

```text
KEY1=VALUE1
KEY2=VALUE2
```

`kubectl create secret tls tls-secret --cert=path/to/tls.cert --key=path/to/tls.key`

### Use container runtime sandboxes in multi-tenant environments (e.g. gvisor, kata containers)

### Implement pod to pod encryption by use of mTLS



## Supply Chain Security – 20%

### Minimize base image footprint

<https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/>

```
    gcr.io/distroless/static-debian10
    gcr.io/distroless/base-debian10
    gcr.io/distroless/java-debian10
    gcr.io/distroless/cc-debian10
```

### Secure your supply chain: whitelist allowed registries, sign and validate images



### Use static analysis of user workloads (e.g.Kubernetes resources, Docker files)

### Scan images for known vulnerabilities

## Monitoring, Logging and Runtime Security – 20%

### Perform behavioral analytics of syscall process and file activities at the host and container level to detect malicious activities

### Detect threats within physical infrastructure, apps, networks, data, users and workloads

### Detect all phases of attack regardless where it occurs and how it spreads

### Perform deep analytical investigation and identification of bad actors within environment

### Ensure immutability of containers at runtime

```
apiVersion: apps/v1
kind: Deployment
metadata:
  name: app
spec:
  selector:
    matchLabels:
      app.kubernetes.io/name: app
  template:
    metadata:
      labels:
        app.kubernetes.io/name: app
      name: app
    spec:
      containers:
      - env:
        - name: TMPDIR
          value: /tmp
        image: my/app:1.0.0
        name: app
        securityContext:
          readOnlyRootFilesystem: true
        volumeMounts:
        - mountPath: /tmp
          name: tmp
      volumes:
      - emptyDir: {}
        name: tmp
```

### Use Audit Logs to monitor access

## Command reference 1.19

```bash
kubectl explain
kubectl config get-contexts
kubectl config set-context CONTEXT_NAME [--namespace=namespace]
kubectl config use-context CONTEXT_NAME
kubectl run
kubectl create deployment
kubectl create secret
kubectl create role
kubectl create rolebinding
kubectl create clusterrole
kubectl create clusterrolebinding
kubectl patch serviceaccount default -p '{"imagePullSecrets": [{"name": "myregistrykey"}]}'
kubectl scale
kubectl top nodes
kubectl top pods
kubectl get pods
kubectl get nodes
kubectl get service
kubectl get deployments [-o wide] [-A]
kubectl cluster-info
kubectl [rollout|scale|autoscale]
kubectl get componentstatuses
kubectl expose [pod|deployment]
kubectl exec -it --rm NAME --image=IMAGE
kubectl logs POD_NAME -c CONTAINER_NAME --tail=5 -f
```

```bash
cat>1.yaml<<EOF
bla
EOF

ls -ltr
netstat -ltnp

command: ["/bin/sh"] args: ["-c","while true; do echo hello; sleep 10;done"]
... args: ["if [ \"$(shuf -i 1-100 -n 1)\" -gt \"50\" ]; then exit 0; else exit 1; fi"]

ETCDCTL_API=3 etcdctl snapshot save <file> --endpoints... --cacert --cert --key

/etc/systemd/system/...
/etc/cni/net.d/...
/etc/kubernetes/pki
/usr/local/bin


vi yy=copy
p=paste
?=search /=backs <l>gg

docker stat / inspect
kubectl top

iptables -t nat -L KUBE-SERVICES
```

## references

<https://github.com/David-VTUK/CKA-StudyGuide/blob/master/RevisionTopics/Part-5-Security.md>

<https://blog.heptio.com/on-securing-the-kubernetes-dashboard-16b09b1b7aca>

<https://cloud.google.com/blog/products/gcp/7-best-practices-for-building-containers>

## CKS prep sites

<https://blog.nativecloud.dev/how-to-prepare-for-the-upcoming-cks-certification/>

<https://github.com/walidshaari/Certified-Kubernetes-Security-Specialist>

<https://github.com/ijelliti/CKSS-Certified-Kubernetes-Security-Specialist>

<https://acloud.guru/learn/7d2c29e7-cdb2-4f44-8744-06332f47040e>



