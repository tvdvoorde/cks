# CKS

Sections with a (*) are in progress and only have links and not yet additional content

## Cluster Setup – 10%

<details><summary>Use Network security policies to restrict cluster level access</summary>

```bash
kubectl explain NetworkPolicy.spec
```

NetworkPolicy's are applied to a namespace. The spec.podSelector defines criteria for the namespace.

Default deny all ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector: {}
  policyTypes:
  - Ingress
```

Default allow all ingress

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-ingress
spec:
  podSelector: {}
  ingress:
  - {}
  policyTypes:
  - Ingress
```

Default deny all egress

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
spec:
  podSelector: {}
  policyTypes:
  - Egress
```

Default allow all egress

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-all-egress
spec:
  podSelector: {}
  egress:
  - {}
  policyTypes:
  - Egress
```

Deny all ingress & egress

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

Real world example

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-microservice-to-microservice
spec:
  podSelector:
    matchLabels: 
      application: one4all
  policyTypes:
  - Ingress
  ingress:
    - from:
      - podSelector:
          matchLabels:
            application: one4all
      ports:
      - protocol: TCP
        port: 6000
      - protocol: TCP
        port: 5000
```

<https://kubernetes.io/docs/concepts/services-networking/network-policies/>

<https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/>

<https://kubernetes.io/docs/tasks/administer-cluster/declare-network-policy/>

<https://kubernetes.io/blog/2017/10/enforcing-network-policies-in-kubernetes/>

<https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/>

</details>

<details><summary>Use CIS benchmark to review the security configuration of Kubernetes components (etcd, kubelet, kubedns, kubeapi)</summary>

CIS Kubernetes Benchmark v1.6.0

<https://learn.cisecurity.org/l/799323/2020-07-22/28v4r>

<https://cloud.google.com/kubernetes-engine/docs/concepts/cis-benchmarks>

<https://www.cisecurity.org/benchmark/kubernetes/>

<https://docs.microsoft.com/en-us/microsoft-365/compliance/offering-cis-benchmark>

<https://github.com/aquasecurity/kube-bench#running-kube-bench>

```bash
git clone https://github.com/aquasecurity/kube-bench.git
kubectl apply -f job.yaml
kubectl get pod
kubectl logs kube-bench-vpqbg
```

<https://cloud.google.com/kubernetes-engine/docs/concepts/cis-benchmarks#default-values>

</details>

<details><summary>Properly set up Ingress objects with security control</summary>

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

<https://kubernetes.io/docs/concepts/services-networking/ingress/>

<https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/>

<https://kubernetes.io/docs/tasks/access-application-cluster/ingress-minikube/>

<https://kubernetes.io/docs/concepts/services-networking/ingress/#tls>

</details>

<details><summary>Protect node metadata and endpoints</summary>

Implement taints & tolerations to place workload

Implement nodeselector to place workload

Implement networksecuritypolicy to prevent access to metadata endpoint

Example code to get metadata on Azure

```bash
curl -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2020-06-01"
wget -qO- --header="Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2020-06-01"
```

Create network policy file

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-specific-endpoint
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32
```

Create namespace `kubectl create ns test`

Apply policy `kubectl apply -f <file> -n test`

Run a busybox pod `kubectl run wget --image=busybox:1.28 -n test -it --rm /bin/sh`

Test

```bash
wget ...
```

Other links:

<https://kubernetes.io/blog/2016/03/how-container-metadata-changes-your-point-of-view/>

<https://blog.cloud66.com/setting-up-secure-endpoints-in-kubernetes/>

<https://cloud.google.com/kubernetes-engine/docs/how-to/protecting-cluster-metadata>

<https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/#restricting-cloud-metadata-api-access>

<https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html>

<https://docs.aws.amazon.com/eks/latest/userguide/restrict-ec2-credential-access.html>

</details>

<details><summary>Minimize use of, and access to, GUI elements</summary>

<https://kubernetes.io/docs/tasks/access-application-cluster/web-ui-dashboard/>

<https://blog.heptio.com/on-securing-the-kubernetes-dashboard-16b09b1b7aca>

Create AKS cluster

```bash
az group create -n rg002 -l westeurope
az aks create -n aks002 -g rg002 --node-count 1 -k 1.19.0
az aks get-credentials -n aks002 -g rg002 --admin
az aks install-cli --client-version 1.19.0
copy .azure-kubectl\kubectl.exe c:\SHORTCUTS
kubectl version
```

name: clusterAdmin_rg002_aks002
organization: system:masters

decode cert `openssl x509 -in cert.crt -text -noout`

Run `kubectl proxy`

Go to <http://localhost:8001/api/v1/namespaces/kube-system/services/https:kubernetes-dashboard:/proxy/#/login>

Clean up

```bash
az group delete -g rg002 --no-wait -y
```

To secure the dashboard

DO NOT SET THE SERVICE TO TYPE LOAD BALANCER

```bash
kube-system   kubernetes-dashboard        ClusterIP   10.0.145.168   <none>        443/TCP         21m
```

ALTERNATIVE WAY TO ACCESS DASHBOARD

`kubectl port-forward service/kubernetes-dashboard -n kube-system 8443:443`

<https://localhost:8443>

```bash
kubectl get serviceAccounts <service-account-name> -n <namespace> -o=jsonpath={.secrets[*].name}
kubectl get secret <service-account-secret-name> -n <namespace> -o json

kubectl get serviceAccounts kubernetes-dashboard -n kube-system -o=jsonpath={.secrets[*].name}
kubectl get secret kubernetes-dashboard-token-nxd89 -n kube-system -o json
```

IMPLEMENT RBAC

LIMIT ACCESS FROM THE kubernetes-dashboard SERVICE ACCOUNT

`kubectl get clusterrolebinding kubernetes-dashboard -o yaml`

```yaml
rules:
- apiGroups:
  - metrics.k8s.io
  resources:
  - pods
  - nodes
  verbs:
  - get
  - list
  - watch
```

</details>

<details><summary>Verify platform binaries before deploying</summary>

```bash
echo -n "bla" | sha256sum
cat <binary> | sha256sum
cat <binary> | sha512sum
```

<https://github.com/kubernetes/kubernetes/releases>

<https://kubernetes.io/docs/setup/release/notes/#client-binaries>

<https://kubernetes.io/docs/tasks/tools/install-kubectl/>

```bash
curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl"
curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.19.0/bin/linux/amd64/kubectl
```

</details>

## Cluster Hardening – 15%

<details><summary>Restrict access to Kubernetes API</summary>

```bash
kubectl create clusterrole
kubectl create role
kubectl create clusterrolebinding
kubectl create rolebinding
```

```bash
kubectl create serviceaccount podreader
kubectl create role pod-reader --verb=get --verb=list --verb=watch --resource=pods
kubectl create rolebinding podr-view --role=pod-reader --serviceaccount=default:podreader 
```

(clusterrole is *not* namespace bound)

Users: create and sign a cert - username = common name ( group = organization )

ServiceAccount: create service account, authenticate with bearer token

```bash
kubectl get serviceAccounts <service-account-name> -n <namespace> -o=jsonpath={.secrets[*].name}
kubectl get secret <service-account-secret-name> -n <namespace> -o json
```

```bash
openssl genrsa -out ted.key 2048
openssl req -new -key ted.key -subj "/CN=ted" -out ted.csr

cat <<EOF | kubectl apply -f -
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: ted
spec:
  request: $(cat ted.csr | base64 | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - client auth
EOF

kubectl describe csr ted

kubectl get csr

kubectl certificate approve ted

kubectl get csr ted -o jsonpath='{.status.certificate}' | base64 --decode > ted.crt

mv ~/.kube/config ~/.kube/config.org

kubectl get pods --certificate-authority=/etc/kubernetes/pki/ca.crt --client-key=ted.key --client-certificate=ted.crt --server=https://10.0.0.4:6443

kubectl get pods --certificate-authority=/etc/kubernetes/pki/ca.crt --client-key=ted.key --client-certificate=ted.crt https://aks002-rg002-5053b0-483fa38b.hcp.westeurope.azmk8s.io:443

kubectl create role pod-reader --verb=get --verb=list --verb=watch --resource=pods --kubeconfig=/root/.kube/config.org
kubectl create rolebinding podr-view --role=pod-reader --user=ted  --kubeconfig=/root/.kube/config.org

kubectl get pods --certificate-authority=/etc/kubernetes/pki/ca.crt --client-key=ted.key --client-certificate=ted.crt --server=https://10.0.0.4:6443

mv ~/.kube/config.org ~/.kube/config
```

<https://kubernetes.io/docs/tasks/administer-cluster/securing-a-cluster/>

<https://kubernetes.io/docs/reference/access-authn-authz/controlling-access/>

<https://cloud.google.com/anthos/gke/docs/on-prem/how-to/hardening-your-cluster>

</details>

<details><summary>Use Role Based Access Controls to minimize exposure </summary>

See previous section

<https://kubernetes.io/docs/reference/access-authn-authz/rbac/>

<https://kubernetes.io/docs/reference/access-authn-authz/authorization/#authorization-modules>

<https://www.youtube.com/watch?v=G3R24JSlGjY>

<https://rbac.dev/>

</details>

<details><summary>Exercise caution in using service accounts e.g. disable defaults, minimize permissions on newly created ones</summary>

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

<https://kubernetes.io/docs/reference/access-authn-authz/service-accounts-admin/>

<https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/>

<https://docs.armory.io/docs/armory-admin/manual-service-account/>

<https://stackoverflow.com/questions/52583497/how-to-disable-the-use-of-a-default-service-account-by-a-statefulset-deployments>

<https://thenewstack.io/kubernetes-access-control-exploring-service-accounts/>

<https://github.com/kubernetes/kubernetes/issues/57601>

<https://www.cyberark.com/resources/threat-research-blog/securing-kubernetes-clusters-by-eliminating-risky-permissions>

</details>

<details><summary>Update Kubernetes frequently</summary>

<https://kubernetes.io/docs/tasks/administer-cluster/kubeadm/kubeadm-upgrade/>

Two nodes, VM0 & VM1
Version 1.19.0

On VM0

```bash
apt-mark unhold kubeadm
apt-mark unhold kubelet
apt-get update
apt-get install -y kubeadm=1.19.2-00
apt-mark hold kubeadm
kubeadm version
kubectl drain vm0 --ignore-daemonsets --force
kubeadm upgrade plan
kubeadm upgrade apply v1.19.2
apt-get install -y kubelet=1.19.2-00
kubectl uncordon vm0
```

On VM1

```bash
apt-mark unhold kubeadm
apt-get update
apt-get install -y kubeadm=1.19.2-00
apt-mark hold kubeadm
kubeadm version
kubectl drain vm1 --ignore-daemonsets --force
kubeadm upgrade node
apt-get install -y kubelet=1.19.2-00
kubectl uncordon vm1
```

`kubectl get componentstatuses`

```bash
root@vm0:~# kubectl get pods -o wide
NAME    READY   STATUS    RESTARTS   AGE   IP          NODE   NOMINATED NODE   READINESS GATES
nginx   1/1     Running   0          59s   10.44.0.1   vm1    <none>           <none>
root@vm0:~# kubectl get pods -o wide -A
NAMESPACE     NAME                          READY   STATUS    RESTARTS   AGE   IP          NODE   NOMINATED NODE   READINESS GATES
default       nginx                         1/1     Running   0          61s   10.44.0.1   vm1    <none>           <none>
kube-system   coredns-f9fd979d6-pj6bt       1/1     Running   1          10m   10.32.0.3   vm0    <none>           <none>
kube-system   coredns-f9fd979d6-qnb62       1/1     Running   1          10m   10.32.0.2   vm0    <none>           <none>
kube-system   etcd-vm0                      1/1     Running   1          13m   10.0.0.4    vm0    <none>           <none>
kube-system   kube-apiserver-vm0            1/1     Running   1          11m   10.0.0.4    vm0    <none>           <none>
kube-system   kube-controller-manager-vm0   1/1     Running   2          11m   10.0.0.4    vm0    <none>           <none>
kube-system   kube-proxy-6x6vx              1/1     Running   1          10m   10.0.0.4    vm0    <none>           <none>
kube-system   kube-proxy-zdwpj              1/1     Running   0          10m   10.0.0.5    vm1    <none>           <none>
kube-system   kube-scheduler-vm0            1/1     Running   2          11m   10.0.0.4    vm0    <none>           <none>
kube-system   weave-net-dshq4               2/2     Running   0          34h   10.0.0.5    vm1    <none>           <none>
kube-system   weave-net-wqrqs               2/2     Running   3          34h   10.0.0.4    vm0    <none>           <none>
root@vm0:~# kubectl get nodes -o wide
NAME   STATUS   ROLES    AGE   VERSION   INTERNAL-IP   EXTERNAL-IP   OS-IMAGE             KERNEL-VERSION     CONTAINER-RUNTIME
vm0    Ready    master   34h   v1.19.2   10.0.0.4      <none>        Ubuntu 18.04.5 LTS   5.4.0-1026-azure   docker://19.3.6
vm1    Ready    <none>   34h   v1.19.2   10.0.0.5      <none>        Ubuntu 18.04.5 LTS   5.4.0-1026-azure   docker://19.3.6
root@vm0:~# kubectl version
Client Version: version.Info{Major:"1", Minor:"19", GitVersion:"v1.19.0", GitCommit:"e19964183377d0ec2052d1f1fa930c4d7575bd50", GitTreeState:"clean", BuildDate:"2020-08-26T14:30:33Z", GoVersion:"go1.15", Compiler:"gc", Platform:"linux/amd64"}
Server Version: version.Info{Major:"1", Minor:"19", GitVersion:"v1.19.2", GitCommit:"f5743093fd1c663cb0cbc89748f730662345d44d", GitTreeState:"clean", BuildDate:"2020-09-16T13:32:58Z", GoVersion:"go1.15", Compiler:"gc", Platform:"linux/amd64"}
```

<https://kubernetes.io/docs/setup/release/notes/#client-binaries>

</details>

## System Hardening – 15%

<details><summary>Minimize host OS footprint (reduce attack surface) (*)</summary>

<https://blog.sonatype.com/kubesecops-kubernetes-security-practices-you-should-follow#:~:text=Reduce%20Kubernetes%20Attack%20Surfaces>

<https://www.cisecurity.org/benchmark/distribution_independent_linux/>

<https://www.cisecurity.org/benchmark/red_hat_linux/>

<https://www.cisecurity.org/benchmark/debian_linux/>

<https://www.cisecurity.org/benchmark/centos_linux/>

<https://www.cisecurity.org/benchmark/suse_linux/>

<https://www.cisecurity.org/benchmark/oracle_linux/>

</details>

<details><summary>Minimize IAM roles (*)</summary>

<https://digitalguardian.com/blog/what-principle-least-privilege-polp-best-practice-information-security-and-compliance>

<https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege>

</details>

<details><summary>Minimize external access to the network</summary>

- set loadbalancer to ClusterIP
- implement network policies

<https://help.replicated.com/community/t/managing-firewalls-with-ufw-on-kubernetes/230>

<https://www.linode.com/docs/security/firewalls/configure-firewall-with-ufw/>

<https://docs.microsoft.com/en-us/azure/aks/concepts-security#azure-network-security-groups>

<https://docs.aws.amazon.com/eks/latest/userguide/sec-group-reqs.html>

<https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-security-groups.html>

</details>

<details><summary>Appropriately use kernel hardening tools such as AppArmor, seccomp</summary>

<https://www.sumologic.com/kubernetes/security/#security-best-practices>

<https://cdn2.hubspot.net/hubfs/1665891/Assets/Container%20Security%20by%20Liz%20Rice%20-%20OReilly%20Apr%202020.pdf>

<https://kubernetes.io/docs/tutorials/clusters/apparmor/>

<https://kubernetes.io/docs/tutorials/clusters/seccomp/>


Seccomp example pod with audit.json

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

</details>

## Minimize Microservice Vulnerabilities – 20%

<details><summary>Setup appropriate OS level security domains e.g. using PSP, OPA, security contexts</summary>

### POD SECURITY POLICY

Ensure PodSecurityPolicy admission controller is active! ( setting on API server)

Edit `etc/kubernetes/manifests/kubeapiserver.yaml` on the master node and set the `--enable-admission-plugins parameter`

```bash
--enable-admission-plugins=...,PodSecurityPolicy,...
```

For kubeadm, create a config file with

```yaml
...
apiVersion: kubeadm.k8s.io/v1beta1
kind: ClusterConfiguration
apiServer:
  extraArgs:
    enable-admission-plugins:  PodSecurityPolicy,LimitRanger,ResourceQuota,AlwaysPullImages,DefaultStorageClass
```

and init cluster with that file to enabel PodSecurityPolicy

`kubeadm init --config kubeadm.json`

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

<http://blog.tundeoladipupo.com/2019/06/01/Kubernetes,-PodSecurityPolicy-and-Kubeadm/>

<https://kubernetes.io/docs/concepts/policy/pod-security-policy/>

### OPEN POLICY AGENT

<https://www.youtube.com/watch?v=Yup1FUc2Qn0>

<https://kubernetes.io/blog/2019/08/06/opa-gatekeeper-policy-and-governance-for-kubernetes/>

<https://www.openpolicyagent.org/docs/v0.12.2/kubernetes-admission-control/>


Example:

```yaml
apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequiredlabels
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredLabels
        listKind: K8sRequiredLabelsList
        plural: k8srequiredlabels
        singular: k8srequiredlabels
      validation:
        # Schema for the `parameters` field
        openAPIV3Schema:
          properties:
            labels:
              type: array
              items: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package k8srequiredlabels

        deny[{"msg": msg, "details": {"missing_labels": missing}}] {
          provided := {label | input.review.object.metadata.labels[label]}
          required := {label | label := input.parameters.labels[_]}
          missing := required - provided
          count(missing) > 0
          msg := sprintf("you must provide labels: %v", [missing])
        }
```

```yaml
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: K8sRequiredLabels
metadata:
  name: ns-must-have-hr
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Namespace"]
  parameters:
    labels: ["hr"]
```

### SECURITY CONTEXT

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

</details>

<details><summary>Manage Kubernetes secrets</summary>

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

<https://www.weave.works/blog/managing-secrets-in-kubernetes>

<https://github.com/kubernetes-sigs/secrets-store-csi-driver>

</details>

<details><summary>Use container runtime sandboxes in multi-tenant environments (e.g. gvisor, kata containers) (*)</summary>

<https://gvisor.dev/docs/>

<https://gvisor.dev/docs/user_guide/quick_start/kubernetes/>

<https://thenewstack.io/how-to-implement-secure-containers-using-googles-gvisor/>

<https://platform9.com/blog/kata-containers-docker-and-kubernetes-how-they-all-fit-together/>

<https://github.com/kata-containers/documentation/blob/master/how-to/how-to-use-k8s-with-cri-containerd-and-kata.md>

</details>

<details><summary>Implement pod to pod encryption by use of mTLS (*)</summary>

Not pod-to-pod, but general background on mutual TLS:

<https://medium.com/@awkwardferny/configuring-certificate-based-mutual-authentication-with-kubernetes-ingress-nginx-20e7e38fdfca>

```bash
openssl req -x509 -sha256 -newkey rsa:4096 -keyout ca.key -out ca.crt -days 356 -nodes -subj '/CN=Fern Cert Authority'
openssl req -new -newkey rsa:4096 -keyout server.key -out server.csr -nodes -subj '/CN=meow.com'
openssl x509 -req -sha256 -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt
openssl req -new -newkey rsa:4096 -keyout client.key -out client.csr -nodes -subj '/CN=Fern'
openssl x509 -req -sha256 -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 02 -out client.crt

kubectl create secret generic my-certs --from-file=tls.crt=server.crt --from-file=tls.key=server.key --from-file=ca.crt=ca.crt

...meow.com >> /etc/hosts
```

ingress example

```yaml
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  annotations:
    nginx.ingress.kubernetes.io/auth-tls-verify-client: \"on\"
    nginx.ingress.kubernetes.io/auth-tls-secret: \"default/my-certs\"
  name: meow-ingress
  namespace: default
spec:
  rules:
  - host: meow.com
    http:
      paths:
      - backend:
          serviceName: meow-svc
          servicePort: 80
        path: /
  tls:
  - hosts:
    - meow.com
    secretName: my-certs
```

```bash
curl https://meow.com/ -k
curl https://meow.com/ --cert client.crt --key client.key -k
```

<https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/>

<https://developer.ibm.com/technologies/containers/tutorials/istio-security-mtls/>

<https://codeburst.io/mutual-tls-authentication-mtls-de-mystified-11fa2a52e9cf>

<https://www.istioworkshop.io/11-security/01-mtls/>

<https://istio.io/latest/blog/2017/0.1-auth/>

<https://linkerd.io/2/features/automatic-mtls/>

</details>

## Supply Chain Security – 20%

<details><summary>Minimize base image footprint</summary>

<https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/>

```bash
    gcr.io/distroless/static-debian10
    gcr.io/distroless/base-debian10
    gcr.io/distroless/java-debian10
    gcr.io/distroless/cc-debian10
```

<https://cloud.google.com/blog/products/gcp/kubernetes-best-practices-how-and-why-to-build-small-container-images>

<https://cloud.google.com/solutions/best-practices-for-building-containers#build-the-smallest-image-possible>

<https://cloud.google.com/blog/products/gcp/7-best-practices-for-building-containers>

<https://github.com/GoogleContainerTools/distroless>

</details>

<details><summary>Secure your supply chain: whitelist allowed registries, sign and validate images (*)</summary>

<https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#imagepolicywebhook>

<https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/>

<https://kubernetes.io/blog/2019/03/21/a-guide-to-kubernetes-admission-controllers/>

<https://docs.docker.com/engine/security/trust/content_trust/>

<https://stackoverflow.com/questions/54463125/how-to-reject-docker-registries-in-kubernetes>

<https://github.com/kubernetes/kubernetes/issues/22888>

<https://www.openpolicyagent.org/docs/latest/kubernetes-primer/>

<https://medium.com/sse-blog/container-image-signatures-in-kubernetes-19264ac5d8ce>

</details>

<details><summary>Use static analysis of user workloads (e.g.Kubernetes resources, Docker files) (*)</summary>

<https://kube-score.com/>

```bash
kubectl api-resources --verbs=list --namespaced -o name \
  | xargs -n1 -I{} bash -c "kubectl get {} --all-namespaces -oyaml && echo ---" \
  | kube-score score -
```


<https://bridgecrew.io/blog/kubernetes-static-code-analysis-with-checkov/>


```bash
clairctl report --host http://myhost IMAGEN_NAME
cves=$(cat report | grep " found " | wc -l)
if [$cves -gt 0]
then
  cat report
  exit 1
fi
```

```bash
brew install kube-score/tap/kube-score
cd /home/azureuser/.linuxbrew/Cellar/kube-score/1.9.0
cd bin
kubectl run nginx --image=nginx
kubectl get pod nginx -o yaml|./kube-score score -
```

</details>

<details><summary>Scan images for known vulnerabilities </summary>

<https://github.com/quay/clair>

clair used postgress db
clair uses config.yaml, create as secret, mount as file

```bash
git clone --single-branch --branch release-2.0 https://github.com/coreos/clair
cd contrib
cd k8s
kubectl create secret generic clairsecret --from-file=./config.yaml
kubectl create -f clair-kubernetes.yaml
curl -X GET -I http://10.96.228.33:6061/health
wget https://github.com/optiopay/klar/releases/download/v2.4.0/klar-2.4.0-linux-amd64
mv klar-2.4.0-linux-amd64 klar
chmod +x klar

CLAIR_ADDR=10.96.228.33:6060 \
CLAIR_OUTPUT=High \
CLAIR_THRESHOLD=10 \
klar tvdvoorde/api1
```

config.yml

```yaml
clair:
 port: 6060
 healthPort: 6061
 request:
 host: HOST
 headers:
 myHeader: header
 uri: http://10.96.228.33
 report:
 path: ./reports
 format: html
```

```bash
./clairctl --config=config.yml report tvdvoorde/api1:latest
```

<https://medium.com/better-programming/scan-your-docker-images-for-vulnerabilities-81d37ae32cb3>

<https://github.com/leahnp/clair-klar-kubernetes-demo>

</details>

## Monitoring, Logging and Runtime Security – 20%

<details><summary>Perform behavioral analytics of syscall process and file activities at the host and container level to detect malicious activities (*)</summary>

<https://sysdig.com/blog/how-to-detect-kubernetes-vulnerability-cve-2019-11246-using-falco/>

<https://medium.com/@SkyscannerEng/kubernetes-security-monitoring-at-scale-with-sysdig-falco-a60cfdb0f67a>

<https://kubernetes.io/docs/tutorials/clusters/seccomp/>

</details>

<details><summary>Detect threats within physical infrastructure, apps, networks, data, users and workloads (*)</summary>

<https://www.cncf.io/blog/2020/08/07/common-kubernetes-config-security-threats/>

<https://www.trendmicro.com/vinfo/us/security/news/virtualization-and-cloud/guidance-on-kubernetes-threat-modeling>

<https://www.microsoft.com/security/blog/2020/04/02/attack-matrix-kubernetes/>

</details>

<details><summary>Detect all phases of attack regardless where it occurs and how it spreads (*)</summary

<https://www.threatstack.com/blog/kubernetes-attack-scenarios-part-1>

<https://www.optiv.com/explore-optiv-insights/source-zero/anatomy-kubernetes-attack-how-untrusted-docker-images-fail-us>

></details>

<details><summary>Perform deep analytical investigation and identification of bad actors within environment (*)</summary>

<https://www.stackrox.com/post/2020/05/kubernetes-security-101/>

</details>

<details><summary>Ensure immutability of containers at runtime</summary>

Create a pod with a readonlyrootfilesystem and writeable /tmp dir

```yaml
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

<https://kubernetes.io/blog/2018/03/principles-of-container-app-design/>

<https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux_atomic_host/7/html/container_security_guide/keeping_containers_fresh_and_updateable#leveraging_kubernetes_and_openshift_to_ensure_that_containers_are_immutable>

<https://medium.com/sroze/why-i-think-we-should-all-use-immutable-docker-images-9f4fdcb5212f>

<https://techbeacon.com/enterprise-it/immutable-infrastructure-your-systems-can-rise-dead>

</details>

<details><summary>Use Audit Logs to monitor access</summary>

Set `--audit-policy-file` on api server

```bash
--audit-policy-file string
Path to the file that defines the audit policy configuration.
```

Example of audit-policy-file: <https://kubernetes.io/docs/tasks/debug-application-cluster/audit/>

<https://kubernetes.io/docs/tasks/debug-application-cluster/audit/>

<https://www.datadoghq.com/blog/monitor-kubernetes-audit-logs/>

<https://docs.sysdig.com/en/kubernetes-audit-logging.html>

</details>

## Preparations

Build a v1.19 'kubeadm' cluster on Ubuntu 18 with a dedicated master and worker node

## Command snippers and reference

kubectl is based on v1.19

Use `kubectl run -o yaml --dry-run` to create a pod.yaml

`kubectl run` has many commandline arguments for specific pod/container configurations

Use `kubectl create deployment -o yaml --dry-run` to create a deployment.yaml

Merge them together in an editor - be carefull of indentation

```bash
kubectl explain  <type>.<fieldName>[.<fieldName>]
kubectl explain pod.spec.containers  *CASE SENSITIVE*
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
<<HERE (here doc) - provides stdin till repeat of HERE keyword
cat<<EOF>1.yaml
---
EOF

cat<<EOF|kubectl apply -f -
---
EOF

kubectl apply -f -<<EOF
---
EOF


cat>1.yaml<<EOF
---
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

### VIM settings

overwrite vimrc to defaults

```bash
echo #>~/.vimrc
```

### Linux security

`sudo -i` interactive sudo prompt
`sudo cmd` execute command with sudo priv

```bash
chmod +x <file>
chmod <owner><group><other> <file>
chown <owner>[:<group>] <file>

cat <<EOF > /root/.ssh/id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAnMWXE21Y+5
...
EOF

chmod 600 /root/.ssh/id_rsa


groupadd <NEW_GROUP>
usermod -a -G <GROUP> <USER>
usermod -g <GROUP> <USER>
passwd <PASSWORD>
groups
id

```

users: `/etc/passwd/` ( `<username>:<password>:<UID>:<GID>` )

accessing cluster

```bash
kubectl config view -o jsonpath='{"Cluster name\tServer\n"}{range .clusters[*]}{.name}{"\t"}{.cluster.server}{"\n"}{end}'
export CLUSTER_NAME="aks002"
APISERVER=$(kubectl config view -o jsonpath="{.clusters[?(@.name==\"$CLUSTER_NAME\")].cluster.server}")
TOKEN=$(kubectl get secrets -o jsonpath="{.items[?(@.metadata.annotations['kubernetes\.io/service-account\.name']=='default')].data.token}"|base64 --decode)

curl -X GET $APISERVER/api --header "Authorization: Bearer $TOKEN" --insecure

kubectl run nginx --image=nginx --restart=Never

kubectl exec nginx -it /bin/sh

# TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
# curl -X GET "https://kubernetes/api" --header "Authorization: Bearer $TOKEN" --insecure



```

## Security related KTHW settings

### ETCD

```bash
ExecStart=/usr/local/bin/etcd \\
  --name ${ETCD_NAME} \\
  --cert-file=/etc/etcd/kubernetes.pem \\
  --key-file=/etc/etcd/kubernetes-key.pem \\
  --peer-cert-file=/etc/etcd/kubernetes.pem \\
  --peer-key-file=/etc/etcd/kubernetes-key.pem \\
  --trusted-ca-file=/etc/etcd/ca.pem \\
  --peer-trusted-ca-file=/etc/etcd/ca.pem \\
  --peer-client-cert-auth \\
  --client-cert-auth \\
  --initial-advertise-peer-urls https://${INTERNAL_IP}:2380 \\
  --listen-peer-urls https://${INTERNAL_IP}:2380 \\
  --listen-client-urls https://${INTERNAL_IP}:2379,https://127.0.0.1:2379 \\
  --advertise-client-urls https://${INTERNAL_IP}:2379 \\
  --initial-cluster-token etcd-cluster-0 \\
  --initial-cluster control0=https://10.240.0.10:2380,control1=https://10.240.0.11:2380,control2=https://10.240.0.12:2380 \\
  --initial-cluster-state new \\
  --data-dir=/var/lib/etcd
```

### KUBE-APISERVER

```bash
  --audit-log-path=/var/log/audit.log \\
  --authorization-mode=Node,RBAC \\
  --enable-admission-plugins=Initializers,NamespaceLifecycle,NodeRestriction,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota   --etcd-cafile=/var/lib/kubernetes/ca.pem \\
  --etcd-certfile=/var/lib/kubernetes/kubernetes.pem \\
  --etcd-keyfile=/var/lib/kubernetes/kubernetes-key.pem \\
  --etcd-servers=https://10.240.0.10:2379,https://10.240.0.11:2379,https://10.240.0.12:2379 \\
  --event-ttl=1h \\
  --experimental-encryption-provider-config=/var/lib/kubernetes/encryption-config.yaml \\
  --kubelet-certificate-authority=/var/lib/kubernetes/ca.pem \\
  --kubelet-client-certificate=/var/lib/kubernetes/kubernetes.pem \\
  --kubelet-client-key=/var/lib/kubernetes/kubernetes-key.pem \\
  --kubelet-https=true \\
  --runtime-config=api/all \\
  --service-account-key-file=/var/lib/kubernetes/service-account.pem \\
  --service-cluster-ip-range=10.32.0.0/24 \\
  --service-node-port-range=30000-32767 \\
  --tls-cert-file=/var/lib/kubernetes/kubernetes.pem \\
  --tls-private-key-file=/var/lib/kubernetes/kubernetes-key.pem \\

```

### KUBE-CONTROLLER-MANAGER

```bash
ExecStart=/usr/local/bin/kube-controller-manager \\
  --address=0.0.0.0 \\
  --cluster-cidr=10.200.0.0/16 \\
  --cluster-name=kubernetes \\
  --cluster-signing-cert-file=/var/lib/kubernetes/ca.pem \\
  --cluster-signing-key-file=/var/lib/kubernetes/ca-key.pem \\
  --kubeconfig=/var/lib/kubernetes/kube-controller-manager.kubeconfig \\
  --leader-elect=true \\
  --root-ca-file=/var/lib/kubernetes/ca.pem \\
  --service-account-private-key-file=/var/lib/kubernetes/service-account-key.pem \\
  --service-cluster-ip-range=10.32.0.0/24 \\
  --use-service-account-credentials=true \\
  --v=2
```

### KUBE-SCHEDULER

```bash
ExecStart=/usr/local/bin/kube-scheduler \\
  --kubeconfig=/var/lib/kubernetes/kube-scheduler.kubeconfig \\
  --address=127.0.0.1 \\
  --leader-elect=true \\
```

### KUBELET

```bash
ExecStart=/usr/local/bin/kubelet \\
  --config=/var/lib/kubelet/kubelet-config.yaml \\
  --image-pull-progress-deadline=2m \\
  --kubeconfig=/var/lib/kubelet/kubeconfig \\
  --network-plugin=cni \\
  --register-node=true \\
  --tls-cert-file=/var/lib/kubelet/${HOSTNAME}.pem \\
  --tls-private-key-file=/var/lib/kubelet/${HOSTNAME}-key.pem \\
  --v=2
```

### KUBEPROXY

```bash
ExecStart=/usr/local/bin/kube-proxy \\
  --config=/var/lib/kube-proxy/kube-proxy-config.yaml
Restart=on-failure
RestartSec=5
```

## Other usefull sites

<https://github.com/David-VTUK/CKA-StudyGuide/blob/master/RevisionTopics/Part-5-Security.md>

<https://blog.heptio.com/on-securing-the-kubernetes-dashboard-16b09b1b7aca>

<https://cloud.google.com/blog/products/gcp/7-best-practices-for-building-containers>

## Other CKS preparation sites

<https://blog.nativecloud.dev/how-to-prepare-for-the-upcoming-cks-certification/>

<https://github.com/walidshaari/Certified-Kubernetes-Security-Specialist>

<https://github.com/ijelliti/CKSS-Certified-Kubernetes-Security-Specialist>

<https://acloud.guru/learn/7d2c29e7-cdb2-4f44-8744-06332f47040e>

<https://github.com/cloudnative-id/certified-kubernetes-security>

<https://ravikirans.com/cks-kubernetes-security-exam-study-guide/>

<https://deploy.live/blog/cks-certified-kubernetes-security-specialist-exam-preparation-guide/>

<https://github.com/vedmichv/CKS-Certified-Kubernetes-Security-Specialist>

<https://awesomeopensource.com/project/walidshaari/Certified-Kubernetes-Security-Specialist>

## Exam details

URLs allowed in browser (only one tab)

<https://kubernetes.io/docs/>

<https://github.com/kubernetes/>

<https://kubernetes.io/blog/>

- Root privileges can be obtained by running 'sudo −i'.
- Rebooting of your server IS permitted at any time.
- Do not stop or tamper with the certerminal process as this will END YOUR EXAM SESSION.
- Do not block incoming ports 8080/tcp, 4505/tcp and 4506/tcp. This includes firewall rules that are found within the distribution's default firewall configuration files as well as interactive firewall commands.
- Use Ctrl+Alt+W instead of Ctrl+W.
- Ctrl+W is a keyboard shortcut that will close the current tab in Google Chrome.
- Ctrl+C & and Ctrl+V are not supported in your exam terminal.
- To copy and paste text, please use;
  - For Linux: select text for copy and middle button for paste (or both left and right simultaneously if you have no middle button).
  - For Mac: ⌘+C to copy and ⌘+V to paste.
  - For Windows: Ctrl+Insert to copy and Shift+Insert to paste.
- In addition, you might find it helpful to use the Notepad (see top menu under 'Exam Controls') to manipulate text before pasting to the command line.
- Installation of services and applications included in this exam may require modification of system security policies to successfully complete.
- Only a single terminal console is available during the exam. Terminal multiplexers such as GNU Screen and tmux can be used to create virtual consoles
