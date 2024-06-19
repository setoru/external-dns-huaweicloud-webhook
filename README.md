# ExternalDNS-HuaweiCloud-Webhook

ExternalDNS is a Kubernetes add-on for automatically managing
Domain Name System (DNS) records for Kubernetes services by using different DNS providers.
By default, Kubernetes manages DNS records internally,
but ExternalDNS takes this functionality a step further by delegating the management of DNS records to an external DNS
provider such as HuaweiCloud.
Therefore, the HuaweiCloud webhook allows to manage your
HuaweiCloud domains inside your kubernetes cluster with [ExternalDNS](https://github.com/kubernetes-sigs/external-dns).

To use ExternalDNS with HuaweiCloud, you need your HuaweiCloud AccessKey&SecretKey or IdpId&IdTokenFile of the account managing
your domains.

## Deployment

The basic development tasks are provided by make. Run `make help` to see the
available targets.

Build the docker image：
```shell
make docker-build
```

## Kubernetes Deployment

### Step 1: Configure IAM Permissions

#### Using IDP Token

Configure the identity provider, refer to [this link](https://support.huaweicloud.com/bestpractice-cce/cce_bestpractice_0333.html#section3).

> When configuring the identity provider, the identity conversion rules must be correctly set. Taking the deployment in Step 2 as an example, it should be configured as **system:serviceaccount:default:external-dns**.

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: external-dns
data:
  cred.yaml: |
    region: xxxx
    projectId: xxxx
    idpId: xxxx # Identity provider name
```

> `idpId` is the identity provider name, not the client ID.
>
> When using an internal domain name, you can specify the same name domain through `vpcId`.

### Step 2: Deploy External-DNS-Webhook

```yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: external-dns
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: external-dns
  template:
    metadata:
      labels:
        app: external-dns
    spec:
      serviceAccountName: external-dns
      containers:
        - name: external-dns
          image: registry.k8s.io/external-dns/external-dns:v0.14.1
          args:
            - --source=service
            - --source=ingress
            - --provider=webhook
            - --registry=txt
            - --txt-owner-id=my-identifier
            - --txt-prefix=hwc.
        - name: huaweicloud-webhook
          image: swr.xxx.myhuaweicloud.com/xx/external-dns-huaweicloud-webhook:v1.0.0     
          ports:
            - containerPort: 8888
          env:
            - name: CONFIG_FILE
              value: /etc/kubernetes/cred.yaml
            - name: ZONE_TYPE
              value: public
            - name: TOKEN_FILE
              value: /var/run/secrets/token
            - name: ZONE_MATCH_PARENT
              value: "false"
            - name: LOG_LEVEL
              value: info
            - name: LOG_FORMAT
              value: text
            - name: EXPIRATION_SECONDS
              value: '7200'              
          volumeMounts:
          - mountPath: /etc/kubernetes
            name: config-volume
            readOnly: true
          - mountPath: /var/run/secrets
            name: token
            readOnly: true           
      imagePullSecrets:
      - name: default-secret
      volumes:
      - configMap:
          defaultMode: 420
          items:
          - key: cred.yaml
            path: cred.yaml
          name: external-dns
        name: config-volume
      - name: token
        projected: 
          defaultMode: 420
          sources:
          - serviceAccountToken:
              audience: external-dns 
              expirationSeconds: 7200 
              path: token

---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: external-dns
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: external-dns
rules:
  - apiGroups: [""]
    resources: ["services","endpoints","pods"]
    verbs: ["get","watch","list"]
  - apiGroups: ["extensions","networking.k8s.io"]
    resources: ["ingresses"]
    verbs: ["get","watch","list"]
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: external-dns-viewer
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: external-dns
subjects:
  - kind: ServiceAccount
    name: external-dns
    namespace: default 
```

- `ZONE_TYPE`: Configurable for Huawei Cloud public or private domain names, with values `public` and `private`.
- `TXT_PREFIX`: Configure the prefix for TXT records to avoid conflicts with CNAME records.
- `CONFIG_FILE`: Path to the configuration file.
- `TOKEN_FILE`: Path to the ServiceAccountToken.
- `ZONE_MATCH_PARENT`: Configure whether to match parent domain names, with values `true` and `false`.
- `EXPIRATION_SECONDS`: Configure token expiration time
### Step 3: Verify ExternalDNS works (Service example)

First, you need to create a private domain name in Huawei Cloud DNS.

Create a domain named `external-dns.com`.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx
  annotations:
    external-dns.alpha.kubernetes.io/hostname: nginx.external-dns.com
    external-dns.alpha.kubernetes.io/ttl: "600"
    kubernetes.io/elb.id: xxxx
spec:
  type: LoadBalancer
  ports:
  - port: 80
    name: http
    targetPort: 80
  selector:
    app: nginx

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - image: nginx
        name: nginx
        ports:
        - containerPort: 80
          name: http
```

To create a LoadBalancer type Service, you need to bind a load balancer (ELB). Configure the Huawei Cloud ELB using `kubernetes.io/elb.id` to obtain the ELB ID

Huawei Cloud DNS will create an A record and a TXT record for `nginx.external-dns.com`

### Step 4: Verify ExternalDNS works(Ingress example)

```yaml
apiVersion: v1
kind: Service
metadata:
  name: nginx
spec:
  type: NodePort
  ports:
  - port: 80
    targetPort: 80
    nodePort: 30120
  selector:
    app: nginx

---
apiVersion: apps/v1
kind: Deployment
metadata:
  labels:
    app: nginx
  name: nginx
spec:
  replicas: 1
  selector:
    matchLabels:
      app: nginx
  template:
    metadata:
      labels:
        app: nginx
    spec:
      containers:
      - image: nginx
        name: nginx
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: nginx
  annotations:
    kubernetes.io/elb.port: '80'
    kubernetes.io/elb.id: xxx
    kubernetes.io/elb.class: union
spec:
  rules:
    - host: nginx.external-dns.com
      http:
        paths:
          - path: /
            backend:
              service:
                name: nginx
                port:
                  number: 80
            pathType: ImplementationSpecific
  ingressClassName: cce
```

> the HuaweiCloud webhook does not currently support `alias` annotations.

