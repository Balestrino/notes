# On master node

`curl -sfL https://get.rke2.io | sh -`

`systemctl enable rke2-server.service`

`nano /etc/rancher/rke2/config.yaml`

```
write-kubeconfig-mode: "0644"
tls-san:
  - "rke2-master-1"
node-label:
  - "something=amazing"
debug: true
disable:
  - rke2-ingress-nginx
```

`systemctl start rke2-server.service`

node token: `cat /var/lib/rancher/rke2/server/node-token`

## install kubectl

`curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"`

`install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl`
