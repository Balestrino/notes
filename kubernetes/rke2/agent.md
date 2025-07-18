curl -sfL https://get.rke2.io | INSTALL_RKE2_TYPE="agent" sh -

systemctl enable rke2-agent.service
mkdir -p /etc/rancher/rke2/
nano /etc/rancher/rke2/config.yaml

```
server: https://192.168.xx.xxx:9345
token:
```

systemctl start rke2-agent.service
