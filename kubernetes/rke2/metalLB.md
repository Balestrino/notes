1. `kubectl apply -f https://raw.githubusercontent.com/metallb/metallb/v0.15.2/config/manifests/metallb-native.yaml`

2. Create a metallb-config.yaml file to tell MetalLB which IP addresses it's allowed to use. These should be unused IPs on your local network

```
apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: default-pool
  namespace: metallb-system
spec:
  addresses:
  - 192.168.88.230-192.168.88.240 # Change this to a free range on your network!
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: default
  namespace: metallb-system
spec:
  ipAddressPools:
  - first-pool
```

2a. `kubectl apply -f metallb-config.yaml`
