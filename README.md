# kubecerts

> **Archived.** Personal homelab tool, no longer maintained. Use at your own risk.

CLI for generating and managing Kubernetes cluster PKI (CAs, API server, etcd, kubelet, kube-proxy, controller-manager, scheduler, service-account, front-proxy, flannel, and per-user kubectl certs) for a NixOS-flake-defined cluster, with [agenix](https://github.com/ryantm/agenix) for encrypted-at-rest storage.

## What it does

- Discovers hosts (and their roles / advertise IPs / kubectl users) from a NixOS flake.
- Generates the full set of Kubernetes control-plane and node certificates per host.
- Stores everything as agenix-encrypted secrets, ready to be consumed by NixOS modules.

## Usage

```sh
kubecerts certs all       # generate everything
kubecerts certs ca        # CAs only
kubecerts certs apiserver # API server certs (master nodes)
kubecerts certs etcd      # etcd server/peer/healthcheck + flannel-etcd-client
kubecerts certs sa        # service account signing key
kubecerts certs client    # kubelet / kube-proxy / controller-manager / scheduler / flannel
kubecerts certs user      # cluster-admin kubeconfig certs for kubectl users
kubecerts certs debug     # dump discovered hosts and users
kubecerts renew           # renew expiring certs
kubecerts status          # show cert status
```

Build:

```sh
go build -o kubecerts ./cmd/kubecerts
```

Dev shell via `devbox` or `nix develop` (see `devbox.json` / `flake.nix`).

## License

MIT — see [LICENSE](LICENSE).
