# Cri-o research


> This research was carried out as part of an internship [Summ3r of Hack](https://dsec.ru/about/summerofhack/) in [Dsec](https://dsec.ru).

Crio is meant to provide an integration path between OCI conformant runtimes and the kubelet. Specifically, it implements the Kubelet Container Runtime Interface (CRI) using OCI conformant runtimes. The scope of crio is tied to the scope of the CRI.
 - Support multiple image formats including the existing Docker and OCI image formats.
 - Support for multiple means to download images including trust & image verification.
 - Container image management (managing image layers, overlay filesystems, etc).
 - Container process lifecycle management.
 - Monitoring and logging required to satisfy the CRI.
 - Resource isolation as required by the CRI.

# CRI-O ⬄ Kubernetes
| Version - Branch | Kubernetes branch/version | Maintenance status |
| ------ | ------ | ------ |
| CRI-O 1.16.x - release-1.16|Kubernetes 1.16 branch, v1.16.x | = |
| CRI-O 1.17.x - release-1.17 |	Kubernetes 1.17 branch, v1.17.x |	=|
| CRI-O 1.18.x - release-1.18 | 	Kubernetes 1.18 branch, v1.18.x | 	=| 
| CRI-O HEAD - master | 	Kubernetes master branch | 	✓| 
 # How it's work??
![Image](https://blog.ordix.de/images/easyblog_articles/280/b2ap3_large_CRI-_20180614-081358_1.png)
# /etc/crio/crio.conf
> Only important settings from a security point of view
```
# If true, SELinux will be used for pod separation on the host.
selinux = false

# Path to the seccomp.json profile which is used as the default seccomp profile
# for the runtime. If not specified, then the internal default seccomp profile
# will be used.
seccomp_profile = ""

# Used to change the name of the default AppArmor profile of CRI-O. The default
# profile name is "crio-default-" followed by the version string of CRI-O.
apparmor_profile = "crio-default"

# Cgroup management implementation used for the runtime.
cgroup_manager = "cgroupfs“
# Maximum number of processes allowed in a container.
pids_limit = 1024
# List of default capabilities for containers. If it is empty or commented out,
# only the capabilities defined in the containers json file by the user/kube
# will be added.
default_capabilities = [
        "CHOWN",
        "DAC_OVERRIDE",
        "FSETID",
        "FOWNER",
        "NET_RAW",
        "SETGID",
        "SETUID",
        "SETPCAP",
        "NET_BIND_SERVICE",
        "SYS_CHROOT",
        "KILL",
]
# List of default sysctls. If it is empty or commented out, only the sysctls
# defined in the container json file by the user/kube will be added.
default_sysctls = [
]
# The UID mappings for the user namespace of each container. A range is
# specified in the form containerUID:HostUID:Size. Multiple ranges must be
# separated by comma.
uid_mappings = ""

# The GID mappings for the user namespace of each container. A range is
# specified in the form containerGID:HostGID:Size. Multiple ranges must be
# separated by comma.
gid_mappings = ""

# The minimal amount of time in seconds to wait before issuing a timeout
# regarding the proper termination of the container.
ctr_stop_timeout = 0

# ManageNetworkNSLifecycle determines whether we pin and remove network namespace
# and manage its lifecycle.
manage_network_ns_lifecycle = false

# The "crio.runtime.runtimes" table defines a list of OCI compatible runtimes.
# The runtime to use is picked based on the runtime_handler provided by the CRI.
# If no runtime_handler is provided, the runtime will be picked based on the level
# of trust of the workload.

```

# File of configuration
- [crio.conf](https://github.com/cri-o/cri-o/blob/master/docs/crio.conf.5.md) (/etc/crio/crio.conf) cri-o configuration file for all of the available command-line options for the crio(8) program, but in a TOML format that can be more easily modified and versioned.
- [policy.json](https://github.com/containers/image/blob/master/docs/containers-policy.json.5.md) (/etc/containers/policy.json) Signature verification policy files are used to specify policy, e.g. trusted keys, applicable when deciding whether to accept an image, or individual signatures of that image, as valid.
- [registries.conf](https://github.com/containers/image/blob/master/docs/containers-registries.conf.5.md) (/etc/containers/registries.conf) Registry configuration file specifies registries which are consulted when completing image names that do not include a registry or domain portion.
- [storage.conf](https://github.com/containers/storage/blob/master/docs/containers-storage.conf.5.md) (/etc/containers/storage.conf) Storage configuration file specifies all of the available container storage options for tools using shared container storage.
# Components
The plan is to use OCI projects and best of breed libraries for different aspects:
- Runtime: [runc](https://github.com/opencontainers/runc) (or any OCI runtime-spec implementation) and [oci runtime tools](https://github.com/opencontainers/runtime-tools)
- Images: Image management using [containers/image](https://github.com/containers/image)
- Storage: Storage and management of image layers using [containers/storage](https://github.com/containers/storage)
- Networking: Networking support through use of [CNI](https://github.com/containernetworking/cni)
 # Crio.sock tricks 
```sh 
curl --unix-socket /var/run/crio/crio.sock http://localhost/info | jq
```
Response:
```sh 
{
  "storage_driver": "overlay",
  "storage_root": "/var/lib/containers/storage",
  "cgroup_driver": "cgroupfs",
  "default_id_mappings": {
    "uids": [
      {
        "container_id": 0,
        "host_id": 0,
        "size": 4294967295
      }
    ],
    "gids": [
      {
        "container_id": 0,
        "host_id": 0,
        "size": 4294967295
      }
    ]
  }
}
```

# Public CVE
> Because we couldn't find new vulnerabilities, so we focused on public CVEs

* [CVE-2018-1000400](https://www.cvedetails.com/cve/CVE-2018-1000400/)
 Kubernetes CRI-O version prior to 1.9 contains a Privilege Context Switching Error (CWE-270) vulnerability in the handling of ambient capabilities that can result in containers running with elevated privileges, allowing users abilities they should not have. This attack appears to be exploitable via container execution. This vulnerability appears to have been fixed in 1.9. Commit [patch](https://github.com/cri-o/cri-o/pull/1558/files)
* [CVE-2019-14891](https://access.redhat.com/security/cve/cve-2019-14891)
A flaw was found in cri-o(< 1.16.1), as a result of all pod-related processes being placed in the same memory cgroup. This can result in container management (conmon) processes being killed if a workload process triggers an out-of-memory (OOM) condition for the cgroup. An attacker could abuse this flaw to get host network access on an cri-o host. [Capsule8 research]( https://capsule8.com/blog/oomypod-nothin-to-cri-o-bout/)
For patch add in configuration file (/etc/crio/crio.conf)
```
conmon_cgroup: system.slice 
```
 
# Try to reproduce CVE-2019-14891
- Install and run old version of minikube(1.3.1) and run cluster with cri-o(1.15.0)
```sh
$ ./minikube-linux-amd64 start --vm-driver=kvm2  --container-runtime=cri-o --memory=2048
```
- Our implementation of exploitable kubernetes deployment
```sh
apiVersion: apps/v1
kind: Deployment
metadata:
  name: repro-pod1
spec:
  selector:
    matchLabels:
      name: repro-pod1
  template:
    metadata:
      labels:
        name: repro-pod1
    spec:
      containers:
        - name: repro-pod1
          image: docker.io/dres666/crio-pwn:latest
          imagePullPolicy: IfNotPresent
          stdin: true
          tty: true
          resources:
            limits:
              memory: 150Mi
      imagePullSecrets:
      - name: regcred
```
- Start our deployment for reproduce bug
```sh
$ for i in {1..10};do ./kubectl apply -f repro-pod$i.yml;done
```
> But we have a problem with race of oom killed conmon process... And now work to solve this problem.....
# Selinux????
[Udica](https://github.com/containers/udica) tool can generate selinux container policy from json inspect of crio containers.
```sh
$ crictl inspect container_Id > container_name.json
$ udica -j container_name.json  my_container –e CRI-O
$ semodule -i my_container.cil /usr/share/udica/templates/{base_container.cil,net_container.cil,home_container.cil
```

### Links

* [Cri-o](https://github.com/cri-o/cri-o) - Cri-o github repository
* [Udica](https://github.com/containers/udica) - Generate SELinux policies for containers
* [kubernetes-container-engine-compariso](https://joejulian.name/post/kubernetes-container-engine-comparison/) - container runtime for  Kubernetes.
* [Demystifying Containers](https://www.cncf.io/blog/2019/07/15/demystifying-containers-part-ii-container-runtimes/) - Container Runtimes

### Todo

 - Finalize our poc of CVE-2019-14891
 - Write more information about source code of cri-o
