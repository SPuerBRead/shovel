## Shovel

Docker容器逃逸工具

原理上就是逃逸的那一堆shell脚本，换成系统调用，绕过bash的监控

## 功能

* 支持的逃逸方式
  * release_agent
  * device_allow
  * cve-2022-0492


* 支持的存储驱动
  * device_mapper
  * aufs
  * btrfs
  * vfs
  * zfs
  * overlayfs


* 支持的利用类型
  * exec: 在宿主机执行命令
  * shell: 获取宿主机shell
  * reverse: 反弹shell
  * backdoor: 向宿主机植入后门并运行


* 自动清理攻击痕迹

## 使用方式

```text
usage: shovel [options ...]

Options:
Options of program
    -h, --help                           show help message
    -v, --version                        show program version
Options of escape
    -r, --release-agent                  escape by release-agent
    -d, --devices-allow                  escape by devices-allow
    -u, --cve-2022-0492                  get cap_sys_admin by cve-2022-0492 and return new namespace bash
Options of other
    -p, --container_path=xxx             manually specify path of container in host,use this parameter if program can't get it automatically
    -m, --mode=xxx                       the mode that needs to be returned after a successful escape { exec | shell | reverse | backdoor }
    -c, --command=xxx                    set command in exec mode
    -I, --ip                             set ip address in reverse mode
    -P, --port                           set port in reverse mode
    -B, --backdoor_path                  set backdoor file path

Mode (-m) type guide
    exec:     run a single command and return the result
    shell:    get host shell in current console
    reverse:  reverse shell to remote listening address
    backdoor: put a backdoor to the host and execute
```
## 编译

编译时尽量用低版本glibc，高版本glibc编译到老系统上没办法运行

```shell
cmake .
make
```