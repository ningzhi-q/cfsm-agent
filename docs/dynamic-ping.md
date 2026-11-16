# 动态 Ping（v1.2.0）

支持 schema 8 的 probe_catalog 与 probe_selection，使用稳定目标 ID。IPv4/IPv6/通用组依据网络可达性选择；manual 空数组不执行动态探测。目录默认关闭，仍可连接旧后端并维持原八路。

四路 worker 独立执行探测，整轮不重叠，结果完成即发布。DNS 根据分组地址族选择并缓存；目录、选择、网络能力变化后重新选目标，删除目标及配置切换清除旧快照，120 秒过期结果不上报。资源监控采样不等待动态探测。

POST 回复及 WSS 配置均可下发约 64 KiB 的 URL 编码目录；配置持久化保留转义，补报按时钟校准复制样本。probes 的 ts 为毫秒，latency/loss 保留数字、null、false。动态启用时旧八路为关闭，旧 Agent 继续接收旧 schema 配置。

安装与自动更新地址切至 ningzhi-q/cfsm-agent 的正式 release。发布包含全部原有系统及 CPU 架构，校验和随 release 一起提供。

验证：go test ./...、go test -race ./internal/cfprobe、go vet ./...。用超过八路、地址族匹配、配置持久化、WSS 对象、补报校时、空快照与过期样本覆盖协议。
