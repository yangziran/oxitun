/// 核心配置模块，定义了客户端的所有配置结构体及默认值
pub mod config;

/// SSH 连接池模块，负责高可用会话管理与调度
pub mod pool;

/// 隧道管理器模块，统筹不同类型隧道的生命周期
pub mod tunnel;

/// SOCKS5 协议处理模块，负责握手与目标地址解析
pub mod socks5;

/// 智能路由模块，依据黑白名单和区域规则对流量进行分流
pub mod router;

/// 加解密模块，提供配置中敏感信息的安全存储
pub mod crypto;

/// 系统代理管理模块，支持多平台代理与 DNS 劫持设置
pub mod sysproxy;

/// 双向异步拷贝模块，提供高性能的底层流转发能力
pub mod copy_bidirectional;

/// DNS 代理模块，支持标准 DNS、DoT 和 DoH 查询以及本地缓存
pub mod dns;
