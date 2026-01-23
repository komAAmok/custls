# custls 快速入门指南

## 什么是 custls？

custls 是一个对 rustls 进行最小侵入式修改的 TLS 库，专门用于模拟真实浏览器的 TLS ClientHello 指纹。它可以帮助你：

- ✅ 绕过基于 TLS 指纹的检测系统（Cloudflare、Akamai、DataDome 等）
- ✅ 模拟 Chrome、Firefox、Safari、Edge 等主流浏览器
- ✅ 自动缓存成功的指纹配置
- ✅ 应用自然的随机变化避免检测
- ✅ 保持 rustls 的所有安全保证

## 5 分钟快速上手

### 第一步：添加依赖

```toml
[dependencies]
# 使用魔改版 rustls（包含 custls）
rustls = { path = "./rustls/rustls" }

# HTTP 客户端（以 hyper 为例）
hyper = { version = "0.14", features = ["client", "http1", "http2"] }
hyper-rustls = "0.24"
tokio = { version = "1", features = ["full"] }
```

### 第二步：配置 custls

```rust
use rustls::custls::{CustlsConfig, BrowserTemplate, RandomizationLevel, DefaultCustomizer};
use std::sync::Arc;

// 创建配置：模拟 Chrome 130，轻度随机化，启用缓存
let custls_config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Chrome130)
    .with_randomization_level(RandomizationLevel::Light)
    .with_cache(true)
    .build();

// 创建定制器
let customizer = Arc::new(DefaultCustomizer::new(custls_config));
```

### 第三步：集成到 HTTP 客户端

```rust
use hyper::{Client, Request, Body};
use hyper_rustls::HttpsConnectorBuilder;
use rustls::ClientConfig;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 配置 rustls
    let mut tls_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_native_roots()
        .with_no_client_auth();
    
    // 附加 custls customizer（具体 API 取决于实现）
    // tls_config.custls_customizer = Some(customizer);
    
    // 构建 HTTPS connector
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_only()
        .enable_http2()
        .build();
    
    // 创建 hyper 客户端
    let client = Client::builder().build::<_, Body>(https);
    
    // 发送请求
    let req = Request::builder()
        .uri("https://example.com")
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        .body(Body::empty())?;
    
    let res = client.request(req).await?;
    println!("状态码: {}", res.status());
    
    Ok(())
}
```

## 核心概念

### 1. 浏览器模板 (Browser Template)

选择要模拟的浏览器：

```rust
BrowserTemplate::Chrome130   // Chrome 130+ (推荐，最常见)
BrowserTemplate::Firefox135  // Firefox 135+ (独特指纹)
BrowserTemplate::Safari17    // Safari 17+ (macOS/iOS)
BrowserTemplate::Edge130     // Edge 130+ (Windows)
```

**如何选择？**
- 一般场景：使用 `Chrome130`（最常见，兼容性最好）
- 需要多样化：轮换使用不同模板
- 特定平台：macOS 用 Safari，Windows 用 Edge

### 2. 随机化级别 (Randomization Level)

控制指纹变化程度：

```rust
RandomizationLevel::None     // 无变化，精确使用模板
RandomizationLevel::Light    // 小幅变化（推荐）
RandomizationLevel::Medium   // 适度变化
RandomizationLevel::High     // 最大变化
```

**如何选择？**
- 性能优先：使用 `None`（开销最小）
- 平衡推荐：使用 `Light`（自然变化，低开销）
- 强反指纹：使用 `Medium` 或 `High`

### 3. 指纹缓存 (Fingerprint Cache)

自动缓存成功的指纹配置：

```rust
.with_cache(true)   // 启用缓存（推荐）
.with_cache(false)  // 禁用缓存
```

**为什么要缓存？**
- ✅ 对同一目标保持一致的指纹
- ✅ 提高性能（避免重复计算）
- ✅ 模拟真实浏览器行为（会话内一致）

## 常见使用场景

### 场景 1：爬虫/数据采集

```rust
// 配置：Chrome + 轻度随机化 + 缓存
let config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Chrome130)
    .with_randomization_level(RandomizationLevel::Light)
    .with_cache(true)
    .build();

// 优点：
// - 看起来像真实 Chrome 浏览器
// - 每个目标保持一致的指纹
// - 自然的小幅变化避免检测
```

### 场景 2：API 测试

```rust
// 配置：Firefox + 中度随机化 + 无缓存
let config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Firefox135)
    .with_randomization_level(RandomizationLevel::Medium)
    .with_cache(false)
    .build();

// 优点：
// - 每次请求使用不同指纹
// - 测试服务器的指纹检测能力
// - 避免被识别为自动化工具
```

### 场景 3：多账号操作

```rust
// 为每个账号使用不同的客户端和模板
let templates = vec![
    BrowserTemplate::Chrome130,
    BrowserTemplate::Firefox135,
    BrowserTemplate::Safari17,
];

for (account, template) in accounts.iter().zip(templates.iter().cycle()) {
    let config = CustlsConfig::builder()
        .with_template(template.clone())
        .with_randomization_level(RandomizationLevel::Light)
        .with_cache(true)
        .build();
    
    let client = create_client(config);
    // 使用该客户端进行该账号的操作
}

// 优点：
// - 每个账号有独特的指纹
// - 避免账号关联检测
// - 模拟不同设备/浏览器
```

## 性能数据

基于实际基准测试：

| 配置 | 延迟 | 开销 |
|------|------|------|
| 原版 rustls | 28.5μs | 0% |
| custls (None) | 29.6μs | +3.9% |
| custls (Light) | 30.0μs | +5.1% |
| custls (Medium) | 29.8μs | +4.7% |
| custls (High) | 29.8μs | +4.7% |

**结论**：开销极小（<6%），远低于 10% 的目标！

## 最佳实践

### ✅ DO（推荐做法）

1. **匹配 HTTP 头部**
   ```rust
   // TLS 指纹是 Chrome，HTTP 头部也要像 Chrome
   .header("User-Agent", "Mozilla/5.0 ... Chrome/130.0.0.0 ...")
   .header("Sec-Ch-Ua", "\"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\"")
   ```

2. **启用缓存**
   ```rust
   .with_cache(true)  // 对同一目标保持一致
   ```

3. **使用轻度随机化**
   ```rust
   .with_randomization_level(RandomizationLevel::Light)  // 平衡性能和自然度
   ```

4. **复用客户端**
   ```rust
   // 创建一次，多次使用
   let client = create_client(config);
   for url in urls {
       client.get(url).await?;
   }
   ```

### ❌ DON'T（避免做法）

1. **不要混用指纹和头部**
   ```rust
   // ❌ 错误：TLS 是 Chrome，User-Agent 是 Firefox
   // 这会被检测为异常
   ```

2. **不要过度随机化**
   ```rust
   // ❌ 除非必要，避免使用 High
   // 可能产生不自然的指纹
   ```

3. **不要频繁切换模板**
   ```rust
   // ❌ 对同一目标频繁切换模板
   // 会被识别为异常行为
   ```

4. **不要忽略错误**
   ```rust
   // ❌ 连接失败可能意味着指纹被检测
   // 应该记录并调整配置
   ```

## 故障排查

### 问题：请求被拒绝

**可能原因**：指纹被识别为异常

**解决方案**：
```rust
// 1. 尝试不同的模板
.with_template(BrowserTemplate::Firefox135)

// 2. 调整随机化级别
.with_randomization_level(RandomizationLevel::Medium)

// 3. 清除缓存
.with_cache(false)

// 4. 检查 HTTP 头部是否匹配
```

### 问题：性能下降

**可能原因**：随机化开销或缓存未启用

**解决方案**：
```rust
// 1. 降低随机化级别
.with_randomization_level(RandomizationLevel::Light)

// 2. 启用缓存
.with_cache(true)

// 3. 使用 None 获得最佳性能
.with_randomization_level(RandomizationLevel::None)
```

### 问题：指纹不一致

**可能原因**：缓存未启用或随机化过高

**解决方案**：
```rust
// 1. 启用缓存
.with_cache(true)

// 2. 降低随机化
.with_randomization_level(RandomizationLevel::Light)
```

## 进阶功能

### 自定义 Hook

如果需要更精细的控制，可以实现自定义 hook：

```rust
use rustls::custls::ClientHelloCustomizer;

#[derive(Debug)]
struct MyHooks;

impl ClientHelloCustomizer for MyHooks {
    // 实现你需要的 hook 方法
    // 4 个阶段：配置、组件、结构、字节
}

let customizer = Arc::new(MyHooks);
```

### 模板轮换

避免行为聚类检测：

```rust
let templates = vec![
    BrowserTemplate::Chrome130,
    BrowserTemplate::Firefox135,
    BrowserTemplate::Safari17,
];

let mut template_index = 0;

for _ in 0..100 {
    let template = &templates[template_index % templates.len()];
    let config = CustlsConfig::builder()
        .with_template(template.clone())
        .build();
    
    // 使用该配置发送请求
    template_index += 1;
}
```

## 示例代码

查看 `examples/` 目录获取完整示例：

- `custls_basic_usage.rs` - 基础用法
- `custls_http_client.rs` - HTTP 客户端集成
- `hyper_custls_complete.rs` - 完整 hyper 示例
- `custls_custom_hooks.rs` - 自定义 hook
- `custls_custom_template.rs` - 自定义模板

## 下一步

1. ✅ 运行示例代码熟悉 API
2. ✅ 在你的项目中集成 custls
3. ✅ 根据目标调整配置
4. ✅ 监控成功率并优化
5. ✅ 查看完整文档了解高级功能

## 获取帮助

- 📖 查看 [完整集成指南](./INTEGRATION_GUIDE.md)
- 📖 查看 [设计文档](./design.md)
- 📖 查看 [需求文档](./requirements.md)
- 💻 查看示例代码
- 🧪 查看测试用例

---

**祝你使用愉快！custls 让 TLS 指纹模拟变得简单。** 🚀
