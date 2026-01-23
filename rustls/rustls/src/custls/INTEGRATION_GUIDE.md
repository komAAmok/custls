# custls Integration Guide

## 如何在 Hyper 中使用 custls

本指南展示如何将 custls 集成到基于 hyper 的 HTTP 客户端中，实现浏览器级别的 TLS 指纹模拟。

## 快速开始

### 1. 添加依赖

在你的 `Cargo.toml` 中添加：

```toml
[dependencies]
rustls = { path = "../path/to/custls/rustls" }  # 使用魔改版 rustls
hyper = { version = "0.14", features = ["client", "http1", "http2"] }
hyper-rustls = "0.24"
tokio = { version = "1", features = ["full"] }
```

### 2. 基础集成代码

```rust
use std::sync::Arc;
use hyper::{Client, Request, Body};
use hyper_rustls::HttpsConnectorBuilder;
use rustls::ClientConfig;
use rustls::custls::{
    CustlsConfig, BrowserTemplate, 
    RandomizationLevel, DefaultCustomizer
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 步骤 1: 配置 custls
    let custls_config = CustlsConfig::builder()
        .with_template(BrowserTemplate::Chrome130)  // 模拟 Chrome 130
        .with_randomization_level(RandomizationLevel::Light)  // 轻度随机化
        .with_cache(true)  // 启用指纹缓存
        .build();
    
    let customizer = Arc::new(DefaultCustomizer::new(custls_config));
    
    // 步骤 2: 配置 rustls
    let mut tls_config = ClientConfig::builder()
        .with_safe_defaults()
        .with_native_roots()
        .with_no_client_auth();
    
    // 步骤 3: 附加 custls customizer
    // 注意：具体 API 取决于 custls 的实现
    // 可能是通过 builder 方法或直接字段访问
    // tls_config.custls_customizer = Some(customizer);
    
    // 步骤 4: 构建 HTTPS connector
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_only()
        .enable_http1()
        .enable_http2()
        .build();
    
    // 步骤 5: 创建 hyper 客户端
    let client = Client::builder().build::<_, Body>(https);
    
    // 步骤 6: 发送请求
    let req = Request::builder()
        .uri("https://example.com")
        .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
        .body(Body::empty())?;
    
    let res = client.request(req).await?;
    println!("Status: {}", res.status());
    
    Ok(())
}
```

## 配置选项

### 浏览器模板

选择要模拟的浏览器：

```rust
// Chrome 130+ (最常见，推荐用于一般场景)
.with_template(BrowserTemplate::Chrome130)

// Firefox 135+ (独特指纹，适合多样化)
.with_template(BrowserTemplate::Firefox135)

// Safari 17+ (macOS/iOS 场景)
.with_template(BrowserTemplate::Safari17)

// Edge 130+ (Windows 场景)
.with_template(BrowserTemplate::Edge130)

// 自定义模板
.with_template(BrowserTemplate::Custom(Box::new(custom_template)))
```

### 随机化级别

控制指纹变化程度：

```rust
// 无随机化 - 精确使用模板
.with_randomization_level(RandomizationLevel::None)

// 轻度随机化 - 小幅变化（推荐）
.with_randomization_level(RandomizationLevel::Light)

// 中度随机化 - 适度变化
.with_randomization_level(RandomizationLevel::Medium)

// 高度随机化 - 最大变化
.with_randomization_level(RandomizationLevel::High)
```

### 缓存配置

```rust
// 启用缓存（推荐）
.with_cache(true)

// 禁用缓存
.with_cache(false)

// 设置缓存大小限制
.with_max_cache_size(1000)
```

## 高级用法

### 1. 多客户端策略

为不同目标使用不同的指纹：

```rust
// Cloudflare 站点使用 Chrome
let cloudflare_config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Chrome130)
    .with_randomization_level(RandomizationLevel::Light)
    .build();

let cloudflare_client = create_client(cloudflare_config);

// Akamai 站点使用 Firefox
let akamai_config = CustlsConfig::builder()
    .with_template(BrowserTemplate::Firefox135)
    .with_randomization_level(RandomizationLevel::Medium)
    .build();

let akamai_client = create_client(akamai_config);
```

### 2. 模板轮换

在请求之间轮换模板以避免行为聚类检测：

```rust
let templates = vec![
    BrowserTemplate::Chrome130,
    BrowserTemplate::Firefox135,
    BrowserTemplate::Safari17,
];

for (i, template) in templates.iter().cycle().enumerate().take(10) {
    let config = CustlsConfig::builder()
        .with_template(template.clone())
        .with_randomization_level(RandomizationLevel::Light)
        .build();
    
    let client = create_client(config);
    // 发送请求...
}
```

### 3. 自定义 Hook

实现 `ClientHelloCustomizer` trait 进行精细控制：

```rust
use rustls::custls::ClientHelloCustomizer;

#[derive(Debug)]
struct MyCustomHooks {
    // 自定义字段
}

impl ClientHelloCustomizer for MyCustomHooks {
    fn on_config_resolve(&self, config: &mut ConfigParams) -> Result<(), Error> {
        // 在 ClientHello 构建前修改配置
        Ok(())
    }
    
    fn on_components_ready(
        &self,
        cipher_suites: &mut Vec<CipherSuite>,
        extensions: &mut Vec<ClientExtension>,
    ) -> Result<(), Error> {
        // 修改密码套件和扩展
        Ok(())
    }
    
    // ... 其他 hook 方法
}

let customizer = Arc::new(MyCustomHooks { /* ... */ });
```

## 最佳实践

### 1. HTTP 头部匹配

确保 HTTP 头部与 TLS 指纹匹配：

```rust
// Chrome 130 的典型头部
let req = Request::builder()
    .uri(uri)
    .header("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")
    .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8")
    .header("Accept-Language", "en-US,en;q=0.9")
    .header("Accept-Encoding", "gzip, deflate, br")
    .header("Sec-Ch-Ua", "\"Chromium\";v=\"130\", \"Google Chrome\";v=\"130\", \"Not?A_Brand\";v=\"99\"")
    .header("Sec-Ch-Ua-Mobile", "?0")
    .header("Sec-Ch-Ua-Platform", "\"Windows\"")
    .body(Body::empty())?;
```

### 2. 连接复用

保持连接池以提高性能：

```rust
// hyper 自动处理连接池
// 确保为同一目标重用客户端实例
let client = Client::builder()
    .pool_idle_timeout(Duration::from_secs(90))
    .pool_max_idle_per_host(10)
    .build::<_, Body>(https);
```

### 3. 错误处理

正确处理 TLS 错误：

```rust
match client.request(req).await {
    Ok(res) => {
        println!("Success: {}", res.status());
    }
    Err(e) => {
        if e.is_connect() {
            eprintln!("Connection error (可能是指纹被检测): {}", e);
            // 考虑切换模板或调整配置
        } else {
            eprintln!("Other error: {}", e);
        }
    }
}
```

### 4. 性能监控

监控性能开销：

```rust
use std::time::Instant;

let start = Instant::now();
let res = client.request(req).await?;
let duration = start.elapsed();

println!("Request took: {:?}", duration);
// custls 开销应该 <10%
```

## 与其他 HTTP 客户端集成

### Reqwest

```rust
use reqwest::Client;

let mut tls_config = ClientConfig::builder()
    .with_safe_defaults()
    .with_native_roots()
    .with_no_client_auth();

// 附加 custls customizer
// tls_config.custls_customizer = Some(customizer);

let client = Client::builder()
    .use_preconfigured_tls(tls_config)
    .build()?;
```

### Surf

```rust
use surf::Client;

// Surf 使用 async-h1/async-h2，可能需要自定义 TLS 配置
// 具体实现取决于 surf 的 TLS 后端
```

## 故障排查

### 问题 1: 连接被拒绝

**症状**: 请求失败，返回连接错误

**可能原因**:
- 指纹被检测为异常
- 模板与目标服务器不兼容

**解决方案**:
```rust
// 尝试不同的模板
.with_template(BrowserTemplate::Firefox135)

// 增加随机化级别
.with_randomization_level(RandomizationLevel::Medium)

// 禁用缓存以获取新指纹
.with_cache(false)
```

### 问题 2: 性能下降

**症状**: 请求延迟增加

**可能原因**:
- 随机化级别过高
- 缓存未启用

**解决方案**:
```rust
// 降低随机化级别
.with_randomization_level(RandomizationLevel::Light)

// 启用缓存
.with_cache(true)

// 使用 None 级别获得最佳性能
.with_randomization_level(RandomizationLevel::None)
```

### 问题 3: 指纹不一致

**症状**: 同一目标的请求使用不同指纹

**可能原因**:
- 缓存未启用
- 随机化级别过高

**解决方案**:
```rust
// 启用缓存以保持一致性
.with_cache(true)

// 使用较低的随机化级别
.with_randomization_level(RandomizationLevel::Light)
```

## 性能特征

基于基准测试结果：

- **开销**: 3.9% - 5.9% (远低于 10% 目标)
- **缓存查找**: <1ns (几乎即时)
- **Hook 调用**: <1ns (零开销)
- **完整流程**: ~30μs (包含所有定制)

## 安全考虑

1. **保持 rustls 安全保证**: custls 不引入 unsafe 代码
2. **证书验证**: 完全保留 rustls 的证书验证
3. **降级保护**: 实现 RFC 8446 降级保护
4. **会话安全**: 正确处理会话票据和恢复

## 示例项目

查看 `examples/` 目录中的完整示例：

- `custls_basic_usage.rs` - 基础配置
- `custls_custom_hooks.rs` - 自定义 hook
- `custls_custom_template.rs` - 自定义模板
- `custls_http_client.rs` - HTTP 客户端集成模式
- `hyper_custls_complete.rs` - 完整 hyper 集成

## 更多资源

- [custls 设计文档](./design.md)
- [custls 需求文档](./requirements.md)
- [性能基准测试](./benches/)
- [浏览器验证测试](./browser_validation.rs)

## 支持

如有问题或需要帮助，请查看：
- 示例代码
- 测试用例
- 文档注释
