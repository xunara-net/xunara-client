use std::{path::PathBuf, sync::Arc};

use anyhow::{Context, Result, ensure};
use tokio::sync::{mpsc, watch};
use xunara_client::{
    VERSION,
    config::Config,
    control,
    engine::Engine,
    state::{Store, read_secret},
};
use zeroize::Zeroizing;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("xunara-client: {error:#}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let mut arguments = std::env::args().skip(1);
    let command = arguments.next().unwrap_or_else(|| "help".into());
    if matches!(command.as_str(), "--version" | "version") {
        println!("xunara-client {VERSION}");
        return Ok(());
    }
    if matches!(command.as_str(), "help" | "--help" | "-h") {
        println!(
            "Xunara 精简 Linux 客户端\n\n  xunara-client run --config /etc/xunara-client/config.json [--auth-key-file /run/secrets/auth-key]\n  xunara-client status [--state-dir /var/lib/xunara-client]\n  xunara-client --version\n\n密钥仅从 0600 文件读取，不支持明文 argv；配置示例见 README。"
        );
        return Ok(());
    }
    let mut config_path = PathBuf::from("/etc/xunara-client/config.json");
    let mut state_dir = PathBuf::from("/var/lib/xunara-client");
    let mut auth_file = None;
    while let Some(flag) = arguments.next() {
        let value = PathBuf::from(arguments.next().context("参数缺少值")?);
        match flag.as_str() {
            "--config" if command == "run" => config_path = value,
            "--auth-key-file" if command == "run" => auth_file = Some(value),
            "--state-dir" if command == "status" => state_dir = value,
            _ => anyhow::bail!("未知参数；使用 --help 查看用法（不接受明文密钥参数）"),
        }
    }
    if command == "status" {
        let raw = read_secret(&state_dir.join("status.json"))?;
        let mut value: serde_json::Value = serde_json::from_str(&raw)?;
        let updated = value
            .get("updated_at")
            .and_then(serde_json::Value::as_i64)
            .unwrap_or(0);
        if time::OffsetDateTime::now_utc().unix_timestamp() - updated > 30 {
            value["online"] = false.into();
        }
        println!("{}", serde_json::to_string_pretty(&value)?);
        return Ok(());
    }
    ensure!(command == "run", "未知命令；使用 --help 查看用法");
    let config = Arc::new(Config::load(&config_path)?);
    let store = Store::open(&config.state_dir)?;
    let normalized = xunara_client::config::server_url(&config.server)?.to_string();
    let identity = Arc::new(store.identity(&normalized)?);
    let auth_key = match auth_file {
        Some(path) => read_secret(&path)?,
        None => Zeroizing::new(String::new()),
    };
    let (endpoints, receiver) = watch::channel(Default::default());
    let mut engine = Engine::new(config.clone(), identity.clone(), endpoints).await?;
    let (maps, updates) = mpsc::channel(4);
    let task = tokio::spawn(control::run(config, identity, auth_key, receiver, maps));
    let mut termination =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let result = tokio::select! {
        result=engine.run(updates,&store)=>result,
        result=tokio::signal::ctrl_c()=>result.map_err(Into::into),
        _=termination.recv()=>Ok(()),
    };
    task.abort();
    let stopped = engine.stop().await;
    engine.status(&store)?;
    result?;
    stopped?;
    Ok(())
}
