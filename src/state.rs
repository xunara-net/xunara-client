use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use crypto_box::SecretKey;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct Identity {
    pub server: String,
    pub machine: [u8; 32],
    pub node: [u8; 32],
    pub disco: [u8; 32],
}

pub struct Store {
    directory: PathBuf,
    _lock: File,
}

impl Store {
    pub fn open(directory: &Path) -> Result<Self> {
        match fs::symlink_metadata(directory) {
            Ok(metadata) => ensure!(
                metadata.is_dir() && !metadata.file_type().is_symlink(),
                "状态目录不能是符号链接"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(directory)?;
            }
            Err(error) => return Err(error.into()),
        }
        private_metadata(&fs::metadata(directory)?)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join("client.lock"))?;
        private_metadata(&lock.metadata()?)?;
        // SAFETY: lock 是持有期间有效的文件描述符；非阻塞锁避免同时启动两个实例。
        let locked = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        ensure!(locked == 0, "此状态目录已有客户端运行");
        Ok(Self {
            directory: directory.into(),
            _lock: lock,
        })
    }

    pub fn identity(&self, server: &str) -> Result<Identity> {
        let path = self.directory.join("identity.json");
        match read_secret(&path) {
            Ok(raw) => {
                let identity: Identity =
                    serde_json::from_slice(raw.as_bytes()).context("身份文件损坏，拒绝覆盖密钥")?;
                ensure!(
                    identity.server == server,
                    "身份属于其他控制面；请为新服务器使用独立状态目录"
                );
                ensure!(
                    identity.machine != [0; 32]
                        && identity.node != [0; 32]
                        && identity.disco != [0; 32],
                    "身份密钥无效"
                );
                Ok(identity)
            }
            Err(error)
                if !path.exists()
                    && error
                        .downcast_ref::<std::io::Error>()
                        .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
            {
                let identity = Identity {
                    server: server.into(),
                    machine: SecretKey::generate(&mut OsRng).to_bytes(),
                    node: SecretKey::generate(&mut OsRng).to_bytes(),
                    disco: SecretKey::generate(&mut OsRng).to_bytes(),
                };
                self.write("identity.json", &identity)?;
                Ok(identity)
            }
            Err(error) => Err(error),
        }
    }

    pub fn write(&self, name: &str, value: &impl Serialize) -> Result<()> {
        ensure!(
            matches!(name, "identity.json" | "status.json"),
            "无效状态文件名"
        );
        let contents = Zeroizing::new(serde_json::to_vec_pretty(value)?);
        let temporary = self
            .directory
            .join(format!(".{name}.{}", std::process::id()));
        let result = (|| -> Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&temporary)?;
            file.write_all(&contents)?;
            file.sync_all()?;
            fs::rename(&temporary, self.directory.join(name))?;
            File::open(&self.directory)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }
}

fn private_metadata(metadata: &fs::Metadata) -> Result<()> {
    // SAFETY: geteuid 不接收指针，只读取调用进程的有效 UID。
    let user = unsafe { libc::geteuid() };
    ensure!(
        metadata.uid() == user && metadata.permissions().mode() & 0o077 == 0,
        "私有文件或目录必须属于当前用户且不允许组/其他用户访问（0700 / 0600）"
    );
    Ok(())
}

pub fn read_secret(path: &Path) -> Result<Zeroizing<String>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= 16 * 1024,
        "私密文件必须是有界普通文件"
    );
    private_metadata(&metadata)?;
    let mut contents = Zeroizing::new(String::new());
    file.take(16 * 1024 + 1).read_to_string(&mut contents)?;
    ensure!(contents.len() <= 16 * 1024, "私密文件过大");
    Ok(contents)
}

pub fn public_key(private: &[u8; 32], prefix: &str) -> String {
    format!(
        "{prefix}{}",
        hex::encode(SecretKey::from(*private).public_key().as_bytes())
    )
}

pub fn parse_key(raw: &str, prefix: &str) -> Result<[u8; 32]> {
    let mut key = [0; 32];
    hex::decode_to_slice(
        raw.strip_prefix(prefix).context("公钥类型不匹配")?,
        &mut key,
    )
    .map_err(|_| anyhow::anyhow!("公钥编码无效"))?;
    ensure!(key != [0; 32], "公钥不能为零");
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_state_persists_and_is_exclusively_locked() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store = Store::open(directory.path()).unwrap();
        let first = store.identity("https://example.com/").unwrap();
        assert_eq!(
            store.identity("https://example.com/").unwrap().node,
            first.node
        );
        assert!(store.identity("https://other.example/").is_err());
        assert!(Store::open(directory.path()).is_err());
        assert_eq!(
            fs::metadata(directory.path().join("identity.json"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        fs::write(directory.path().join("identity.json"), "broken").unwrap();
        assert!(store.identity("https://example.com/").is_err());
    }

    #[test]
    fn reject_symlinks_and_public_secrets() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("key");
        fs::write(&path, "secret").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_secret(&path).is_err());
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(path, &link).unwrap();
        assert!(read_secret(&link).is_err());
    }
}
