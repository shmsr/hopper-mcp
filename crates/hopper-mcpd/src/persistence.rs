use crate::store::SnapshotStore;
use anyhow::{Context, Result};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn load_store(path: &Path) -> Result<SnapshotStore> {
    if !path.exists() {
        return Ok(SnapshotStore::default());
    }

    let file = fs::File::open(path)
        .with_context(|| format!("failed to open store file {}", path.display()))?;
    let mut store: SnapshotStore = serde_json::from_reader(file)
        .with_context(|| format!("failed to deserialize store file {}", path.display()))?;
    store.rehydrate_after_load();
    Ok(store)
}

pub fn save_store(path: &Path, store: &SnapshotStore) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create store directory {}", parent.display()))?;

    let file_name = path
        .file_name()
        .context("store path must include a file name")?
        .to_string_lossy();
    let (temp_path, mut temp_file) = create_temp_sibling(parent, &file_name)?;

    let result = (|| -> Result<()> {
        serde_json::to_writer_pretty(&mut temp_file, store)
            .with_context(|| format!("failed to serialize store to {}", temp_path.display()))?;
        temp_file
            .write_all(b"\n")
            .with_context(|| format!("failed to write {}", temp_path.display()))?;
        temp_file
            .sync_all()
            .with_context(|| format!("failed to sync {}", temp_path.display()))?;
        drop(temp_file);
        fs::rename(&temp_path, path).with_context(|| {
            format!(
                "failed to atomically replace {} with {}",
                path.display(),
                temp_path.display()
            )
        })?;
        fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .with_context(|| format!("failed to sync store directory {}", parent.display()))?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }

    result
}

fn create_temp_sibling(parent: &Path, file_name: &str) -> Result<(PathBuf, fs::File)> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    for attempt in 0..100 {
        let temp_path = parent.join(format!(
            ".{file_name}.{}.{}.tmp",
            process::id(),
            nonce + attempt
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)
        {
            Ok(file) => return Ok((temp_path, file)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| {
                    format!("failed to create temp store file {}", temp_path.display())
                });
            }
        }
    }

    anyhow::bail!(
        "failed to create a unique temp store file in {}",
        parent.display()
    )
}
