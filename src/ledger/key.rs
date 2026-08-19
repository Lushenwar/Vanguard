//! Ledger HMAC key: load from the environment, else from disk, else create.

use std::fs;
use std::path::Path;

use crate::error::{Error, Result};
use crate::ledger::event::{unhex, HASH_LEN};

pub const KEY_LEN: usize = 32;
pub const ENV_VAR: &str = "VANGUARD_LEDGER_KEY";
pub const KEY_FILE: &str = "ledger.key";

/// Resolve the key for `state_dir`.
///
/// Precedence: `VANGUARD_LEDGER_KEY` (hex) beats the key file, so an operator
/// can verify a ledger copied off a machine without also copying the key file
/// into place. If neither exists, one is generated and persisted.
pub fn load_or_create(state_dir: &Path) -> Result<[u8; KEY_LEN]> {
    if let Ok(hex) = std::env::var(ENV_VAR) {
        let bytes = unhex(hex.trim())
            .ok_or_else(|| Error::Config(format!("{ENV_VAR} is not valid hex")))?;
        return exact(bytes);
    }

    let path = state_dir.join(KEY_FILE);
    if path.exists() {
        check_permissions(&path)?;
        return exact(fs::read(&path)?);
    }

    fs::create_dir_all(state_dir)?;
    let mut key = [0u8; KEY_LEN];
    getrandom::fill(&mut key).map_err(|e| Error::Config(format!("CSPRNG unavailable: {e}")))?;
    write_private(&path, &key)?;
    Ok(key)
}

fn exact(bytes: Vec<u8>) -> Result<[u8; KEY_LEN]> {
    <[u8; KEY_LEN]>::try_from(bytes.as_slice()).map_err(|_| Error::KeyLength {
        expected: KEY_LEN,
        found: bytes.len(),
    })
}

#[cfg(unix)]
fn write_private(path: &Path, key: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    // Mode is set at create time rather than chmod'd after: between the two
    // there is a window where the key exists world-readable.
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(key)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, key: &[u8]) -> Result<()> {
    // ponytail: Windows inherits the parent directory's ACL. Tightening it
    // needs the Win32 security APIs, which is a dependency and a pile of unsafe
    // for a dev-only platform. Add it when Vanguard is deployed on Windows.
    fs::write(path, key)?;
    Ok(())
}

#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = fs::metadata(path)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(Error::KeyPermissions {
            path: path.to_path_buf(),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

// Keeps the key width tied to the hash width; if one moves the other must.
const _: () = assert!(KEY_LEN == HASH_LEN);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_then_reuses_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        // The env var would shadow the file and defeat the test.
        std::env::remove_var(ENV_VAR);
        let a = load_or_create(dir.path()).unwrap();
        let b = load_or_create(dir.path()).unwrap();
        assert_eq!(a, b);
        assert_ne!(a, [0u8; KEY_LEN], "key must not be all zeroes");
    }

    #[test]
    fn rejects_a_short_key() {
        assert!(matches!(
            exact(vec![1, 2, 3]),
            Err(Error::KeyLength { found: 3, .. })
        ));
    }
}
