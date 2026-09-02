use anyhow::{bail, Context, Result};
use std::fs::File;
use std::io::Write;
use std::path::Path;

pub fn random_hex(bytes: usize) -> Result<String> {
    let mut value = vec![0_u8; bytes];
    getrandom::getrandom(&mut value)
        .map_err(|error| anyhow::anyhow!("secure randomness is unavailable: {error}"))?;
    Ok(value.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::ffi::{CString, OsStr};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::Component;

    fn c_name(name: &OsStr) -> Result<CString> {
        CString::new(name.as_bytes()).context("path contains a NUL byte")
    }

    fn open_initial(absolute: bool) -> Result<OwnedFd> {
        let name = if absolute { c"/" } else { c"." };
        let fd = unsafe {
            libc::open(
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error()).context("could not anchor path traversal");
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn open_child(parent: &OwnedFd, name: &CString) -> std::io::Result<OwnedFd> {
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(unsafe { OwnedFd::from_raw_fd(fd) })
        }
    }

    fn owner_private_directory(directory: &OwnedFd) -> Result<()> {
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(directory.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("could not inspect private directory");
        }
        let stat = unsafe { stat.assume_init() };
        if stat.st_uid != unsafe { libc::geteuid() }
            || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
            || stat.st_mode & 0o077 != 0
        {
            bail!("private directory must be owned by the current user with mode 0700");
        }
        Ok(())
    }

    fn normalized_path(path: &Path) -> std::path::PathBuf {
        #[cfg(target_os = "macos")]
        {
            // macOS exposes these immutable system locations through root-level
            // compatibility symlinks. Translate them lexically before beginning
            // descriptor-anchored traversal; no user-controlled link is followed.
            for prefix in ["var", "tmp", "etc"] {
                let visible = Path::new("/").join(prefix);
                if let Ok(remainder) = path.strip_prefix(&visible) {
                    return Path::new("/private").join(prefix).join(remainder);
                }
            }
        }
        path.to_path_buf()
    }

    fn open_directory(path: &Path, create: bool, private_final: bool) -> Result<OwnedFd> {
        let normalized = normalized_path(path);
        let path = normalized.as_path();
        let mut directory = open_initial(path.is_absolute())?;
        let components = path.components().collect::<Vec<_>>();
        let normal_count = components
            .iter()
            .filter(|component| matches!(component, Component::Normal(_)))
            .count();
        let mut normal_index = 0;
        for component in components {
            let Component::Normal(name) = component else {
                if matches!(component, Component::ParentDir | Component::Prefix(_)) {
                    bail!("secure paths must not contain parent or platform-prefix components");
                }
                continue;
            };
            normal_index += 1;
            let name = c_name(name)?;
            let child = match open_child(&directory, &name) {
                Ok(child) => child,
                Err(error) if create && error.kind() == std::io::ErrorKind::NotFound => {
                    if unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                        let mkdir_error = std::io::Error::last_os_error();
                        if mkdir_error.kind() != std::io::ErrorKind::AlreadyExists {
                            return Err(mkdir_error).context("could not create private directory");
                        }
                    }
                    open_child(&directory, &name)
                        .context("could not open created private directory")?
                }
                Err(error) => {
                    return Err(error)
                        .context("path contains a missing, symlinked, or non-directory component")
                }
            };
            directory = child;
            if private_final && normal_index == normal_count {
                owner_private_directory(&directory)?;
            }
        }
        if private_final && normal_count == 0 {
            owner_private_directory(&directory)?;
        }
        Ok(directory)
    }

    fn parent_and_name(
        path: &Path,
        create_parent: bool,
        private_parent: bool,
    ) -> Result<(OwnedFd, CString)> {
        let name = path
            .file_name()
            .filter(|name| !name.is_empty())
            .context("secure file path needs a filename")?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        Ok((
            open_directory(parent, create_parent, private_parent)?,
            c_name(name)?,
        ))
    }

    pub fn ensure_private_dir(path: &Path) -> Result<()> {
        open_directory(path, true, true).map(drop)
    }

    pub fn create_file(path: &Path, private_parent: bool) -> Result<File> {
        let (parent, name) = parent_and_name(path, true, private_parent)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("could not exclusively create {}", path.display()));
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub fn open_file(path: &Path, maximum_bytes: u64, private_file: bool) -> Result<File> {
        let (parent, name) = parent_and_name(path, false, private_file)?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("could not securely open {}", path.display()));
        }
        let file = unsafe { File::from_raw_fd(fd) };
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > maximum_bytes {
            bail!("file is not a bounded regular file");
        }
        if private_file {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.uid() != unsafe { libc::geteuid() }
                || metadata.permissions().mode() & 0o077 != 0
            {
                bail!("private file must be owned by the current user with mode 0600");
            }
        }
        Ok(file)
    }

    pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
        let (parent, name) = parent_and_name(path, true, true)?;
        let temporary_name = CString::new(format!(
            ".agentwire-{}-{}",
            std::process::id(),
            super::random_hex(16)?
        ))?;
        let temporary_fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                temporary_name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if temporary_fd < 0 {
            return Err(std::io::Error::last_os_error())
                .context("could not create private temporary file");
        }
        let mut temporary = unsafe { File::from_raw_fd(temporary_fd) };
        let result = (|| -> Result<()> {
            temporary.write_all(contents)?;
            temporary.sync_all()?;
            if unsafe {
                libc::renameat(
                    parent.as_raw_fd(),
                    temporary_name.as_ptr(),
                    parent.as_raw_fd(),
                    name.as_ptr(),
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error())
                    .context("could not atomically publish private file");
            }
            if unsafe { libc::fsync(parent.as_raw_fd()) } != 0 {
                return Err(std::io::Error::last_os_error())
                    .context("could not sync private directory");
            }
            Ok(())
        })();
        if result.is_err() {
            unsafe {
                libc::unlinkat(parent.as_raw_fd(), temporary_name.as_ptr(), 0);
            }
        }
        result
    }
}

#[cfg(not(unix))]
mod portable {
    use super::*;
    use std::fs::OpenOptions;

    pub fn ensure_private_dir(path: &Path) -> Result<()> {
        std::fs::create_dir_all(path)
            .with_context(|| format!("could not create directory {}", path.display()))
    }

    pub fn create_file(path: &Path, private_parent: bool) -> Result<File> {
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
            if private_parent {
                ensure_private_dir(parent)?;
            }
        }
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("could not exclusively create {}", path.display()))
    }

    pub fn open_file(path: &Path, maximum_bytes: u64, _private_file: bool) -> Result<File> {
        let metadata = std::fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.len() > maximum_bytes {
            bail!("file is not a bounded regular file");
        }
        File::open(path).with_context(|| format!("could not open {}", path.display()))
    }

    pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
        let parent = path.parent().context("private file needs a parent")?;
        ensure_private_dir(parent)?;
        let temporary = parent.join(format!(".agentwire-{}", super::random_hex(16)?));
        let mut file = create_file(&temporary, true)?;
        file.write_all(contents)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        Ok(())
    }
}

pub fn ensure_private_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    return unix::ensure_private_dir(path);
    #[cfg(not(unix))]
    return portable::ensure_private_dir(path);
}

pub fn create_private_file(path: &Path, private_parent: bool) -> Result<File> {
    #[cfg(unix)]
    return unix::create_file(path, private_parent);
    #[cfg(not(unix))]
    return portable::create_file(path, private_parent);
}

pub fn open_bounded_file(path: &Path, maximum_bytes: u64, private_file: bool) -> Result<File> {
    #[cfg(unix)]
    return unix::open_file(path, maximum_bytes, private_file);
    #[cfg(not(unix))]
    return portable::open_file(path, maximum_bytes, private_file);
}

pub fn atomic_write_private(path: &Path, contents: &[u8]) -> Result<()> {
    #[cfg(unix)]
    return unix::atomic_write(path, contents);
    #[cfg(not(unix))]
    return portable::atomic_write(path, contents);
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn exclusive_creation_does_not_replace_an_existing_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("trace.jsonl");
        create_private_file(&path, false).unwrap();
        assert!(create_private_file(&path, false).is_err());
    }

    #[test]
    fn descriptor_traversal_rejects_a_symlinked_parent() {
        let directory = tempfile::tempdir().unwrap();
        let actual = directory.path().join("actual");
        std::fs::create_dir(&actual).unwrap();
        let linked = directory.path().join("linked");
        symlink(&actual, &linked).unwrap();
        assert!(create_private_file(&linked.join("trace.jsonl"), false).is_err());
    }

    #[test]
    fn bounded_open_rejects_a_symlinked_file() {
        let directory = tempfile::tempdir().unwrap();
        let actual = directory.path().join("actual.jsonl");
        std::fs::write(&actual, b"{}\n").unwrap();
        let linked = directory.path().join("linked.jsonl");
        symlink(&actual, &linked).unwrap();
        assert!(open_bounded_file(&linked, 1024, false).is_err());
    }
}
