use anyhow::{bail, Result};
use std::ffi::OsString;
use std::path::PathBuf;

#[cfg(target_os = "linux")]
const MAX_COPY_BYTES: usize = 64 * 1024;

#[cfg(target_os = "linux")]
mod linux {
    use super::{bail, OsString, PathBuf, Result, MAX_COPY_BYTES};
    use anyhow::Context;
    use std::ffi::CString;
    use std::io::{self, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::{Duration, Instant};

    const TRUSTED_PATH: &str = "/usr/bin";
    const COPY_PROGRAM: &str = "/usr/bin/wl-copy";
    const OPEN_PROGRAM: &str = "/usr/bin/xdg-open";
    const ACTION_TIMEOUT: Duration = Duration::from_secs(5);
    const TERMINATION_GRACE: Duration = Duration::from_secs(1);

    struct TrustedProgram {
        file: OwnedFd,
        display_path: &'static str,
    }

    impl TrustedProgram {
        fn open(path: &'static str) -> Result<Self> {
            let path_bytes = CString::new(path.as_bytes()).context("trusted path contains NUL")?;
            // O_PATH binds subsequent execution to this exact object. O_NOFOLLOW
            // lets fstat reject a symlink rather than silently following it.
            let descriptor =
                unsafe { libc::open(path_bytes.as_ptr(), libc::O_PATH | libc::O_NOFOLLOW) };
            if descriptor < 0 {
                return Err(io::Error::last_os_error())
                    .with_context(|| format!("cannot open trusted executable {path}"));
            }
            let file = unsafe { OwnedFd::from_raw_fd(descriptor) };
            let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
            if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
                return Err(io::Error::last_os_error())
                    .with_context(|| format!("cannot inspect trusted executable {path}"));
            }
            let stat = unsafe { stat.assume_init() };
            validate_metadata(path, stat.st_mode, stat.st_uid)?;
            Ok(Self {
                file,
                display_path: path,
            })
        }

        fn proc_path(&self) -> PathBuf {
            PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
        }
    }

    fn validate_metadata(path: &str, mode: libc::mode_t, owner: libc::uid_t) -> Result<()> {
        if mode & libc::S_IFMT != libc::S_IFREG {
            bail!("trusted executable is not a regular file: {path}");
        }
        if owner != 0 {
            bail!("trusted executable is not owned by root: {path}");
        }
        if mode & 0o022 != 0 {
            bail!("trusted executable is group- or world-writable: {path}");
        }
        if mode & 0o111 == 0 {
            bail!("trusted executable is not executable: {path}");
        }
        Ok(())
    }

    fn configure_child(command: &mut Command) {
        command.env("PATH", TRUSTED_PATH);
        for name in [
            "BASH_ENV",
            "ENV",
            "SHELLOPTS",
            "CDPATH",
            "GLOBIGNORE",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "LD_AUDIT",
            "LD_PROFILE",
            "BROWSER",
        ] {
            command.env_remove(name);
        }
        command.stdout(Stdio::null()).stderr(Stdio::null());
        let parent = unsafe { libc::getpid() };
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    libc::_exit(125);
                }
                if libc::setsid() < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    fn signal_group(child: &Child, signal: libc::c_int) -> io::Result<()> {
        let process_group = -(child.id() as libc::pid_t);
        if unsafe { libc::kill(process_group, signal) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error)
        }
    }

    fn wait_until(child: &mut Child, deadline: Instant) -> io::Result<Option<i32>> {
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(Some(status.code().unwrap_or(1)));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn finish_bounded(mut child: Child, program: &str) -> Result<i32> {
        if let Some(code) = wait_until(&mut child, Instant::now() + ACTION_TIMEOUT)? {
            return Ok(code);
        }
        signal_group(&child, libc::SIGTERM).context("terminating desktop action group")?;
        if wait_until(&mut child, Instant::now() + TERMINATION_GRACE)?.is_none() {
            signal_group(&child, libc::SIGKILL).context("killing desktop action group")?;
            child
                .wait()
                .context("waiting for terminated desktop action")?;
        }
        eprintln!("AgentWire desktop action timed out: {program}");
        Ok(124)
    }

    fn command(program: &TrustedProgram) -> Command {
        let mut command = Command::new(program.proc_path());
        configure_child(&mut command);
        command
    }

    pub(super) fn copy(value: OsString) -> Result<i32> {
        if value.as_bytes().len() > MAX_COPY_BYTES {
            bail!("clipboard value exceeds {MAX_COPY_BYTES} bytes");
        }
        let program = TrustedProgram::open(COPY_PROGRAM)?;
        let mut command = command(&program);
        command.stdin(Stdio::piped());
        let mut child = command
            .spawn()
            .with_context(|| format!("cannot execute trusted helper {}", program.display_path))?;
        let mut input = child
            .stdin
            .take()
            .context("clipboard helper stdin unavailable")?;
        let contents = value.as_bytes().to_vec();
        let writer = thread::spawn(move || input.write_all(&contents));
        let code = finish_bounded(child, program.display_path)?;
        let write_result = writer
            .join()
            .map_err(|_| anyhow::anyhow!("clipboard writer thread panicked"))?;
        if code == 0 {
            write_result.context("writing clipboard value")?;
        }
        Ok(code)
    }

    pub(super) fn open(path: PathBuf) -> Result<i32> {
        let program = TrustedProgram::open(OPEN_PROGRAM)?;
        let mut command = command(&program);
        command.arg(path).stdin(Stdio::null());
        let child = command
            .spawn()
            .with_context(|| format!("cannot execute trusted helper {}", program.display_path))?;
        finish_bounded(child, program.display_path)
    }

    #[cfg(test)]
    mod tests {
        use super::validate_metadata;

        #[test]
        fn trusted_metadata_requires_root_owned_non_writable_executable_file() {
            assert!(validate_metadata("ok", libc::S_IFREG | 0o755, 0).is_ok());
            assert!(validate_metadata("symlink", libc::S_IFLNK | 0o777, 0).is_err());
            assert!(validate_metadata("owner", libc::S_IFREG | 0o755, 1000).is_err());
            assert!(validate_metadata("writable", libc::S_IFREG | 0o775, 0).is_err());
            assert!(validate_metadata("mode", libc::S_IFREG | 0o644, 0).is_err());
        }
    }
}

#[cfg(target_os = "linux")]
pub fn copy(value: OsString) -> Result<i32> {
    linux::copy(value)
}

#[cfg(target_os = "linux")]
pub fn open(path: PathBuf) -> Result<i32> {
    linux::open(path)
}

#[cfg(not(target_os = "linux"))]
pub fn copy(_value: OsString) -> Result<i32> {
    bail!("trusted desktop actions are supported only on Linux")
}

#[cfg(not(target_os = "linux"))]
pub fn open(_path: PathBuf) -> Result<i32> {
    bail!("trusted desktop actions are supported only on Linux")
}
