//! Running a build command in a process tree we can actually kill.
//!
//! A candidate build starts Ninja, which starts compilers and a linker. When a
//! trial times out or the run is cancelled, killing Ninja leaves that fan-out
//! behind holding files open in a workspace the coordinator is about to reset.
//! So every command gets a container: a kill-on-close Job Object on Windows, a
//! new process group on Unix, and killing the container takes the whole tree.

use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Why a command did not succeed.
///
/// The three cases are kept apart because a stage treats them differently: a
/// failed build bisects, a timeout bisects but also says the bound may be
/// wrong, and a cancellation is not a result about the candidate at all.
#[derive(Debug)]
pub enum CommandError {
    /// The command ran and exited non-zero.
    Failed { status: Option<i32>, evidence: Option<Box<CommandEvidence>> },
    /// The command exceeded its time bound and its tree was killed.
    TimedOut { after: Duration, evidence: Option<Box<CommandEvidence>> },
    /// The run was cancelled; nothing is known about the candidate.
    Cancelled,
    /// The command could not be started, or its output could not be read.
    Io(std::io::Error),
}

/// Only this command's output, even when many commands append to the same log.
/// The full bytes remain in `log`; excerpts here are bounded for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandEvidence {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub log: PathBuf,
    pub log_start: u64,
    pub log_end: u64,
    pub stdout_excerpt: String,
    pub stderr_excerpt: String,
}

impl CommandError {
    pub fn evidence(&self) -> Option<&CommandEvidence> {
        match self {
            Self::Failed { evidence, .. } | Self::TimedOut { evidence, .. } => evidence.as_deref(),
            Self::Cancelled | Self::Io(_) => None,
        }
    }

    fn with_evidence(self, evidence: CommandEvidence) -> Self {
        match self {
            Self::Failed { status, .. } => {
                Self::Failed { status, evidence: Some(Box::new(evidence)) }
            }
            Self::TimedOut { after, .. } => {
                Self::TimedOut { after, evidence: Some(Box::new(evidence)) }
            }
            other => other,
        }
    }
}

impl std::fmt::Display for CommandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Failed { status: Some(code), .. } => write!(f, "exit status {code}")?,
            Self::Failed { status: None, .. } => write!(f, "terminated by a signal")?,
            Self::TimedOut { after, .. } => {
                write!(f, "timed out after {:.0}s", after.as_secs_f64())?
            }
            Self::Cancelled => write!(f, "cancelled")?,
            Self::Io(e) => write!(f, "{e}")?,
        };
        if let Some(evidence) = self.evidence() {
            write!(
                f,
                " in {} ({}:{}..{})",
                evidence.program.display(),
                evidence.log.display(),
                evidence.log_start,
                evidence.log_end
            )?;
            if !evidence.stderr_excerpt.trim().is_empty() {
                write!(f, "; stderr: {}", evidence.stderr_excerpt.trim())?;
            } else if !evidence.stdout_excerpt.trim().is_empty() {
                write!(f, "; stdout: {}", evidence.stdout_excerpt.trim())?;
            }
        }
        Ok(())
    }
}

impl std::error::Error for CommandError {}

impl From<std::io::Error> for CommandError {
    fn from(error: std::io::Error) -> Self { Self::Io(error) }
}

/// A flag the coordinator sets to stop every command it owns.
pub type Cancel = Arc<AtomicBool>;

/// How a command should be run.
pub struct Spec<'a> {
    pub program: &'a Path,
    pub args: Vec<String>,
    pub cwd: &'a Path,
    pub env: Vec<(String, String)>,
    /// Appended to, never truncated: one log per stage output directory holds
    /// the whole sequence of commands a trial ran.
    pub log: &'a Path,
    /// Whether the caller wants stdout back as a string as well as logged.
    pub capture: bool,
    pub timeout: Option<Duration>,
    pub cancel: Option<Cancel>,
}

/// Runs one command to completion, killing its whole process tree on any exit.
pub fn run(spec: &Spec) -> Result<String, CommandError> {
    if spec.cancel.as_ref().is_some_and(|c| c.load(Ordering::SeqCst)) {
        return Err(CommandError::Cancelled);
    }
    if let Some(parent) = spec.log.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut log = std::fs::OpenOptions::new().create(true).append(true).open(spec.log)?;
    let log_start = log.metadata()?.len();
    writeln!(
        log,
        "+ {} {}",
        spec.program.display(),
        spec.args.iter().map(|a| quote(a)).collect::<Vec<_>>().join(" ")
    )?;

    let mut command = Command::new(spec.program);
    command.args(&spec.args).current_dir(spec.cwd).stdin(Stdio::null());
    for (key, value) in &spec.env {
        command.env(key, value);
    }
    command.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut tree = Tree::new(&mut command)?;
    let mut output = String::new();
    let mut errors = String::new();
    // Drain both pipes on their own threads: a build that fills one while we
    // block on the other deadlocks, and MWCC is chatty on stderr.
    let stdout = tree.child.stdout.take();
    let stderr = tree.child.stderr.take();
    let reader = std::thread::scope(|scope| {
        let out = scope.spawn(move || read_all(stdout));
        let err = scope.spawn(move || read_all(stderr));
        let status = wait(&mut tree, spec);
        (status, out.join().unwrap_or_default(), err.join().unwrap_or_default())
    });
    let (status, out, err) = reader;
    output.push_str(&out);
    errors.push_str(&err);

    log.write_all(output.as_bytes())?;
    log.write_all(errors.as_bytes())?;
    match &status {
        Ok(()) => {}
        Err(error) => writeln!(log, "! {error}")?,
    }
    log.flush()?;
    let log_end = log.metadata()?.len();
    status.map_err(|error| {
        error.with_evidence(CommandEvidence {
            program: spec.program.to_path_buf(),
            args: spec.args.clone(),
            log: spec.log.to_path_buf(),
            log_start,
            log_end,
            stdout_excerpt: bounded_excerpt(&output),
            stderr_excerpt: bounded_excerpt(&errors),
        })
    })?;
    Ok(if spec.capture { output } else { String::new() })
}

const EXCERPT_BYTES: usize = 4096;
const OMITTED: &str = "\n[middle output omitted; full command output is in the log]\n";

fn bounded_excerpt(output: &str) -> String {
    if output.len() <= EXCERPT_BYTES {
        return output.to_string();
    }
    let side = (EXCERPT_BYTES - OMITTED.len()) / 2;
    let mut end = side;
    while !output.is_char_boundary(end) {
        end -= 1;
    }
    let mut start = output.len() - side;
    while !output.is_char_boundary(start) {
        start += 1;
    }
    format!("{}{}{}", &output[..end], OMITTED, &output[start..])
}

fn read_all(stream: Option<impl Read>) -> String {
    let mut text = String::new();
    if let Some(mut stream) = stream {
        let mut bytes = Vec::new();
        let _ = stream.read_to_end(&mut bytes);
        text = String::from_utf8_lossy(&bytes).into_owned();
    }
    text
}

fn wait(tree: &mut Tree, spec: &Spec) -> Result<(), CommandError> {
    let started = Instant::now();
    loop {
        if let Some(status) = tree.child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(CommandError::Failed { status: status.code(), evidence: None })
            };
        }
        if spec.cancel.as_ref().is_some_and(|c| c.load(Ordering::SeqCst)) {
            tree.kill();
            return Err(CommandError::Cancelled);
        }
        if let Some(timeout) = spec.timeout
            && started.elapsed() >= timeout
        {
            tree.kill();
            return Err(CommandError::TimedOut { after: started.elapsed(), evidence: None });
        }
        // Long enough that polling costs nothing against a multi-minute link,
        // short enough that a cancelled run stops promptly.
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn quote(argument: &str) -> String {
    if argument.contains(' ') { format!("\"{argument}\"") } else { argument.to_string() }
}

/// A child process and whatever the platform needs to kill its descendants.
struct Tree {
    child: Child,
    #[cfg(windows)]
    job: windows::Job,
}

impl Drop for Tree {
    fn drop(&mut self) {
        self.kill();
        let _ = self.child.wait();
    }
}

#[cfg(windows)]
mod windows {
    use std::{io, mem, process::Command};

    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
                SetInformationJobObject,
            },
            Threading::{CREATE_NO_WINDOW, CREATE_SUSPENDED},
        },
    };

    /// A kill-on-close Job Object.
    ///
    /// Closing the handle terminates every process still assigned to the job,
    /// which is the whole point: the tree dies with the container rather than
    /// being chased process by process.
    pub struct Job(HANDLE);

    // The handle is only ever used by the thread that owns the Tree.
    unsafe impl Send for Job {}

    impl Job {
        pub fn create() -> io::Result<Self> {
            // SAFETY: null name and attributes are valid; the handle is checked.
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            let job = Self(handle);
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { mem::zeroed() };
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            // SAFETY: `info` matches the class being set and outlives the call.
            let ok = unsafe {
                SetInformationJobObject(
                    handle,
                    JobObjectExtendedLimitInformation,
                    (&raw const info).cast(),
                    mem::size_of_val(&info) as u32,
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(job)
        }

        pub fn assign(&self, process: HANDLE) -> io::Result<()> {
            // SAFETY: both handles are live for the duration of the call.
            if unsafe { AssignProcessToJobObject(self.0, process) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        pub fn close(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the handle was created by us and is closed once.
                unsafe { CloseHandle(self.0) };
                self.0 = std::ptr::null_mut();
            }
        }
    }

    impl Drop for Job {
        fn drop(&mut self) { self.close(); }
    }

    /// Starts the child suspended so it cannot spawn anything before it is in
    /// the job, then resumes it once assigned.
    pub fn configure(command: &mut Command) {
        use std::os::windows::process::CommandExt;
        command.creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW);
    }

    pub fn resume(child: &std::process::Child) -> io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        unsafe extern "system" {
            fn NtResumeProcess(handle: HANDLE) -> i32;
        }
        // SAFETY: the handle belongs to a live child we started suspended.
        let status = unsafe { NtResumeProcess(child.as_raw_handle() as HANDLE) };
        if status != 0 {
            return Err(io::Error::other(format!("NtResumeProcess failed: {status:#x}")));
        }
        Ok(())
    }

    pub fn raw_handle(child: &std::process::Child) -> HANDLE {
        use std::os::windows::io::AsRawHandle;
        child.as_raw_handle() as HANDLE
    }
}

#[cfg(windows)]
impl Tree {
    fn new(command: &mut Command) -> Result<Self, CommandError> {
        let job = windows::Job::create()?;
        windows::configure(command);
        let child = command.spawn()?;
        // Assign before resuming, so nothing the child starts escapes the job.
        job.assign(windows::raw_handle(&child))?;
        windows::resume(&child)?;
        Ok(Self { child, job })
    }

    fn kill(&mut self) {
        self.job.close();
        let _ = self.child.kill();
    }
}

#[cfg(unix)]
impl Tree {
    fn new(command: &mut Command) -> Result<Self, CommandError> {
        use std::os::unix::process::CommandExt;
        // SAFETY: setsid is async-signal-safe and valid between fork and exec.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            })
        };
        Ok(Self { child: command.spawn()? })
    }

    fn kill(&mut self) {
        // SAFETY: killing our own process group by its known id.
        unsafe { libc::killpg(self.child.id() as libc::pid_t, libc::SIGKILL) };
        let _ = self.child.kill();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec<'a>(program: &'a Path, args: &[&str], dir: &'a Path, log: &'a Path) -> Spec<'a> {
        Spec {
            program,
            args: args.iter().map(|a| a.to_string()).collect(),
            cwd: dir,
            env: Vec::new(),
            log,
            capture: true,
            timeout: None,
            cancel: None,
        }
    }

    #[cfg(windows)]
    fn shell() -> (&'static str, &'static str) { ("cmd", "/c") }
    #[cfg(unix)]
    fn shell() -> (&'static str, &'static str) { ("/bin/sh", "-c") }

    #[test]
    fn a_successful_command_returns_its_output_and_logs_it() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("build.log");
        let (program, flag) = shell();
        let output =
            run(&spec(Path::new(program), &[flag, "echo hello"], dir.path(), &log)).unwrap();
        assert!(output.contains("hello"), "{output:?}");
        let logged = std::fs::read_to_string(&log).unwrap();
        assert!(logged.contains("hello"), "{logged:?}");
        assert!(logged.starts_with('+'), "the log should record the command");
    }

    #[test]
    fn a_failing_command_reports_its_exit_status() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("build.log");
        let (program, flag) = shell();
        let error =
            run(&spec(Path::new(program), &[flag, "exit 3"], dir.path(), &log)).unwrap_err();
        assert!(matches!(error, CommandError::Failed { status: Some(3), .. }), "{error:?}");
        assert!(std::fs::read_to_string(&log).unwrap().contains("exit status 3"));
    }

    #[test]
    fn adjacent_failures_keep_their_own_output_and_log_ranges() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("build.log");
        let (program, flag) = shell();
        #[cfg(windows)]
        let first_command = "echo FIRST_ONLY 1>&2 & exit /b 3";
        #[cfg(unix)]
        let first_command = "echo FIRST_ONLY >&2; exit 3";
        #[cfg(windows)]
        let second_command = "echo SECOND_ONLY 1>&2 & exit /b 4";
        #[cfg(unix)]
        let second_command = "echo SECOND_ONLY >&2; exit 4";
        let first =
            run(&spec(Path::new(program), &[flag, first_command], dir.path(), &log)).unwrap_err();
        let second =
            run(&spec(Path::new(program), &[flag, second_command], dir.path(), &log)).unwrap_err();
        let first = first.evidence().unwrap();
        let second = second.evidence().unwrap();
        assert!(first.stderr_excerpt.contains("FIRST_ONLY"));
        assert!(!first.stderr_excerpt.contains("SECOND_ONLY"));
        assert!(second.stderr_excerpt.contains("SECOND_ONLY"));
        assert!(!second.stderr_excerpt.contains("FIRST_ONLY"));
        assert!(first.log_end <= second.log_start);
        assert_eq!(first.program, Path::new(program));
        assert_eq!(first.args, [flag, first_command]);
        let bytes = std::fs::read(&log).unwrap();
        let first_span =
            String::from_utf8_lossy(&bytes[first.log_start as usize..first.log_end as usize]);
        let second_span =
            String::from_utf8_lossy(&bytes[second.log_start as usize..second.log_end as usize]);
        assert!(first_span.contains("FIRST_ONLY") && !first_span.contains("SECOND_ONLY"));
        assert!(second_span.contains("SECOND_ONLY") && !second_span.contains("FIRST_ONLY"));
    }

    #[test]
    fn a_large_command_keeps_early_and_late_diagnostics_within_the_bound() {
        let output = format!("undefined symbol: Early\n{}\nlast error", "🦀".repeat(2000));
        let excerpt = bounded_excerpt(&output);
        assert!(excerpt.starts_with("undefined symbol: Early"));
        assert!(excerpt.ends_with("last error"));
        assert!(excerpt.len() <= EXCERPT_BYTES);
    }

    #[test]
    fn a_command_past_its_bound_times_out_rather_than_hanging() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("build.log");
        let (program, flag) = shell();
        #[cfg(windows)]
        let sleep = "ping -n 30 127.0.0.1 > nul";
        #[cfg(unix)]
        let sleep = "sleep 30";
        let mut spec = spec(Path::new(program), &[flag, sleep], dir.path(), &log);
        spec.timeout = Some(Duration::from_millis(300));
        let started = Instant::now();
        let error = run(&spec).unwrap_err();
        assert!(matches!(error, CommandError::TimedOut { .. }), "{error:?}");
        assert!(started.elapsed() < Duration::from_secs(10), "kill should be prompt");
    }

    #[test]
    fn a_cancelled_run_never_starts_the_command() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("build.log");
        let (program, flag) = shell();
        let mut spec = spec(Path::new(program), &[flag, "echo nope"], dir.path(), &log);
        spec.cancel = Some(Arc::new(AtomicBool::new(true)));
        assert!(matches!(run(&spec).unwrap_err(), CommandError::Cancelled));
        assert!(!log.exists(), "a cancelled command should not log");
    }

    #[test]
    fn the_environment_reaches_the_child() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("build.log");
        let (program, flag) = shell();
        #[cfg(windows)]
        let echo = "echo %DTK_MIGRATE_PROBE%";
        #[cfg(unix)]
        let echo = "echo $DTK_MIGRATE_PROBE";
        let mut spec = spec(Path::new(program), &[flag, echo], dir.path(), &log);
        spec.env.push(("DTK_MIGRATE_PROBE".to_string(), "seen".to_string()));
        assert!(run(&spec).unwrap().contains("seen"));
    }
}
