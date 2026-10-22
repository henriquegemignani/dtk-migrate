//! Opt-in tracing for finding where a run spends its time.
//!
//! Set `DTK_MIGRATE_PROFILE=<prefix>` and the run writes `<prefix>.spans.tsv`
//! (labelled intervals on the process clock) and, on Windows,
//! `<prefix>.samples.tsv` (stack samples of every thread). Both share one
//! clock, so a sample can be attributed to the span and phase it fell in.

use std::{
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};

type Samples = Vec<(f64, u32, Vec<u64>)>;

struct Recorder {
    start: Instant,
    prefix: String,
    spans: Mutex<Vec<(u32, f64, f64, String)>>,
    stop: AtomicBool,
    sampler: Mutex<Option<std::thread::JoinHandle<Samples>>>,
}

static RECORDER: OnceLock<Recorder> = OnceLock::new();

/// Starts recording when `DTK_MIGRATE_PROFILE` is set.
pub fn init() {
    let Some(prefix) = std::env::var_os("DTK_MIGRATE_PROFILE") else { return };
    let recorder = Recorder {
        start: Instant::now(),
        prefix: prefix.to_string_lossy().into_owned(),
        spans: Mutex::new(Vec::new()),
        stop: AtomicBool::new(false),
        sampler: Mutex::new(None),
    };
    if RECORDER.set(recorder).is_err() {
        return;
    }
    #[cfg(windows)]
    {
        let recorder = RECORDER.get().unwrap();
        let hz: f64 = std::env::var("DTK_MIGRATE_PROFILE_HZ")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(50.0);
        let handle = std::thread::Builder::new()
            .name("profile-sampler".into())
            .spawn(move || sampler::run(recorder.start, &recorder.stop, hz))
            .expect("spawn sampler");
        *recorder.sampler.lock().unwrap() = Some(handle);
    }
}

pub fn thread_id() -> u32 {
    #[cfg(windows)]
    {
        unsafe { windows_sys::Win32::System::Threading::GetCurrentThreadId() }
    }
    #[cfg(not(windows))]
    {
        0
    }
}

/// Records an interval that began at `begin` and ends now.
pub fn record(label: impl FnOnce() -> String, begin: Instant) {
    let Some(recorder) = RECORDER.get() else { return };
    let from = begin.saturating_duration_since(recorder.start).as_secs_f64();
    let to = recorder.start.elapsed().as_secs_f64();
    recorder.spans.lock().unwrap().push((thread_id(), from, to, label()));
}

/// Stops sampling and writes the trace files.
pub fn finish() {
    let Some(recorder) = RECORDER.get() else { return };
    recorder.stop.store(true, Ordering::SeqCst);
    let end = recorder.start.elapsed().as_secs_f64();
    let spans = recorder.spans.lock().unwrap();
    let mut text = format!("0\t0.0000\t{end:.4}\ttotal\n");
    for (tid, from, to, label) in spans.iter() {
        text.push_str(&format!("{tid}\t{from:.4}\t{to:.4}\t{label}\n"));
    }
    let _ = std::fs::write(format!("{}.spans.tsv", recorder.prefix), text);
    #[cfg(windows)]
    if let Some(handle) = recorder.sampler.lock().unwrap().take()
        && let Ok(samples) = handle.join()
    {
        sampler::write(&format!("{}.samples.tsv", recorder.prefix), &samples);
    }
}

#[cfg(windows)]
mod sampler {
    use std::{
        collections::HashMap,
        ffi::c_void,
        sync::atomic::{AtomicBool, Ordering},
        time::{Duration, Instant},
    };

    use windows_sys::Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::{
            Diagnostics::{
                Debug::{
                    CONTEXT, GetThreadContext, RtlLookupFunctionEntry, RtlVirtualUnwind,
                    SYMBOL_INFOW, SYMOPT_DEFERRED_LOADS, SYMOPT_UNDNAME, SymFromAddrW,
                    SymInitializeW, SymSetOptions,
                },
                ToolHelp::{
                    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First,
                    Thread32Next,
                },
            },
            LibraryLoader::GetModuleHandleW,
            Threading::{
                GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, OpenThread,
                ResumeThread, SuspendThread, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
                THREAD_SUSPEND_RESUME,
            },
        },
    };

    const CONTEXT_AMD64: u32 = 0x0010_0000;
    const CONTEXT_FULL: u32 = CONTEXT_AMD64 | 0x1 | 0x2;
    const MAX_FRAMES: usize = 160;

    fn threads() -> Vec<u32> {
        let mut ids = Vec::new();
        unsafe {
            let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snapshot.is_null() || snapshot as isize == -1 {
                return ids;
            }
            let mut entry: THREADENTRY32 = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
            let pid = GetCurrentProcessId();
            let mut more = Thread32First(snapshot, &mut entry) != 0;
            while more {
                if entry.th32OwnerProcessID == pid {
                    ids.push(entry.th32ThreadID);
                }
                more = Thread32Next(snapshot, &mut entry) != 0;
            }
            CloseHandle(snapshot);
        }
        ids
    }

    /// Walks the suspended thread's stack into `frames` without allocating:
    /// the thread may hold the heap lock.
    unsafe fn capture(handle: HANDLE, frames: &mut [u64; MAX_FRAMES]) -> usize {
        unsafe {
            let mut context: CONTEXT = std::mem::zeroed();
            context.ContextFlags = CONTEXT_FULL;
            if GetThreadContext(handle, &mut context) == 0 {
                return 0;
            }
            let mut count = 0;
            while count < MAX_FRAMES {
                let pc = context.Rip;
                if pc == 0 {
                    break;
                }
                frames[count] = pc;
                count += 1;
                let mut base = 0u64;
                let entry = RtlLookupFunctionEntry(pc, &mut base, std::ptr::null_mut());
                if entry.is_null() {
                    // A leaf function: the return address is on top of the stack.
                    let sp = context.Rsp as *const u64;
                    if sp.is_null() {
                        break;
                    }
                    context.Rip = *sp;
                    context.Rsp += 8;
                } else {
                    let mut handler_data: *mut c_void = std::ptr::null_mut();
                    let mut establisher = 0u64;
                    RtlVirtualUnwind(
                        0,
                        base,
                        pc,
                        entry,
                        &mut context,
                        &mut handler_data,
                        &mut establisher,
                        std::ptr::null_mut(),
                    );
                }
            }
            count
        }
    }

    pub fn run(start: Instant, stop: &AtomicBool, hz: f64) -> super::Samples {
        let period = Duration::from_secs_f64(1.0 / hz);
        let own = unsafe { GetCurrentThreadId() };
        let mut samples = Vec::new();
        let mut frames = [0u64; MAX_FRAMES];
        let mut next = Instant::now();
        while !stop.load(Ordering::SeqCst) {
            next += period;
            let tick = start.elapsed().as_secs_f64();
            for tid in threads() {
                if tid == own {
                    continue;
                }
                unsafe {
                    let handle = OpenThread(
                        THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                        0,
                        tid,
                    );
                    if handle.is_null() {
                        continue;
                    }
                    let mut count = 0;
                    if SuspendThread(handle) != u32::MAX {
                        count = capture(handle, &mut frames);
                        ResumeThread(handle);
                    }
                    CloseHandle(handle);
                    if count > 0 {
                        samples.push((tick, tid, frames[..count].to_vec()));
                    }
                }
            }
            let now = Instant::now();
            if next > now {
                std::thread::sleep(next - now);
            } else {
                next = now;
            }
        }
        samples
    }

    fn symbolize(addresses: impl Iterator<Item = (u64, bool)>) -> HashMap<u64, String> {
        let mut names = HashMap::new();
        unsafe {
            let process = GetCurrentProcess();
            SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
            SymInitializeW(process, std::ptr::null(), 1);
            const NAME: usize = 512;
            // Addresses inside this executable are written as `exe+0xRVA` and
            // resolved afterwards against its PDB; dbghelp does not find the
            // Rust PDB reliably.
            let base = GetModuleHandleW(std::ptr::null()) as u64;
            let e_lfanew = *((base + 0x3c) as *const u32) as u64;
            let size = *((base + e_lfanew + 0x50) as *const u32) as u64;
            let mut buffer = vec![0u8; std::mem::size_of::<SYMBOL_INFOW>() + NAME * 2];
            for (address, leaf) in addresses {
                let info = buffer.as_mut_ptr() as *mut SYMBOL_INFOW;
                (*info).SizeOfStruct = std::mem::size_of::<SYMBOL_INFOW>() as u32;
                (*info).MaxNameLen = NAME as u32;
                // Return addresses point past the call; look up the call itself.
                if address >= base && address < base + size {
                    names.insert(address, format!("exe+0x{:x}", address - base - u64::from(!leaf)));
                    continue;
                }
                let lookup = if leaf { address } else { address - 1 };
                let mut displacement = 0u64;
                let name = if SymFromAddrW(process, lookup, &mut displacement, info) != 0 {
                    let len = (*info).NameLen as usize;
                    let chars = std::slice::from_raw_parts((*info).Name.as_ptr(), len.min(NAME));
                    String::from_utf16_lossy(chars)
                } else {
                    format!("0x{address:x}")
                };
                names.insert(address, name.replace([';', '\t', '\n'], "_"));
            }
        }
        names
    }

    pub fn write(path: &str, samples: &super::Samples) {
        let mut seen: HashMap<u64, bool> = HashMap::new();
        for (_, _, frames) in samples {
            for (index, &address) in frames.iter().enumerate() {
                *seen.entry(address).or_insert(false) |= index == 0;
            }
        }
        // An address may be a leaf in one sample and a return address in
        // another; the one-byte difference rarely changes the function, so one
        // lookup per address is enough.
        let names = symbolize(seen.into_iter());
        let mut text = String::new();
        for (tick, tid, frames) in samples {
            let stack: Vec<&str> =
                frames.iter().rev().map(|a| names.get(a).map_or("?", String::as_str)).collect();
            text.push_str(&format!("{tick:.4}\t{tid}\t{}\n", stack.join(";")));
        }
        let _ = std::fs::write(path, text);
    }
}
