use serde::Serialize;
use tauri::State;
use crate::state::AppState;

/// 28 crypto algorithms with their magic number constants.
/// Each entry: (algorithm_name, &[magic_u32_values])
const CRYPTO_MAGIC_NUMBERS: &[(&str, &[u32])] = &[
    ("MD5",          &[0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE]),
    ("SHA1",         &[0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]),
    ("SHA256",       &[0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5]),
    ("SM3",          &[0x79CC4519, 0x7A879D8A]),
    ("CRC32",        &[0x77073096, 0xEE0E612C, 0xEDB88320, 0x04C11DB7]),
    ("CRC32C",       &[0x82F63B78]),
    ("ChaCha20/Salsa20", &[0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]),
    ("HMAC (generic)", &[0x36363636, 0x5C5C5C5C]),
    ("TEA",          &[0x9E3779B9]),
    ("Twofish",      &[0xBCBC3275, 0xECEC21F3, 0x202043C6, 0xB3B3C9F4]),
    ("Blowfish",     &[0x243F6A88, 0x85A308D3]),
    ("RC6",          &[0xB7E15163, 0x9E3779B9]),
    ("AES",          &[0xC66363A5, 0xF87C7C84]),
    ("APLib",        &[0x32335041]),
    ("RC4",          &[0x4F3B2B74, 0x4E27D213]),
    ("Threefish",    &[0x1B22B279, 0xAE23C8A4, 0xBC6F0C0D, 0x5E27A878]),
    ("Camellia",     &[0x4D49E62D, 0x934F19C8, 0x34E72602, 0xF75E005E]),
    ("Serpent",      &[0xC43FFF8B, 0x1D03D043, 0x1B2A04D0, 0x9AC28989]),
    ("AES_SBOX",     &[0x637C777B, 0xF26B6FC5, 0x3001672B, 0xFEFED7AB]),
    ("SHA256_K2",    &[0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5]),
    ("SHA512_IV",    &[0x6A09E667, 0xF3BCC908, 0xBB67AE85, 0x84CAA73B]),
    ("Camellia_IV",  &[0xA09E667F, 0x3BCC908B, 0xB67AE858, 0x4CAA73B2]),
    ("Whirlpool_T0", &[0x18186018, 0xC07830D8, 0x60281818, 0xD8181860]),
    ("Poly1305",     &[0xEB44ACC0, 0xD8DFB523]),
    ("DES",          &[0xFEE1A2B3, 0xD7BEF080]),
    ("DES1",         &[0x3A322A22, 0x2A223A32]),
    ("DES_SBOX",     &[0x2C1E241B, 0x5A7F361D, 0x3D4793C6, 0x0B0EEDF8]),
];

#[derive(Serialize, Clone)]
pub struct CryptoMatch {
    pub algorithm: String,
    pub magic_hex: String,
    pub seq: u32,
    pub address: String,
    pub disasm: String,
    pub changes: String,
}

#[derive(Serialize)]
pub struct CryptoScanResult {
    pub matches: Vec<CryptoMatch>,
    pub algorithms_found: Vec<String>,
    pub total_lines_scanned: u32,
    pub scan_duration_ms: u64,
}

/// Pre-compute all needle bytes (lowercase hex of each magic number).
/// Returns Vec<(algorithm, magic_hex_display, needle_bytes)>
fn build_needles() -> Vec<(&'static str, String, Vec<u8>)> {
    let mut needles = Vec::new();
    for &(algo, magics) in CRYPTO_MAGIC_NUMBERS {
        for &val in magics {
            let hex_display = format!("0x{:08X}", val);
            let needle = format!("{:x}", val).into_bytes();
            needles.push((algo, hex_display, needle));
        }
    }
    needles
}

/// Case-insensitive ASCII substring match (replicates search.rs ascii_contains)
#[inline]
fn ascii_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() { return true; }
    if needle.len() > haystack.len() { return false; }
    haystack.windows(needle.len()).any(|window| {
        window.iter().zip(needle).all(|(h, n)| h.to_ascii_lowercase() == *n)
    })
}

/// Scan a chunk of the trace file for crypto magic numbers.
fn scan_chunk(
    data: &[u8],
    start_seq: u32,
    end_seq: u32,
    start_offset: usize,
    needles: &[(&str, String, Vec<u8>)],
    trace_format: crate::taint::types::TraceFormat,
    max_matches: usize,
) -> Vec<CryptoMatch> {
    let mut matches = Vec::new();
    let mut pos = start_offset;
    let mut seq = start_seq;

    while pos < data.len() && seq < end_seq {
        let end = memchr::memchr(b'\n', &data[pos..])
            .map(|i| pos + i)
            .unwrap_or(data.len());

        let line = &data[pos..end];

        for (algo, hex_display, needle) in needles {
            if ascii_contains(line, needle) {
                if matches.len() < max_matches {
                    let parsed = match trace_format {
                        crate::taint::types::TraceFormat::Unidbg =>
                            crate::commands::browse::parse_trace_line(seq, line),
                        crate::taint::types::TraceFormat::Gumtrace =>
                            crate::commands::browse::parse_trace_line_gumtrace(seq, line),
                    };
                    if let Some(p) = parsed {
                        matches.push(CryptoMatch {
                            algorithm: algo.to_string(),
                            magic_hex: hex_display.clone(),
                            seq,
                            address: p.address,
                            disasm: p.disasm,
                            changes: p.changes,
                        });
                    }
                }
                break; // one match per line is enough
            }
        }

        pos = end + 1;
        seq += 1;
    }

    matches
}

#[tauri::command]
pub async fn scan_crypto(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<CryptoScanResult, String> {
    let start_time = std::time::Instant::now();

    let num_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    let (mmap_arc, total_lines, trace_format, chunks) = {
        let sessions = state.sessions.read().map_err(|e| e.to_string())?;
        let session = sessions.get(&session_id)
            .ok_or_else(|| format!("Session {} not found", session_id))?;
        let total_lines = session.lidx_store.as_ref().map(|s| s.total_lines()).unwrap_or(0);

        let chunks: Option<Vec<(u32, u32, usize)>> = if num_cpus > 1 && total_lines > 10000 {
            session.line_index_view().map(|li| {
                let data: &[u8] = &session.mmap;
                let num_chunks = num_cpus.min(16);
                let lines_per_chunk = (total_lines as usize + num_chunks - 1) / num_chunks;
                let mut chunks = Vec::with_capacity(num_chunks);
                for i in 0..num_chunks {
                    let start_seq = (i * lines_per_chunk) as u32;
                    if start_seq >= total_lines { break; }
                    let end_seq = ((i + 1) * lines_per_chunk).min(total_lines as usize) as u32;
                    let start_offset = li.line_byte_offset(data, start_seq).unwrap_or(0) as usize;
                    chunks.push((start_seq, end_seq, start_offset));
                }
                chunks
            })
        } else {
            None
        };

        (session.mmap.clone(), total_lines, session.trace_format, chunks)
    };

    let result = tauri::async_runtime::spawn_blocking(move || {
        let data: &[u8] = &mmap_arc;
        let needles = build_needles();
        let max_total = 10000usize;

        let all_matches = if let Some(chunks) = chunks {
            use rayon::prelude::*;
            let chunk_results: Vec<Vec<CryptoMatch>> = chunks.par_iter()
                .map(|&(start_seq, end_seq, start_offset)| {
                    scan_chunk(data, start_seq, end_seq, start_offset, &needles, trace_format, max_total)
                })
                .collect();

            let mut all = Vec::new();
            for chunk_matches in chunk_results {
                if all.len() >= max_total { break; }
                let remaining = max_total - all.len();
                all.extend(chunk_matches.into_iter().take(remaining));
            }
            all
        } else {
            scan_chunk(data, 0, total_lines, 0, &needles, trace_format, max_total)
        };

        // Collect unique algorithms found
        let mut algos: Vec<String> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for m in &all_matches {
            if seen.insert(&m.algorithm) {
                algos.push(m.algorithm.clone());
            }
        }

        CryptoScanResult {
            matches: all_matches,
            algorithms_found: algos,
            total_lines_scanned: total_lines,
            scan_duration_ms: start_time.elapsed().as_millis() as u64,
        }
    })
    .await
    .map_err(|e| format!("Scan thread panic: {}", e))?;

    Ok(result)
}
