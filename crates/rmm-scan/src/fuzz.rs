//! A small mutation fuzzer for the parsers' tests: seeds are flipped, truncated, spliced and
//! grown at random, deterministically (fixed seed), and each result is handed to the parser.
//! The parser must return (no panic: the sensor runs with `panic = "abort"`) and do so
//! quickly (no runaway loop), which the caller checks by the run's total time.

/// xorshift64*: deterministic, no dependency.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.max(1))
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

/// Interesting values to plant: lengths and offsets that overflow, wrap or point nowhere.
const SPECIAL: [u32; 10] = [0, 1, 0x7f, 0x80, 0xff, 0xffff, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, 0xffff_ffff];

pub fn mutate_once(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut d = seed.to_vec();
    for _ in 0..=rng.below(8) {
        match rng.below(6) {
            0 if !d.is_empty() => {
                let i = rng.below(d.len());
                d[i] ^= 1 << rng.below(8);
            }
            1 if !d.is_empty() => {
                let i = rng.below(d.len());
                d[i] = rng.next() as u8;
            }
            2 if d.len() >= 4 => {
                let i = rng.below(d.len() - 3);
                let v = SPECIAL[rng.below(SPECIAL.len())].to_le_bytes();
                d[i..i + 4].copy_from_slice(&v);
            }
            3 => d.truncate(rng.below(d.len() + 1)),
            4 if !d.is_empty() => {
                // Copy a run of the input elsewhere (repeated structures, self-references).
                let a = rng.below(d.len());
                let n = rng.below((d.len() - a).min(64)) + 1;
                let run = d[a..a + n].to_vec();
                let at = rng.below(d.len() + 1);
                d.splice(at..at, run);
            }
            _ => {
                let n = rng.below(16);
                for _ in 0..n {
                    d.push(rng.next() as u8);
                }
            }
        }
    }
    d
}

/// Runs `f` on `rounds` mutations of the seeds. Fails if the whole run takes over a minute
/// (in debug builds, where a runaway loop on any one input would show).
pub fn mutate(seeds: &[&[u8]], rounds: usize, mut f: impl FnMut(&[u8])) {
    let started = std::time::Instant::now();
    let mut rng = Rng::new(0x5eed_1234_abcd_0001);
    for s in seeds {
        f(s);
    }
    for i in 0..rounds {
        let seed = seeds[i % seeds.len()];
        let d = mutate_once(&mut rng, seed);
        f(&d);
    }
    assert!(started.elapsed() < std::time::Duration::from_secs(60), "parser too slow on hostile input: {:?}", started.elapsed());
}
