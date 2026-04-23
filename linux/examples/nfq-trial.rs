// reflex/linux/examples/nfq-trial.rs
//
// Geneva NFQUEUE trial runner.
// Usage (as root):
//   iptables -I OUTPUT -p tcp --dport 443 -m mark ! --mark 0xBB -j NFQUEUE --queue-num 200
//   cargo run --example nfq-trial --features nfqueue -- --domains path/to/domains.lst
//   iptables -D OUTPUT -p tcp --dport 443 -m mark ! --mark 0xBB -j NFQUEUE --queue-num 200

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use clap::Parser;
use reflex_core::command::{Command, InjectablePacket};
use reflex_core::geneva::executor;
use reflex_core::geneva::random_strategy::seed_strategies;
use reflex_core::geneva::GenevaStrategy;
use reflex_core::parse::parse_tcp_from_ip;
use reflex_core::tls::build_client_hello;
use reflex_core::types::Mac;
use reflex_linux::nfqueue::{NfqHandler, NfqPacket, NfqPipeline, NfqVerdict};

const QUEUE_NUM: u16 = 200;
const FWMARK: u32 = 0xBB;
const TIMEOUT: Duration = Duration::from_secs(5);
const DUMMY_MAC: Mac = Mac([0x00; 6]);

#[derive(Parser)]
#[command(
    name = "nfq-trial",
    about = "Test Geneva strategies against blocked domains"
)]
struct Cli {
    #[arg(long)]
    domains: String,

    #[arg(long, default_value = "10")]
    limit: usize,
}

#[derive(Debug)]
enum TrialResult {
    Success,
    Reset,
    Timeout,
    Error(String),
}

impl std::fmt::Display for TrialResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TrialResult::Success => write!(f, "OK"),
            TrialResult::Reset => write!(f, "RST"),
            TrialResult::Timeout => write!(f, "TIMEOUT"),
            TrialResult::Error(e) => write!(f, "ERR: {e}"),
        }
    }
}

struct TrialState {
    strategy: Option<GenevaStrategy>,
    applied: bool,
}

struct TrialHandler {
    state: Arc<Mutex<TrialState>>,
}

impl NfqHandler for TrialHandler {
    fn handle(&mut self, packet: &NfqPacket) -> (NfqVerdict, Vec<InjectablePacket>) {
        let mut state = self.state.lock().unwrap();

        let strategy = match (&state.strategy, state.applied) {
            (Some(s), false) => s.clone(),
            _ => return (NfqVerdict::Accept, vec![]),
        };

        let segment = match parse_tcp_from_ip(&packet.payload) {
            Some(seg) => seg,
            None => return (NfqVerdict::Accept, vec![]),
        };

        let is_hello =
            segment.payload.len() >= 6 && segment.payload[0] == 0x16 && segment.payload[5] == 0x01;

        if !is_hello {
            return (NfqVerdict::Accept, vec![]);
        }

        let commands = executor::execute(&strategy, &segment, &DUMMY_MAC, &DUMMY_MAC);
        state.applied = true;

        let mut verdict = NfqVerdict::Accept;
        let mut injects = Vec::new();

        for cmd in commands {
            match cmd {
                Command::Inject(pkt) => injects.push(pkt),
                Command::DropFlow(_) => verdict = NfqVerdict::Drop,
                Command::Accept(_) => verdict = NfqVerdict::Accept,
                _ => {}
            }
        }

        (verdict, injects)
    }
}

fn run_trial(
    domain: &str,
    strategy: Option<&GenevaStrategy>,
    state: &Arc<Mutex<TrialState>>,
) -> TrialResult {
    {
        let mut s = state.lock().unwrap();
        s.strategy = strategy.cloned();
        s.applied = false;
    }

    let addr = match format!("{domain}:443").to_socket_addrs() {
        Ok(mut addrs) => match addrs.find(|a| a.is_ipv4()) {
            Some(a) => a,
            None => return TrialResult::Error("no IPv4 address".into()),
        },
        Err(e) => return TrialResult::Error(format!("DNS: {e}")),
    };

    let mut stream = match TcpStream::connect_timeout(&addr, TIMEOUT) {
        Ok(s) => s,
        Err(e) => return classify_error(e),
    };
    let _ = stream.set_read_timeout(Some(TIMEOUT));
    let _ = stream.set_write_timeout(Some(TIMEOUT));

    let hello = build_client_hello(domain);
    if let Err(e) = stream.write_all(&hello) {
        return classify_error(e);
    }

    let mut buf = [0u8; 16];
    match stream.read(&mut buf) {
        Ok(n) if n >= 1 => TrialResult::Success,
        Ok(_) => TrialResult::Reset,
        Err(e) => classify_error(e),
    }
}

fn classify_error(e: std::io::Error) -> TrialResult {
    let msg = e.to_string();
    if msg.contains("reset") || msg.contains("refused") {
        TrialResult::Reset
    } else if msg.contains("timed out") || msg.contains("WouldBlock") {
        TrialResult::Timeout
    } else {
        TrialResult::Error(msg)
    }
}

fn main() {
    let cli = Cli::parse();

    let content = std::fs::read_to_string(&cli.domains)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", cli.domains));
    let domains: Vec<&str> = content
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    let limit = if cli.limit == 0 {
        domains.len()
    } else {
        cli.limit.min(domains.len())
    };
    let strategies = seed_strategies();

    println!(
        "Loaded {} domains, testing {} with {} strategies",
        domains.len(),
        limit,
        strategies.len()
    );

    let state = Arc::new(Mutex::new(TrialState {
        strategy: None,
        applied: false,
    }));

    let handler = TrialHandler {
        state: state.clone(),
    };

    let mut pipeline = NfqPipeline::new(QUEUE_NUM, FWMARK, handler)
        .expect("failed to create NfqPipeline (are you root?)");

    let pipeline_handle = std::thread::spawn(move || loop {
        match pipeline.step() {
            Ok(_) => {}
            Err(e) => {
                eprintln!("pipeline error: {e}");
                break;
            }
        }
        std::thread::sleep(Duration::from_micros(50));
    });

    std::thread::sleep(Duration::from_millis(100));

    for domain in &domains[..limit] {
        let baseline = run_trial(domain, None, &state);
        print!("{domain}: baseline={baseline}");

        match baseline {
            TrialResult::Success => {
                println!(" (not blocked, skip)");
                continue;
            }
            TrialResult::Error(ref e) => {
                println!(" (error: {e}, skip)");
                continue;
            }
            TrialResult::Reset | TrialResult::Timeout => {
                println!(" (BLOCKED, trying strategies...)");
            }
        }

        for (i, strategy) in strategies.iter().enumerate() {
            let result = run_trial(domain, Some(strategy), &state);
            let desc = format!("{:?}", strategy.tree);
            let short_desc = if desc.len() > 60 { &desc[..60] } else { &desc };
            print!("  strategy[{i}] {short_desc}: {result}");

            if matches!(result, TrialResult::Success) {
                println!(" *** WORKS ***");
                break;
            }
            println!();
        }
    }

    println!("\nDone. Ctrl+C to exit.");
    let _ = pipeline_handle.join();
}
