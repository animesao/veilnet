use serde::Serialize;

/// A desync strategy preset. Ported conceptually from zapret approaches,
/// implemented natively by veilnet's eBPF desync engine.
#[derive(Debug, Clone, Serialize)]
pub struct Strategy {
    /// Stable identifier used in config
    pub id: &'static str,
    /// Human-readable name
    pub name: &'static str,
    /// Short description
    pub description: &'static str,
    /// Desync modes combined, e.g. ["fake", "multisplit"]
    pub modes: &'static [&'static str],
    /// Split position: 1 = beginning of payload
    pub split_pos: u16,
    /// Sequence overlap size (0 = disabled)
    pub seqovl: u16,
    /// Number of fake packet repeats
    pub repeats: u8,
    /// TCP fooling technique: none | badseq | badsum | ts | md5
    pub tcp_fooling: &'static str,
    /// Applied to UDP (QUIC) traffic too
    pub udp: bool,
}

pub const STRATEGIES: &[Strategy] = &[
    Strategy {
        id: "none",
        name: "None (pass-through)",
        description: "No desync. Matched traffic passes unmodified. Useful for testing rules.",
        modes: &[],
        split_pos: 0,
        seqovl: 0,
        repeats: 0,
        tcp_fooling: "none",
        udp: false,
    },
    Strategy {
        id: "multisplit",
        name: "MultiSplit",
        description: "Classic zapret approach: split TLS ClientHello into multiple segments at position 1.",
        modes: &["multisplit"],
        split_pos: 1,
        seqovl: 0,
        repeats: 0,
        tcp_fooling: "none",
        udp: false,
    },
    Strategy {
        id: "multisplit-seqovl",
        name: "MultiSplit + SeqOvl",
        description: "Split with sequence overlap pattern, like zapret's --dpi-desync-split-seqovl=681.",
        modes: &["multisplit"],
        split_pos: 1,
        seqovl: 681,
        repeats: 0,
        tcp_fooling: "none",
        udp: false,
    },
    Strategy {
        id: "fake",
        name: "Fake",
        description: "Send fake TLS/QUIC packets with wrong sequence to desynchronize DPI state.",
        modes: &["fake"],
        split_pos: 0,
        seqovl: 0,
        repeats: 6,
        tcp_fooling: "none",
        udp: true,
    },
    Strategy {
        id: "fake-aggressive",
        name: "Fake Aggressive",
        description: "Fake with 11 repeats, as in zapret's FAKE TLS AUTO strategies.",
        modes: &["fake"],
        split_pos: 0,
        seqovl: 0,
        repeats: 11,
        tcp_fooling: "none",
        udp: true,
    },
    Strategy {
        id: "fake-fakedsplit",
        name: "Fake + FakeSplit",
        description: "Fake packets combined with split, like general (ALT).bat fake,fakedsplit.",
        modes: &["fake", "fakedsplit"],
        split_pos: 1,
        seqovl: 0,
        repeats: 6,
        tcp_fooling: "ts",
        udp: false,
    },
    Strategy {
        id: "fake-multidisorder",
        name: "Fake + MultiDisorder",
        description: "Fake with disorder + badseq fooling, like general (FAKE TLS AUTO).bat.",
        modes: &["fake", "multidisorder"],
        split_pos: 1,
        seqovl: 0,
        repeats: 11,
        tcp_fooling: "badseq",
        udp: false,
    },
    Strategy {
        id: "multidisorder",
        name: "MultiDisorder",
        description: "Multiple out-of-order segments with midsld split position.",
        modes: &["multidisorder"],
        split_pos: 2, // midsld
        seqovl: 0,
        repeats: 0,
        tcp_fooling: "badseq",
        udp: false,
    },
    Strategy {
        id: "disorder",
        name: "Disorder",
        description: "Reorder segments with positive desync, minimal footprint.",
        modes: &["disorder"],
        split_pos: 1,
        seqovl: 0,
        repeats: 0,
        tcp_fooling: "none",
        udp: false,
    },
    Strategy {
        id: "split2",
        name: "Split2",
        description: "Two-segment split at position 2, low false-positive rate.",
        modes: &["multisplit"],
        split_pos: 2,
        seqovl: 0,
        repeats: 0,
        tcp_fooling: "none",
        udp: false,
    },
];

pub fn find(id: &str) -> Option<&'static Strategy> {
    STRATEGIES.iter().find(|s| s.id == id)
}

impl Strategy {
    /// Render as a veilnet TOML rule body.
    pub fn to_toml_rule(&self, cidrs: &str) -> String {
        let mut out = String::new();
        out.push_str(&format!("# {}\n", self.name));
        out.push_str(&format!("# {}\n", self.description));
        out.push_str(&format!(
            "[[rule]]\nmatch = {{ ip = [\"{}\"] }}\nstrategy = \"{}\"\n",
            cidrs, self.id
        ));
        out.push_str(&format!(
            "params = {{ split_pos = {}, seqovl = {}, repeats = {}, tcp_fooling = \"{}\", udp = {} }}\n",
            self.split_pos, self.seqovl, self.repeats, self.tcp_fooling, self.udp
        ));
        out
    }
}
