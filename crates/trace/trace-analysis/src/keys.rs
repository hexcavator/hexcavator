//! What a tree's nodes are: processes, threads and frames, interned as
//! [`KeyId`]s, and how a frame's address becomes a key.

use rustc_hash::FxHashMap;

use hexcavator_trace::{ImageIx, ProcessIx, ThreadIx, Trace};

use crate::shape::{Folds, StackTags};

/// One node's identity in a tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Key {
    /// A process.
    Process(ProcessIx),
    /// A thread.
    Thread(ThreadIx),
    /// A processor.
    Cpu(u16),
    /// A frame in an image: at a function's start, at an address's offset,
    /// or (with `offset` [`Key::MODULE`]) anywhere in the image.
    Frame {
        /// The image.
        image: ImageIx,
        /// The offset in it.
        offset: u64,
    },
    /// An address in no image we know.
    Unknown(u64),
    /// A stack tag ([`Key::NO_TAG`] for stacks no tag matches).
    Tag(u32),
    /// A run of frames collapsed by a folding rule.
    Fold(u32),
    /// A call inlined into a frame's function: its site in the image's
    /// symbols.
    Inline {
        /// The image.
        image: ImageIx,
        /// The inline site.
        site: u32,
    },
}

impl Key {
    /// The offset of a [`Key::Frame`] that stands for its whole image.
    pub const MODULE: u64 = u64::MAX;
    /// The tag of stacks that no stack tag matches ("Other").
    pub const NO_TAG: u32 = u32::MAX;
}

/// An interned [`Key`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(pub u32);

/// The keys of a query.
#[derive(Clone, Debug, Default)]
pub struct Keys {
    keys: Vec<Key>,
    ids: FxHashMap<Key, KeyId>,
}

impl Keys {
    /// The ID of `key`.
    pub fn intern(&mut self, key: Key) -> KeyId {
        if let Some(&id) = self.ids.get(&key) {
            return id;
        }
        let id = KeyId(u32::try_from(self.keys.len()).expect("fewer than 4G keys"));
        self.keys.push(key);
        self.ids.insert(key, id);
        id
    }

    /// The key with `id`.
    pub fn get(&self, id: KeyId) -> Key {
        self.keys[id.0 as usize]
    }

    /// The ID of `key`, if it has one.
    pub fn find(&self, key: &Key) -> Option<KeyId> {
        self.ids.get(key).copied()
    }
}

/// How finely frames are told apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
pub enum FrameMode {
    /// By function (needs a [`Symbolizer`]; without one, by image).
    #[default]
    Function,
    /// By image: consecutive frames in the same image are one node.
    Module,
    /// By address.
    Address,
}

/// Finds the function an address is in.
pub trait Symbolizer {
    /// The start offset and name of the function at `offset` in `image`.
    fn function(&self, trace: &Trace, image: ImageIx, offset: u64) -> Option<(u64, String)>;

    /// The calls inlined at `offset` in `image`, outermost first: each
    /// one's site and inlined function's name.
    fn inlines(&self, _trace: &Trace, _image: ImageIx, _offset: u64) -> Vec<(u32, String)> {
        Vec::new()
    }

    /// The inlined function's name of an inline site.
    fn inline_name(&self, _trace: &Trace, _image: ImageIx, _site: u32) -> Option<String> {
        None
    }

    /// The source file and line of `offset` in `image`.
    fn line(&self, _trace: &Trace, _image: ImageIx, _offset: u64) -> Option<(String, u32)> {
        None
    }
}

/// A symbolizer that knows no functions.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoSymbols;

impl Symbolizer for NoSymbols {
    fn function(&self, _: &Trace, _: ImageIx, _: u64) -> Option<(u64, String)> {
        None
    }
}

/// Finds the image an address is in, for each process.
#[derive(Clone, Debug)]
pub struct Resolver {
    /// Kernel-mode images: (base, end, image), sorted by base.
    kernel: Vec<(u64, u64, ImageIx)>,
    /// Each process's images, the same way.
    user: FxHashMap<ProcessIx, Vec<(u64, u64, ImageIx)>>,
}

impl Resolver {
    /// A resolver for `trace`'s images. An address range reused by two
    /// images over time resolves to the later one.
    pub fn new(trace: &Trace) -> Self {
        let mut kernel = Vec::new();
        let mut user: FxHashMap<ProcessIx, Vec<(u64, u64, ImageIx)>> = FxHashMap::default();
        for (i, image) in trace.images.iter().enumerate() {
            let entry = (
                image.base,
                image.base.saturating_add(image.size),
                ImageIx(u32::try_from(i).expect("fewer than 4G images")),
            );
            if image.process.is_some() {
                user.entry(image.process).or_default().push(entry);
            } else {
                kernel.push(entry);
            }
        }
        // Sorted by base, later images after earlier ones at the same base.
        kernel.sort_by_key(|&(base, _, ix)| (base, ix));
        for list in user.values_mut() {
            list.sort_by_key(|&(base, _, ix)| (base, ix));
        }
        Self { kernel, user }
    }

    /// The image `address` is in, in `process`.
    pub fn image(&self, process: ProcessIx, address: u64) -> Option<ImageIx> {
        let find = |list: &[(u64, u64, ImageIx)]| {
            // The last image starting at or below the address that covers it.
            let i = list.partition_point(|&(base, _, _)| base <= address);
            list[..i]
                .iter()
                .rev()
                .take(8)
                .find(|&&(_, end, _)| address < end)
                .map(|&(_, _, ix)| ix)
        };
        self.user
            .get(&process)
            .and_then(|l| find(l))
            .or_else(|| find(&self.kernel))
    }
}

/// Turns frame addresses into keys, caching what it finds.
pub struct Framer<'a> {
    trace: &'a Trace,
    resolver: &'a Resolver,
    symbolizer: &'a dyn Symbolizer,
    mode: FrameMode,
    cache: FxHashMap<(ProcessIx, u64), Key>,
    tags: Option<StackTags>,
    folds: Folds,
    /// Each frame's stack tag and folding rule, by (process, lookup
    /// address).
    classes: FxHashMap<(ProcessIx, u64), (Option<u32>, Option<u32>)>,
    /// Each frame's inlined calls, by (process, lookup address).
    inlines: FxHashMap<(ProcessIx, u64), Vec<Key>>,
}

impl<'a> Framer<'a> {
    /// A framer for `trace`.
    pub fn new(
        trace: &'a Trace,
        resolver: &'a Resolver,
        symbolizer: &'a dyn Symbolizer,
        mode: FrameMode,
    ) -> Self {
        Self {
            trace,
            resolver,
            symbolizer,
            mode,
            cache: FxHashMap::default(),
            tags: None,
            folds: Folds::default(),
            classes: FxHashMap::default(),
            inlines: FxHashMap::default(),
        }
    }

    /// The calls inlined at a frame, outermost first, as keys (only by
    /// function).
    pub fn inline_keys(
        &mut self,
        process: ProcessIx,
        address: u64,
        return_address: bool,
    ) -> &[Key] {
        if self.mode != FrameMode::Function {
            return &[];
        }
        let lookup = if return_address {
            address.wrapping_sub(1)
        } else {
            address
        };
        let (trace, resolver, symbolizer) = (self.trace, self.resolver, self.symbolizer);
        self.inlines.entry((process, lookup)).or_insert_with(|| {
            let Some(image) = resolver.image(process, lookup) else {
                return Vec::new();
            };
            let offset = lookup - trace.images[image.index()].base;
            symbolizer
                .inlines(trace, image, offset)
                .into_iter()
                .map(|(site, _)| Key::Inline { image, site })
                .collect()
        })
    }

    /// Uses `tags` for [`crate::GroupBy::StackTag`].
    pub fn with_tags(mut self, tags: StackTags) -> Self {
        self.tags = Some(tags);
        self.classes.clear();
        self
    }

    /// Folds frames by `folds`.
    pub fn with_folds(mut self, folds: Folds) -> Self {
        self.folds = folds;
        self.classes.clear();
        self
    }

    /// Whether stack tags were given.
    pub fn has_tags(&self) -> bool {
        self.tags.is_some()
    }

    /// Whether any folding rules were given.
    pub fn has_folds(&self) -> bool {
        !self.folds.is_empty()
    }

    /// The stack tag and folding rule of the frame at `address` in
    /// `process` (by its function, whatever the frame mode).
    pub fn classify(
        &mut self,
        process: ProcessIx,
        address: u64,
        return_address: bool,
    ) -> (Option<u32>, Option<u32>) {
        let lookup = if return_address {
            address.wrapping_sub(1)
        } else {
            address
        };
        if let Some(&c) = self.classes.get(&(process, lookup)) {
            return c;
        }
        let class = match self.resolver.image(process, lookup) {
            None => (None, None),
            Some(image) => {
                let module = self.trace.images[image.index()].file_name();
                let offset = lookup - self.trace.images[image.index()].base;
                let function = self.symbolizer.function(self.trace, image, offset);
                let method = function.as_ref().map(|(_, n)| n.as_str());
                (
                    self.tags.as_ref().and_then(|t| t.frame_tag(module, method)),
                    self.folds.frame_rule(module, method),
                )
            }
        };
        self.classes.insert((process, lookup), class);
        class
    }

    /// A key's text, with the names of stack tags and folding rules.
    pub fn label(&self, key: Key) -> String {
        match key {
            Key::Tag(Key::NO_TAG) => "Other".to_string(),
            Key::Tag(t) => self
                .tags
                .as_ref()
                .filter(|tags| (t as usize) < tags.len())
                .map_or_else(|| format!("Tag {t}"), |tags| tags.name(t).to_string()),
            Key::Fold(r) => format!("[{}]", self.folds.name(r)),
            k => label(self.trace, k, self.symbolizer),
        }
    }

    /// The mode.
    pub fn mode(&self) -> FrameMode {
        self.mode
    }

    /// The key of the frame at `address` in `process`. A return address
    /// is looked up one byte back, so that a call at the end of a function
    /// is attributed to that function.
    pub fn key(&mut self, process: ProcessIx, address: u64, return_address: bool) -> Key {
        let lookup = if return_address && self.mode == FrameMode::Function {
            address.wrapping_sub(1)
        } else {
            address
        };
        if let Some(&k) = self.cache.get(&(process, lookup)) {
            return k;
        }
        let key = match self.resolver.image(process, lookup) {
            None => Key::Unknown(if self.mode == FrameMode::Address {
                address
            } else {
                0
            }),
            Some(image) => {
                let offset = lookup - self.trace.images[image.index()].base;
                let offset = match self.mode {
                    FrameMode::Address => offset,
                    FrameMode::Module => Key::MODULE,
                    FrameMode::Function => self
                        .symbolizer
                        .function(self.trace, image, offset)
                        .map_or(Key::MODULE, |(start, _)| start),
                };
                Key::Frame { image, offset }
            }
        };
        self.cache.insert((process, lookup), key);
        key
    }
}

/// A key's text, as a tree shows it.
pub fn label(trace: &Trace, key: Key, symbolizer: &dyn Symbolizer) -> String {
    match key {
        Key::Process(p) if p.is_some() => {
            let p = &trace.processes[p.index()];
            format!("{} ({})", p.name, p.pid)
        }
        Key::Process(_) => "Unknown process".to_string(),
        Key::Thread(t) if t.is_some() => {
            let t = &trace.threads[t.index()];
            match &t.name {
                Some(n) => format!("Thread {} ({n})", t.tid),
                None => format!("Thread {}", t.tid),
            }
        }
        Key::Thread(_) => "Unknown thread".to_string(),
        Key::Cpu(c) => format!("CPU {c}"),
        Key::Frame { image, offset } => {
            let name = trace.images[image.index()].file_name();
            if offset == Key::MODULE {
                return format!("{name}!<module>");
            }
            match symbolizer.function(trace, image, offset) {
                Some((start, f)) if start == offset => format!("{name}!{f}"),
                Some((start, f)) => format!("{name}!{f}+{:#x}", offset - start),
                None => format!("{name}+{offset:#x}"),
            }
        }
        Key::Unknown(0) => "?".to_string(),
        Key::Unknown(a) => format!("{a:#x}"),
        Key::Tag(Key::NO_TAG) => "Other".to_string(),
        Key::Tag(t) => format!("Tag {t}"),
        Key::Fold(r) => format!("Fold {r}"),
        Key::Inline { image, site } => {
            let name = trace.images[image.index()].file_name();
            match symbolizer.inline_name(trace, image, site) {
                Some(f) => format!("{name}!{f} (inlined)"),
                None => format!("{name}!<inline site {site}>"),
            }
        }
    }
}
