//! The integration tests, as one binary (one link, not one per file):
//! each module was a file of its own.

mod common;

mod batch;
mod checksec;
mod data;
mod debugmap;
mod dwarf;
mod info;
mod layers;
mod licenses;
mod lines;
mod linkmap;
mod mcp;
mod pdb;
mod query;
mod readobj;
mod self_contained;
mod serve;
mod signature;
mod size;
mod snapshot;
mod targets;
mod types;
mod xref;
