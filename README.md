
# Bijou

Bijou (['bi:ʒu], French for "jewel") is a tiny yet fast encrypted file system, built upon [RocksDB](https://github.com/facebook/rocksdb).

Bijou provides a command line interface, as well as Rust API (`bijou-core`) to manipulate the file system.

## Installation

```bash
cargo install --git https://github.com/Mivik/bijou
```

## Usage

```bash
# Create a database
bijou create <data-dir>

# Mount it
bijou mount <data-dirs> <mountpoint>
```

## License

Licensed under the Apache License, Version 2.0: <http://www.apache.org/licenses/LICENSE-2.0>
