# Bijou ✨💎✨

[![Crates.io](https://img.shields.io/crates/v/bijou)](https://crates.io/crates/bijou)
[![docs.rs](https://img.shields.io/docsrs/bijou)](https://docs.rs/bijou)

Bijou (['bi:ʒu], French for "jewel") is a tiny embeddable encrypted filesystem, built upon [RocksDB](https://github.com/facebook/rocksdb).

Bijou provides a FUSE interface, as well as Rust API (`bijou-core`) to manipulate the filesystem.

## Why Bijou?

The initial motivation of Bijou is to provide access to encrypted filesystem everywhere, without extra requirement for the host system. Most of currently available encrypted filesystems just rely on the underlying filesystem to do the most of the work (directory structure, filenames, metadata, xattrs, etc.), which both limits the portability and compromises the security.

Bijou is developed with safety and performance in mind. Almost all metadata is stored in a RocksDB database, which is extended to support at-rest encryption. Because of that, Bijou poses minimum requirement on the underlying filesystem (specifically, being able to store random-accessible regular files in directories is all we need).

In addition, an abstraction of the storage layer makes it possible to store file contents nearly everywhere, including local file system, OpenDAL (experimental) or even RocksDB itself.

## **Warning**

Bijou is under active development and is not ready for production use. It's unstable (may crash!) and on-disk format may change. **You definitely don't want to use it to store your important data for now.**

## Features

- [x] File encryption with integrity check
- [x] Cross platform filesystem features: (hard or soft) links, xattrs, file permissions
- [x] Directory structure encryption
- [x] Customizable storage layer
- [x] Rust API
- [x] Filenames with arbitrary length

Currently Bijou is only tested on Linux, but it should work on other platforms as well.

## Performance

The following benchmark is done on a 14-core Intel i7-12700H CPU with 32GB RAM and a 1T NVMe SSD.

|                | Baseline |      Bijou     |    [gocryptfs](https://github.com/rfjakob/gocryptfs)   | [Cryptomator](https://cryptomator.org) | [securefs](https://github.com/netheril96/securefs)[^1] |  [encfs](https://github.com/vgough/encfs)  |
|:----------------:|:---------------:|:-----------------:|:--------------:|:------------:|:----------------:|:-----------:|
|  Tested Version  |       N/A       |   commit 823bf69  | commit 8b1c4b0 |    v1.9.3    |      v0.14.3     |    v1.9.5   |
|     Seq Read     |     1748MB/s    |      1134MB/s     |     655MB/s    |   1084MB/s   |      643MB/s     |   342MB/s   |
|     Seq Write    |     1351MB/s    |      1251MB/s     |     506MB/s    |    605MB/s   |      169MB/s     |   137MB/s   |
|    Random Read   |     605MB/s     |      244MB/s      |     36MB/s     |    134MB/s   |      42MB/s      |    26MB/s   |
|   Random Write   |     270MB/s     |      123MB/s      |     23MB/s     |    62MB/s    |      24MB/s      |    18MB/s   |
|  untar linux-3.0 |   1.7s ± 0.03s  |    7.3s ± 2.4s    |   7.1s ± 0.3s  | 12.7s ± 0.5s |    5.1s ± 0.4s   | 7.8s ± 0.3s |
| ls -lR linux-3.0 | 115.7ms ± 2.4ms | 263.4ms ± 243.7ms |  1.3s ± 0.06s  |  2.4s ± 0.3s | 220.3ms ± 17.8ms | 2.0s ± 0.2s |

[^1]: securefs does not support O_DIRECT flag, and is tested without it

Bijou might be slower in cases where directory structure or file metadata is frequently accessed since they are stored in a separate database. However, Bijou still outperforms other filesystems in most cases.

## Security & Design

See [security](docs/security.md) and [design](docs/design.md) for more information.

## Get Involved

Bijou is still in its early stage, and there are many things to do. If you're interested in this project, check out [CONTRIBUTING.md](CONTRIBUTING.md). Any contribution is welcome!

## Installation

```bash
cargo install bijou-cli
```

## Usage

```bash
# Create a database
bijou create <data-dir>

# Mount it
bijou mount <data-dir> <mountpoint>
```

See `bijou --help` for more information.

## License

Licensed under the Apache License, Version 2.0: <http://www.apache.org/licenses/LICENSE-2.0>
