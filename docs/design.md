# Bijou Design

This page illustrates the design of Bijou.

## `FileId`

Each file in Bijou is identified by a unique `FileId` (currently 64-bit unsigned integer). The underlying storage (a.k.a. `RawFileSystem`) only needs to store a mapping from `FileId` to the actual file content, which makes it easy to implement any kind of storage backend.

## `Bijou`

`Bijou` is the main interface. It provides low level operations on files, such as `open`, `rename` and `unlink`. Under the hood, it wraps a `RawFileSystem` and maintains metadata in a RocksDB database.

## `RawFileSystem`

`RawFileSystem` is the abstraction of the underlying storage. It does not account for encryption, filenames, directory structure, etc. It just simply stores file contents and metadata by `FileId`. Bijou requires `RawFileMeta` to be stored for each file, which contains three fields: file size, modification time and access time.

Here lists some implementations:

### `LocalFileSystem`

As the most basic implementation, `LocalFileSystem` stores all files in a local directory, taking their `FileId`'s first two characters as subdirectory names (git-like). For instance, file with id `deadbeef01234567` will be stored in `de/adbeef01234567`.

### `TrackingFileSystem`

Unlike `LocalFileSystem`, some filesystems are unable to store `RawFileMeta` on their own (e.g. OpenDAL). `TrackingFileSystem` is a wrapper which stores `RawFileMeta` on each modification in the database.

### `SplitFileSystem`

`SplitFileSystem` is a wrapper which splits file blocks into clusters. A cluster consists of `cluster_size` blocks, and each cluster is stored in a separate file.

When `cluster_size` is 1, each block is stored in a separate file, and thus no random read / write is needed for the underlying storage, which can be useful for filesystems who do not support efficient random read / write (e.g. OpenDAL).

On the other hand, `SplitFileSystem` can be used to hide file sizes, since files are split into clusters of the (almost) same size.

Note that `SplitFileSystem` does not store `RawFileMeta` on its own. It should be used with `TrackingFileSystem`.

### `OpenDALFileSystem` (experimental)

`OpenDALFileSystem` is a wrapper which stores file contents in OpenDAL. Currently only `memory` mode is supported.

`OpenDALFileSystem` does not support random read / write. For better performance, wrap it with `SplitFileSystem`.

### `RocksDBFileSystem`

`RocksDBFileSystem` is a wrapper which stores file in a separate RocksDB database.

`RocksDBFileSystem` does not support random read / write. For better performance, wrap it with `SplitFileSystem`.

## `BijouFs`

On top of `Bijou`, `BijouFs` provides high level API interface. It corresponds to `std::fs`. All operations are thread-safe and can be executed concurrently.

## Cryptography

See [security](../docs/security.md) for more information.
