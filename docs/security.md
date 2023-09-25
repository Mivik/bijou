
# Bijou Security Model

This page illustrates the security model of Bijou.

## Key Derivation

Master key is 256-bits, which is generated from user password using `argon2id`. Four keys are then derived in order using `blake2b`:

0. `config_key` (256 bits): used to encrypt Bijou configuration;
1. `content_key` (256 bits): used to further derive keys for file encryption;
2. `file_name_key` (256 bits): used to optionally encrypt filenames;
3. `db_key` (256 bits): used to encrypt database.

## Database Encryption

Bijou patched RocksDB to support at-rest database encryption. In particular, a custom filesysytem layer is implemented. It encrypts all database files in 4096-bytes blocks, storing extra authentication information in a separate file (`[filename].meta`). Currently, the algorithm is XSalsa20, where IVs are re-generated on each write.

## Configuration Storage

A `keystore.json` is stored in plaintext, containing necessary information to retrieve the master key using password. Bijou's configuration is stored in `config.json`, which is encrypted using `config_key`.

## Content Encryption

Each file has a unique encryption key (derived from `content_key`). Files are segmented into blocks (4096 bytes by default). On each modification, a new IV is generated, the block gets encrypted, prepended with header and appended with tag. Header and tag are algorithm-specific. For instance, `AES-256-GCM` uses 12-bytes IV as header and 16-bytes authentication tag.

In order to be compatible with file holes, Bijou uses IVs to distinguish between normal content and holes. Bijou will avoid generating zero IVs, and if a underlying block's IV is all zeros, Bijou knows that it is a hole.

## Filename Encryption

Though filenames are already encrypted at the phase of database encryption, Bijou provides an option to encrypt filenames using `file_name_key` anyway. Under this mode, filenames are encrypted using `XChaCha20-SIV`. Files in different directories are encrypted using different IVs, so that the same filename in different directories will not be the same.
