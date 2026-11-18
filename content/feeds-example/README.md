# Feed format examples

Tiny files in each format `rmm-sign build-db` imports, for its tests and as a template. Every
hash here is made up or is the EICAR test file's; no real feed data is kept in the repository.
Real feeds are downloaded by whoever builds the database, and whether an MSP may use one
commercially is theirs to check:

- `--sha256`: abuse.ch MalwareBazaar exports (CC0): the plain `sha256_hashes.txt` list or the
  CSV dump (`malwarebazaar.csv` shows the layout). Any list of SHA-256 hashes, one per line,
  optionally followed by a name, works too (`plain.sha256`).
- `--yara`: YARA rule files or directories, for example the YARA Forge packages
  (`forge-example.yar`). Each rule keeps its own `license`/`author`/`reference` meta, which the
  console shows; imported rules run in audit mode.
- `--clamav`: ClamAV hash signatures, `.hdb` (MD5) and `.hsb` (SHA-1 or SHA-256).
