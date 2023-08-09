# qualysx
Fast and reliable rust implementation of xml to json parser for qualys scans.

:arrow_right: [ddt file](https://qualysguard.qg2.apps.qualys.eu/scan-1.dtd)

## Installation

| Environment | CLI command |
|-------------|-------------|
| Cargo (Rust 1.59+) | `cargo install qualysx` |

On Windows, Linux, and macOS, you can use the
[pre-built binaries](https://github.com/marcuccio/qualysx/releases).

## How to use it

```bash
qualysx -x qualys_report.xml > out.json
[WRN] Use with caution. You are responsible for your actions.
[WRN] Developers assume no liability and are not responsible for any misuse or damage.
```

## ... or use qualysx in your projects

Add qualysx as dependency
`cargo add qualysx`

```rust
use qualysx::from_str;

fn main() {

    let file: String = std::fs::read_to_string(xml).unwrap();
    let scan: qualysx::Scan = qualysx::from_str(&file).unwrap();
    let j = serde_json::to_string(&scan).unwrap();
    
    println!("{}", j);
}
````

# Contribute

Contributions are always welcome! Please create a PR to add Github Profile.

## :pencil: License

This project is licensed under [GPL-3.0](https://opensource.org/license/gpl-3-0/) license.

## :man_astronaut: Show your support

Give a ⭐️ if this project helped you!
