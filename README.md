# CogitSec: Advanced Network Login Cracker with Rust GTK GUI

CogitSec is a modern, high-performance network login cracker built entirely in Rust with a GTK-based graphical interface. This single-language approach leverages Rust's safety, performance, and concurrency advantages while providing a consistent development experience throughout the application.

## Features

- **Multi-protocol Support**: SSH, FTP, HTTP(S), SMTP, SMB, MySQL, PostgreSQL, and other common protocols
- **Parallel Processing**: Utilize Rust's ownership model and thread safety for efficient concurrent login attempts
- **Smart Attack Optimization**: Adaptive timing and throttling to avoid triggering account lockouts or detection
- **Session Management**: Save, pause, and resume attack sessions
- **Real-time Statistics Dashboard**: Visual representation of attempts, successes, and progress
- **Intelligent Word Mangling**: Create password variations based on common patterns
- **Target Profiling**: Automatic service fingerprinting and tailored attack strategies
- **Export Capabilities**: Generate comprehensive reports in multiple formats

## Architecture Overview

CogitSec is built with a unified Rust codebase:

- **Unified Rust Codebase**: Full application written in Rust using gtk-rs for the GUI components
- **Engine Core**: Optimized Rust modules handling all security operations and networking
- **GUI Layer**: GTK interface built directly with Rust bindings

## Getting Started

### Prerequisites

- Rust 1.67.0 or higher
- GTK 4.8 or higher
- libadwaita 1.2 or higher

### Building from Source

1. Clone the repository:

```bash
git clone https://github.com/username/cogitsec.git
cd cogitsec
```

2. Build the project:

```bash
cargo build --release
```

3. Run the application:

```bash
cargo run --release
```

## Usage

1. **Configure Target**: Enter the target information and protocol.
2. **Select Wordlists**: Choose username and password lists or create them in the Wordlist Manager.
3. **Configure Attack Options**: Set concurrency, delays, and other attack parameters.
4. **Launch Attack**: Start the attack and monitor progress in real-time.
5. **View Results**: Check discovered credentials and export them to various formats.

## Advanced Features

- **Proxy Chain Support**: Route attacks through SOCKS, HTTP proxies or TOR for anonymity
- **Custom Rule Engine**: Create complex custom attack patterns with a visual rule builder
- **Distributed Attack Mode**: Coordinate attacks across multiple systems for larger targets
- **Auto-Reconnaissance**: Integrated port scanning and service discovery before launching attacks
- **Credential Harvesting**: Extract and reuse discovered credentials across multiple services
- **Advanced Password Analytics**: Analyze target password policies to optimize wordlists

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for educational and ethical testing purposes only. Always ensure you have explicit permission before testing any system that you do not own. Unauthorized testing may violate laws and regulations. 