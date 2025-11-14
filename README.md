# attest-cli

**A Command-Line Utility for Intel TDX Attestation**

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://opensource.org/licenses/MIT)

`attest-cli` is a powerful and easy-to-use command-line tool for generating and parsing attestation quotes within an Intel Trust Domain Extensions (TDX) environment. It serves as a practical interface to the underlying attestation mechanisms, allowing developers and operators to easily create and inspect evidence of a workload's integrity.

This tool is built in Rust and leverages the `aael` library from the [Confidential Containers](https://github.com/confidential-containers/attestation-agent) project.

## What is Attestation?

In a confidential computing environment like Intel TDX, attestation is the process by which a trusted execution environment (the "TD") proves its identity and the integrity of the software running inside it to a remote party (the "Relying Party"). The core artifact of this process is the **Quote**, a cryptographically signed data structure containing measurements of the TD's initial state and runtime events.

`attest-cli` simplifies the two main operations involving quotes:
1.  **Generation**: Creating a new quote that reflects the current state of the machine.
2.  **Parsing**: Decoding an existing quote to inspect its contents and verify its claims.

## Features

*   **Generate TDX Evidence**: Create a complete evidence structure, including the TDX quote and event logs.
*   **Extend Runtime Measurements**: Include custom application events in the attestation report by extending the Runtime Measurement Registers (RTMRs).
*   **Save & Print**: Save the generated quote to a file or print the full evidence to standard output.
*   **Parse and Display**: Read a base64-encoded quote from a file and display its contents in a human-readable JSON format.

## Prerequisites

*   **To generate quotes**: This tool **must be run inside an Intel TDX confidential virtual machine** that is properly configured for attestation.
*   **To parse quotes**: Parsing can be done on any system (Linux, macOS, Windows).
*   **Rust Toolchain**: You need `rustc` and `cargo` installed. You can get them from [rustup.rs](https://rustup.rs/).

## Installation

### From Source

1.  Clone the repository:
    ```bash
    git clone https://github.com/billionairiam/attest-cli.git
    cd attest-cli
    ```
2.  Build the project:
    ```bash
    cargo build --release
    ```
3.  The binary will be located at `target/release/attest-cli`. You can add this to your system's `PATH` for easier access.

## Usage

`attest-cli` is structured with subcommands. The two main commands are `quote` and `parse`.

### Getting Help

To see a full list of commands and options, use:

```bash
attest-cli --help
```

To get help for a specific subcommand:

```bash
attest-cli quote --help
attest-cli parse --help
```

---

### `quote` - Generate Attestation Evidence

This command generates new attestation evidence from within the TDX environment.

**1. Generate evidence and print to console:**

By default, the `quote` command will generate evidence and print the full JSON structure (including the quote and event logs) to standard output.

```bash
attest-cli quote
```

**2. Generate and save the quote to a file:**

Use the `-s` or `--save` flag to save the base64-encoded quote to a file.

*   Save to the default file (`quote.bin`):
    ```bash
    attest-cli quote --save
    ```

*   Save to a custom file path:
    ```bash
    attest-cli quote --save /path/to/my-quote.txt
    ```

**3. Extend RTMRs with a custom event:**

Use the `-e` or `--extend` flag to include a custom measurement in the quote. This is useful for attesting to application-specific events, like loading a configuration or a data payload. The argument must be a valid JSON string.

```bash
# Note the single quotes around the JSON to prevent shell interpretation
attest-cli quote -e '{"domain":"my-app","operation":"load-config","content":"config_file_hash_abc123"}'
```

**4. Combine options:**

You can combine flags to perform a more complex operation, such as extending the measurements and saving the resulting quote.

```bash
attest-cli quote --extend '{"domain":"web-server","operation":"start","content":"v1.2.3"}' --save server-startup.quote
```

---

### `parse` - Parse an Existing Quote

This command takes a file containing a base64-encoded quote, decodes it, and prints its contents in a human-readable format.

```bash
attest-cli parse <PATH_TO_QUOTE_FILE>
```

**Example:**

If you have a quote saved in `server-startup.quote`, you can parse it like this:

```bash
attest-cli parse server-startup.quote
```

This will output a JSON object containing the parsed fields from the quote, such as RTMR values, TCB information, and other security-critical data.

## Example Workflow

Here is a common end-to-end workflow:

1.  **Inside the TDX VM**, generate a quote that attests to starting a specific application version. Save it to a file named `app.quote`.

    ```bash
    attest-cli quote -s app.quote -e '{"domain":"billing-service","operation":"deploy","content":"sha256:f12a..."}'
    ```

2.  Transfer the `app.quote` file to an external machine for verification.

3.  **On the external machine**, parse the quote to inspect its contents.

    ```bash
    attest-cli parse app.quote
    ```

4.  The output JSON can then be used by a verifier service to check if the RTMR values match the expected measurements for the "billing-service" deployment.

## License

This project is licensed under either of

*   Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
*   MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please feel free to open an issue or submit a pull request on the [GitHub repository](https://github.com/billionairiam/attest-cli).