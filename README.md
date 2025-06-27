# Code Detective

## Overview

`Code Detective` is a Python-based security scanner that analyzes C and C++ source code for common vulnerabilities such as buffer overflows, unsafe pointer dereferencing, memory risks, and other potential security issues. The script uses regular expressions to detect potential security flaws in the code, and it can also integrate with external static analysis tools like `cppcheck` for deeper analysis.

## Features

- Scans C and C++ source code files for various security risks.
- Detects potential **buffer overflows**, **unsafe pointer dereferencing**, **memory risks**, and **integer overflow**.
- Integrates with external tools like `cppcheck` for additional static analysis.
- Analyzes for potential **code injection vulnerabilities**.
- Can scan individual files or entire directories.

## Usage

You can use the `Code Detective` either directly through Python or via Docker. Below are the instructions for both methods.

### 1. Running with Python

#### Prerequisites:
- Python 3.x
- Install `cppcheck` if you want to use external static analysis (Linux: `sudo apt-get install cppcheck`)

#### Running the Script:

To scan a single C or C++ file, run:

```bash
python3 code_detective.py /path/to/your/c/source/file.c
```

To scan an entire directory, run:

```bash
python3 code_detective.py /path/to/your/c/source/directory
```

### 2. Running with Docker

#### Prerequisites:
- Docker installed on your system

#### Building the Docker Image:

Build the Docker image by running:

```bash
docker build -t code-detective .
```

#### Running the Container:

To scan a single C or C++ file, run:

```bash
docker run -it -v /path/to/your/c/source:/app code-detective /app/file.c
```

To scan an entire directory, run:

```bash
docker run -it -v /path/to/your/c/source:/app code-detective /app/
```

### 3. Output

The script will output a detailed report of any detected security risks in the source code. The output will display the following information for each risk:

- The file and line number where the risk was detected.
- A description of the risk (e.g., buffer overflow, pointer dereferencing).
- Any specific matches for the identified risk.

Example output:

```
=== ADVANCED C/C++ SECURITY ANALYSIS REPORT ===

[FILE] /app/file.c
  BUFFER_OVERFLOWS RISKS:
    - Line 45: strcpy(buffer, input);
      Specific Matches: ['strcpy']
  POINTER_RISKS:
    - Line 52: *ptr = value;
      Specific Matches: ['*']
```

## Project Structure

```
/code_detective
│
├── Dockerfile             # Dockerfile for containerization
├── code_detective.py      # Python script for scanning C/C++ code
├── test.c                 # Vulnerable C Code for testing
└── README.md              # This README file
└── LICENSE                # The project license
```

## Contributing

Contributions are welcome! Please fork this repository and submit a pull request with any improvements or bug fixes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
