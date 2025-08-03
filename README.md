# Togi C++ Client

This repository provides two standalone C++ command-line clients for posting **decisions** and **reports** to a [Togi](https://togi-app.com) project.

Togi lets you add human-in-the-loop decision making to your automation workflows — these C++ tools let you interface with the Togi REST API directly.

---

## Dependencies (Debian / Ubuntu)

Install the required packages:

```bash
sudo apt install build-essential libcurl4-openssl-dev libssl-dev nlohmann-json3-dev
```

These packages provide:

- C++ compiler and standard library
- `libcurl` for making HTTP requests
- `OpenSSL` for HMAC and signature generation
- `nlohmann/json` for working with JSON

---

## Build Instructions

This repository contains two source files:

- `togi-decision.cpp`: Sends a decision payload
- `togi-report.cpp`: Sends a report payload

Both have been tested on Debian and Ubuntu.

### ▶️ Build the Decision Client

```bash
g++ togi-decision.cpp -o togi-decision -lcurl -pthread -lssl -lcrypto
```

### ▶️ Build the Report Client

```bash
g++ togi-report.cpp -o togi-report -lcurl -pthread -lssl -lcrypto
```

---

## Usage

Run the compiled programs directly:

```bash
./togi-decision
```

or

```bash
./togi-report
```

The programs will prompt for necessary inputs.

---

## Support

Need help, want to report a bug, or have feedback?

Contact us at: [support@togi-app.com](mailto:support@togi-app.com)

---

## 📝 License

MIT License

Copyright (c) 2025 Togi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights  
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell  
copies of the Software, and to permit persons to whom the Software is  
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in  
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR  
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,  
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE  
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER  
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING  
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS  
IN THE SOFTWARE.
