# An API client for Edgescan

---

## Index

- [Overview](#overview)
  - [Edgescan](#edgescan)
    - [Data model](#data-model)
    - [Caveats](#caveats)
- [Features](#features)
- [Installation](#installation)
  - [Environment variables](#environment-variables)
- [Testing](#testing)
  - [Code coverage](#code-coverage)
- [Docker](#docker)
  - [Building the container](#building-the-container)
  - [Exporting the container to a file](#exporting-the-container-to-a-file)
- [General usage](#general-usage)
  - [Python](#python)
    - [Search for assets](#search-for-assets)


## Overview

### Edgescan

[Edgescan](https://www.edgescan.com/) is a vulnerability management solution that allows you to identify both network and application layer vulnerabilities across a wide variety of systems.

### Data model

![Edgescan's data model](resources/images/edgescan-data-model.png)

Edgescan's data model includes:
- **Assets**: define which _hosts_ to scan for _vulnerabilities_;
- **Hosts**: represent individual computer systems (physical or virtual); and 
- **Vulnerabilities**: represent known attack vectors that may be exploited by an adversary.

### Caveats

- Since hosts and vulnerabilities are linked by location (i.e. by IP address or hostname) rather than using stronger factors such as UUIDs, any two hosts that have the same IP address or hostname will have the same vulnerabilities.

---

## Package

### Features

You can use this package to:

- List, count, and retrieve assets, hosts, licenses, and vulnerabilities;
- Export data from Edgescan in JSONL format

---

### Installation

To install the `edgescan` package (requires [`poetry`](https://github.com/python-poetry/poetry)):

```shell
$ git clone https://github.com/whitfieldsdad/edgescan-api-client.git
$ cd edgescan-api-client
$ make install
```

#### Environment variables

| Name               | Description             | Default           | Required |
|--------------------|-------------------------|-------------------|----------|
| `EDGESCAN_HOST`    | Address of Edgescan API | live.edgescan.com | false    |
| `EDGESCAN_API_KEY` | Edgescan API key        | n/a               | true     |

---

### Testing

To run the unit tests and integration tests:

```shell
$ make test
```

#### Code coverage

Code coverage reports will automatically be created in two different formats:
- HTML: `coverage/html/index.html`
- JSON: `coverage/json/coverage.json`

To view the HTML-formatted code coverage report:

```
$ open coverage/html/index.html
```

To view the JSON-formatted code coverage report:

```shell
$ cat coverage/json/coverage.json | jq
```

---

### Docker

This repository has been packaged as a Docker container! 

✨📦 🐋✨

#### Building the container

```shell
$ make build-container
```

#### Exporting the container to a file

To create a tarball `edgescan-api-client.tar.gz`:

```shell
$ make export-container
$ du -sh edgescan-api-client.tar.gz
176M    edgescan-api-client.tar.gz
```

---

### General usage

#### Command line

After installing this package you can access the command line interface as follows:

```shell
$ poetry run edgescan
Usage: edgescan [OPTIONS] COMMAND [ARGS]...

Options:
  --edgescan-host TEXT
  --edgescan-api-key TEXT
  --help                   Show this message and exit.

Commands:
  assets           Query or count assets.
  hosts            Query or count hosts.
  licenses         Query or count licenses.
  vulnerabilities  Query or count vulnerabilities.
```

##### Search for assets

You can search for assets by:
- Asset ID;
- Name;
- Tag;
- Create time; and/or
- Update time

```shell
$ poetry run edgescan assets get-assets --help
Usage: edgescan assets get-assets [OPTIONS]

  Search for assets.

Options:
  --asset-ids TEXT
  --names TEXT
  --tags TEXT
  --min-create-time TEXT
  --max-create-time TEXT
  --min-update-time TEXT
  --max-update-time TEXT
  --limit INTEGER
  --help                  Show this message and exit.
```

#### Search for hosts

You can search for hosts by:

- Asset ID;
- Host ID;
- Location (i.e. by IP address or hostname);
- Status (i.e. whether they're "dead" or "alive");
- Create time; and/or
- Update time.

```shell
$ poetry run edgescan hosts get-hosts --help
Usage: edgescan hosts get-hosts [OPTIONS]

  Search for hosts.

Options:
  --asset-ids TEXT
  --host-ids TEXT
  --locations TEXT
  --alive / --dead
  --min-create-time TEXT
  --max-create-time TEXT
  --min-update-time TEXT
  --max-update-time TEXT
  --limit INTEGER
  --help                  Show this message and exit.
```

#### Count active vs. inactive hosts

You can count active hosts like this:

```shell
$ poetry run edgescan hosts count-hosts --alive
123
```

And inactive hosts like this:

```shell
$ poetry run edgescan hosts count-hosts --dead
456
```

#### Search for vulnerabilities

You can search for vulnerabilities by:
- Vulnerability ID;
- CVE ID;
- Asset ID;
- Host ID;
- Location (i.e. by IP address or hostname);
- Status (i.e. whether the host is "dead" or "alive");
- Layer (i.e. "app" layer or "network" layer);
- Create time;
- Update time

```shell
$ poetry run edgescan vulnerabilities get-vulnerabilities --help
Usage: edgescan vulnerabilities get-vulnerabilities [OPTIONS]

  List vulnerabilities.

Options:
  --vulnerability-ids TEXT
  --cve-ids TEXT
  --asset-ids TEXT
  --host-ids TEXT
  --locations TEXT
  --alive / --dead
  --include-application-layer-vulnerabilities / --exclude-application-layer-vulnerabilities
  --include-network-layer-vulnerabilities / --exclude-network-layer-vulnerabilities
  --min-create-time TEXT
  --max-create-time TEXT
  --min-update-time TEXT
  --max-update-time TEXT
  --limit INTEGER
  --help                          Show this message and exit.
```

#### Search for licenses

Licenses are applied to assets.

You can search for licenses by:
- License ID;
- License name; and/or
- Whether the license is expired.

```shell
$ poetry run edgescan licenses get-licenses --help
Usage: edgescan licenses get-licenses [OPTIONS]

  List licenses.

Options:
  --license-ids TEXT
  --license-names TEXT
  --expired / --not-expired
  --limit INTEGER
  --help                     Show this message and exit.
```