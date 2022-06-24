# Edgescan

---

API is a vulnerability management solution that allows you to identify for both network and application layer
vulnerabilities.

## Features

- List, count, and retrieve assets, hosts, licenses, and vulnerabilities through Python or via command line

---

## Installation

To install the `edgescan` package (requires [`poetry`](https://github.com/python-poetry/poetry)):

```shell
$ git clone https://github.com/whitfieldsdad/edgescan-api-client.git
$ cd edgescan
$ make install
```

### Required environment variables

| Name               | Description             | Default           | Required |
|--------------------|-------------------------|-------------------|----------|
| `EDGESCAN_HOST`    | Address of Edgescan API | live.edgescan.com | true     |
| `EDGESCAN_API_KEY` | Edgescan API key        | n/a               | true     |

---

## Docker

This repository has been packaged as a Docker container!

### Building the container

```shell
$ make build-container
```

### Exporting the container to a file

To create a tarball `edgescan-api-client.tar.gz`:

```shell
$ make export-container
$ du -sh edgescan-api-client.tar.gz
176M    edgescan-api-client.tar.gz
```

---

## Testing

To run the unit tests and integration tests:

```shell
$ make test
```

A code coverage report will be written to `htmlcov/index.html`.

---
