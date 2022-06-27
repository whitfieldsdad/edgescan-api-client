.PHONY: coverage

CONTAINER_NAME="edgescan-api-client"
CONTAINER_REGISTRY_HOST="localhost:5000"

all: clean build

clean:
	rm -rf dist

app: install

build:
	poetry build

install:
	poetry install

update:
	poetry show -o
	poetry update
	poetry export -f requirements.txt -o requirements.txt --without-hashes
	poetry show --tree

test:
	poetry run coverage run -m pytest --durations=0

coverage:
	poetry run coverage json -o coverage/json/coverage.json --pretty-print
	poetry run coverage html -d coverage/html

release:
	poetry publish

container: build-container

build-container:
	docker build -t $(CONTAINER_NAME):latest .

export-container:
	docker save $(CONTAINER_NAME):latest | gzip > $(CONTAINER_NAME).tar.gz

push-container:
	docker push $(CONTAINER_REGISTRY_HOST)/$(CONTAINER_NAME):latest
