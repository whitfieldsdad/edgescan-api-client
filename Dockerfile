FROM python:3.9-slim-bullseye

RUN apt-get update
RUN apt-get -y install --no-install-recommends apt-utils gcc g++ make
RUN pip install poetry

WORKDIR /app

COPY pyproject.toml poetry.lock ./
RUN poetry install --no-root --no-dev

COPY . .
RUN poetry install --no-dev

ENTRYPOINT ["poetry", "run", "edgescan"]
