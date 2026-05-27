FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src
COPY tests ./tests
COPY datasets ./datasets
COPY docs ./docs
COPY examples ./examples
COPY scripts ./scripts
COPY Makefile requirements*.txt ./

RUN python -m pip install --no-cache-dir -e ".[all]"

CMD ["python", "-m", "hardeninspector", "--help"]

