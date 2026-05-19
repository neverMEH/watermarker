PY := .venv/bin/python
PIP := .venv/bin/pip

.PHONY: help venv install test demo backend clean

help:
	@echo "Watermark MVP — make targets:"
	@echo "  venv      create .venv/"
	@echo "  install   install Python deps into .venv"
	@echo "  test      run the test suite"
	@echo "  demo      end-to-end demo (artifacts under ./artifacts/)"
	@echo "  backend   start the backend on 127.0.0.1:8765"
	@echo "  clean     remove artifacts/, .venv/, *.db"

venv:
	python3 -m venv .venv
	$(PIP) install --upgrade pip wheel setuptools

install: venv
	$(PIP) install -e .[dev]

test:
	$(PY) -m pytest -q tests/

demo:
	$(PY) scripts/demo.py

backend:
	WATERMARK_ADMIN_TOKEN?=$(shell openssl rand -hex 16) \
	$(PY) -m watermark_mvp.backend.run

clean:
	rm -rf artifacts/ *.db .pytest_cache
