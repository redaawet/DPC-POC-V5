# DPC-POC-V5

Minimal offline digital payment chain proof-of-concept.

## Structure

- `dpc/` core modules (crypto, token, wallet, protocol, issuer)
- `tests/` pytest suite
- `scripts/run_demo.py` end-to-end demo

## Run

```bash
pip install -r requirements.txt
pytest
python scripts/run_demo.py
```
