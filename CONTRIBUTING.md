# Contributing

Thanks for your interest! This is primarily a personal portfolio project, but contributions are welcome.

## Getting Started

1. Fork the repository and clone your fork.
2. Create and activate a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Run the test suite to confirm your environment is set up:
   ```bash
   pytest -v
   ```
5. Try a demo run:
   ```bash
   python main.py --demo
   ```

## Submitting Changes

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature
   ```
2. Make focused, well-described commits.
3. Make sure the test suite passes locally before pushing.
4. Open a pull request against `main` with a clear description of what you changed and why. Reference any related issues.

## Code Style

- Follow PEP 8 for Python code.
- Add tests for any new behavior — especially detection rules and ML pipeline changes.
- Use only synthetic / RFC 1918 / IANA-reserved IP ranges in any new sample data.
- Update the README if user-facing behavior changes.
- Keep changes focused — one PR, one concern.
