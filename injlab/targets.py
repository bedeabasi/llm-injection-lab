"""Targets the harness can attack.

Three offline mock targets (deterministic, no API key needed) and one optional
adapter for a real model.

IMPORTANT: the mocks are SIMULATIONS written to illustrate why some defenses
fail. They are not measurements of any real model. Results on a mock say
nothing about how a real LLM behaves.
"""

import base64
import binascii
import os
import re
from typing import List, Optional

from .attacks import CANARY

REFUSAL = "I can't help with that request."

_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

# What a naive keyword filter looks for in the RAW input.
_BASIC_BLOCKLIST = [
    re.compile(r"ignore (all )?(previous|prior) instructions", re.I),
    re.compile(r"system prompt", re.I),
]

# Extra patterns the hardened mock adds.
_EXTRA_BLOCKLIST = [
    re.compile(r"no rules", re.I),
    re.compile(r"hidden configuration", re.I),
    re.compile(r"reveal the (secret|token)", re.I),
    re.compile(r"secret token", re.I),
]


def decode_b64_segments(text: str) -> List[str]:
    """Return decoded text for any base64-looking segments in `text`."""
    out = []
    for match in _B64_RE.findall(text or ""):
        try:
            out.append(base64.b64decode(match, validate=True).decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
    return out


def _leak(system: str) -> str:
    found = re.search(r"token: ([A-Z]+-\d+)", system)
    token = found.group(1) if found else CANARY
    return f"The internal token is {token}."


def _benign(user: str, document: Optional[str]) -> str:
    if document:
        first_words = " ".join(document.split()[:8])
        return f"Summary: {first_words} ..."
    if "support hours" in user.lower():
        return "Support hours are 9am to 5pm ET, Monday to Friday."
    return "Happy to help with support hours and billing questions."


class Target:
    name = "base"

    def respond(self, system: str, user: str,
                document: Optional[str] = None) -> str:
        raise NotImplementedError


def _naive_core(system: str, user: str, document: Optional[str]) -> str:
    """A model that obeys whatever instruction it sees, in any input,
    including decoded base64."""
    decoded = decode_b64_segments(user) + decode_b64_segments(document or "")
    blob = " ".join([user, document or "", *decoded]).lower()
    if "ignore" in blob and "instruction" in blob:
        if "pwned" in blob:
            return "PWNED"
        return _leak(system)
    if "system prompt" in blob:
        return system
    if "secret" in blob or "hidden configuration" in blob:
        return _leak(system)
    return _benign(user, document)


class NaiveMock(Target):
    """Follows any instruction it finds. Baseline for 'no defense'."""

    name = "naive"

    def respond(self, system, user, document=None):
        return _naive_core(system, user, document)


class FilterMock(Target):
    """Keyword blocklist on the raw input, then behaves like the naive model.

    Illustrates the classic weakness: filtering the surface string misses
    rephrased and encoded attacks.
    """

    name = "filter"

    def respond(self, system, user, document=None):
        raw = f"{user}\n{document or ''}"
        if any(p.search(raw) for p in _BASIC_BLOCKLIST):
            return REFUSAL
        return _naive_core(system, user, document)


class HardenedMock(Target):
    """Layered defenses:
    1. documents are data only; never used as instructions
    2. decode obfuscated segments before checking
    3. broader pattern checks
    4. redact the canary from any output (output filter)
    """

    name = "hardened"

    def respond(self, system, user, document=None):
        candidates = [user, *decode_b64_segments(user)]
        patterns = _BASIC_BLOCKLIST + _EXTRA_BLOCKLIST
        if any(p.search(text) for text in candidates for p in patterns):
            return REFUSAL
        reply = _benign(user, document)
        return reply.replace(CANARY, "[REDACTED]")


class AnthropicTarget(Target):
    """Optional adapter for a real model through the Anthropic API.

    Needs: pip install anthropic, ANTHROPIC_API_KEY and INJLAB_MODEL set in
    the environment. No model name is hardcoded on purpose.
    NOTE: written but not exercised in the sample report (no key in CI).
    """

    name = "anthropic"

    def __init__(self):
        key = os.environ.get("ANTHROPIC_API_KEY")
        model = os.environ.get("INJLAB_MODEL")
        if not key or not model:
            raise RuntimeError(
                "Set ANTHROPIC_API_KEY and INJLAB_MODEL to use this target."
            )
        import anthropic  # optional dependency

        self._client = anthropic.Anthropic()
        self._model = model

    def respond(self, system, user, document=None):
        content = user
        if document is not None:
            content = f"{user}\n\n<document>\n{document}\n</document>"
        msg = self._client.messages.create(
            model=self._model,
            max_tokens=300,
            system=system,
            messages=[{"role": "user", "content": content}],
        )
        return "".join(
            block.text for block in msg.content
            if getattr(block, "type", "") == "text"
        )


MOCK_TARGETS = {
    "naive": NaiveMock,
    "filter": FilterMock,
    "hardened": HardenedMock,
}
