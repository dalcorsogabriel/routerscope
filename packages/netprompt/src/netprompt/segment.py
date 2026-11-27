"""Split a terminal session into (prompt, command, output) segments."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, replace

from netprompt.constants import HUAWEI_VRP, JUNIPER_JUNOS
from netprompt.normalize import normalize
from netprompt.prompt import Mode, Prompt, detect_prompt, parse_banner
from netprompt.vendor import fingerprint_scores

_MAX_BANNER_LINES = 3


@dataclass(frozen=True, slots=True)
class Segment:
    """One command typed at a prompt and the output that followed it.

    ``line`` is the 1-based line of the prompt in the normalized text; ``output`` has no
    trailing newline; ``device`` is the resolved hostname (``None`` if unresolved).
    """

    prompt: Prompt
    command: str
    output: str
    line: int
    device: str | None


def _pick_vendor(candidates: tuple[str, ...], hint: str | None, scores: Counter[str]) -> str | None:
    if hint in candidates:
        return hint
    ranked = sorted(((scores[c], c) for c in candidates if scores[c] > 0), reverse=True)
    if not ranked or (len(ranked) > 1 and ranked[0][0] == ranked[1][0]):
        return None
    return ranked[0][1]


def _detect_all(lines: list[str]) -> dict[int, tuple[Prompt, str]]:
    detections: dict[int, tuple[Prompt, str]] = {}
    known: set[str] = set()
    for i, line in enumerate(lines):
        found = detect_prompt(line)
        if found is not None:
            detections[i] = found
            if found[0].vendor == HUAWEI_VRP and found[0].hostname:
                known.add(found[0].hostname)
    if known:
        for i, (prompt, _) in list(detections.items()):
            if prompt.vendor == HUAWEI_VRP and prompt.hostname is None:
                detections[i] = detect_prompt(lines[i], known_hostnames=known) or detections[i]
    return detections


def segment(text: str, *, vendor: str | None = None) -> list[Segment]:
    """Normalize ``text`` and split it into :class:`Segment` records.

    A segment starts at every prompt line and runs until the next prompt. Prompts with an empty
    command and no output are skipped. Ambiguous Huawei hostnames are resolved from hostnames
    seen elsewhere in the session; ambiguous IOS/OcNOS prompts get their vendor from ``vendor``
    or from fingerprints in the session. Junos ``[edit ...]`` and Nokia MD-CLI context lines
    directly above a prompt set its context (and, for MD-CLI, its mode) and are not output.
    """
    lines = normalize(text).split("\n")
    detections = _detect_all(lines)

    scores = fingerprint_scores("\n".join(lines))
    for prompt, _ in detections.values():
        if prompt.vendor:
            scores[prompt.vendor] += 1

    consumed: set[int] = set()
    prompts: dict[int, Prompt] = {}
    for idx, (prompt, _) in detections.items():
        if prompt.vendor is None:
            prompt = replace(prompt, vendor=_pick_vendor(prompt.candidates, vendor, scores))
        j = idx - 1
        while j >= 0 and j not in detections and idx - j <= _MAX_BANNER_LINES:
            banner = parse_banner(lines[j])
            if banner is None:
                break
            consumed.add(j)
            if banner.kind == "mdcli" and "md_cli" in prompt.flags:
                mode = Mode.CONFIG if banner.config else Mode.EXEC
                prompt = replace(prompt, mode=mode, context=banner.context)
            elif banner.kind == "junos_edit" and prompt.vendor == JUNIPER_JUNOS:
                prompt = replace(prompt, context=banner.context)
            j -= 1
        prompts[idx] = prompt

    order = sorted(detections)
    result: list[Segment] = []
    for n, idx in enumerate(order):
        end = order[n + 1] if n + 1 < len(order) else len(lines)
        body = [lines[k] for k in range(idx + 1, end) if k not in consumed]
        output = "\n".join(body).rstrip("\n")
        command = detections[idx][1]
        if not command and not output.strip():
            continue
        prompt = prompts[idx]
        result.append(Segment(prompt, command, output, idx + 1, prompt.hostname))
    return result
