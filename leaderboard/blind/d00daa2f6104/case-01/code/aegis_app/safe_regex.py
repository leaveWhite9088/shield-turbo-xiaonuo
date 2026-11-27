# -*- coding: utf-8 -*-
"""小型 Thompson NFA 正则搜索引擎：O(len(pattern) * len(text))，无回溯炸弹。"""
from __future__ import annotations

from typing import Any


class _Parser:
    def __init__(self, pattern: str) -> None:
        self.pattern = pattern
        self.pos = 0
        self.depth = 0

    def parse(self) -> Any:
        node = self._alternation()
        if self.pos != len(self.pattern):
            raise ValueError("Unbalanced regular expression")
        return node

    def _alternation(self) -> Any:
        self.depth += 1
        if self.depth > 32:
            raise ValueError("Regular expression nesting is too deep")
        choices = [self._concat()]
        while self.pos < len(self.pattern) and self.pattern[self.pos] == "|":
            self.pos += 1
            choices.append(self._concat())
        self.depth -= 1
        return choices[0] if len(choices) == 1 else ("alt", choices)

    def _concat(self) -> Any:
        nodes = []
        while self.pos < len(self.pattern) and self.pattern[self.pos] not in ")|":
            nodes.append(self._repeat())
        if not nodes:
            return ("empty",)
        return nodes[0] if len(nodes) == 1 else ("cat", nodes)

    def _repeat(self) -> Any:
        node = self._atom()
        if self.pos >= len(self.pattern):
            return node
        char = self.pattern[self.pos]
        minimum = maximum = None
        if char == "*":
            minimum, maximum = 0, None
            self.pos += 1
        elif char == "+":
            minimum, maximum = 1, None
            self.pos += 1
        elif char == "?":
            minimum, maximum = 0, 1
            self.pos += 1
        elif char == "{":
            end = self.pattern.find("}", self.pos + 1)
            if end < 0 or end - self.pos > 12:
                raise ValueError("Invalid counted repetition")
            spec = self.pattern[self.pos + 1:end]
            parts = spec.split(",")
            try:
                minimum = int(parts[0])
                maximum = minimum if len(parts) == 1 else (None if parts[1] == "" else int(parts[1]))
            except ValueError as exc:
                raise ValueError("Invalid counted repetition") from exc
            if len(parts) > 2 or minimum < 0 or minimum > 64 or (maximum is not None and not minimum <= maximum <= 64):
                raise ValueError("Repetition exceeds the safety budget")
            self.pos = end + 1
        else:
            return node
        if self.pos < len(self.pattern) and self.pattern[self.pos] in "*+?{":
            raise ValueError("Nested repeat operators are forbidden")
        return ("rep", node, minimum, maximum)

    def _atom(self) -> Any:
        if self.pos >= len(self.pattern):
            return ("empty",)
        char = self.pattern[self.pos]
        self.pos += 1
        if char == "(":
            if self.pos < len(self.pattern) and self.pattern[self.pos] == "?":
                raise ValueError("Lookaround and inline groups are not supported")
            node = self._alternation()
            if self.pos >= len(self.pattern) or self.pattern[self.pos] != ")":
                raise ValueError("Unclosed regular expression group")
            self.pos += 1
            return node
        if char == ")":
            raise ValueError("Unexpected closing group")
        if char == ".":
            return ("any",)
        if char == "^":
            return ("start",)
        if char == "$":
            return ("end",)
        if char == "[":
            return self._character_class()
        if char == "\\":
            return self._escape(in_class=False)
        if char in "*+?{":
            raise ValueError("Repeat operator has no atom")
        return ("char", char)

    def _escape(self, *, in_class: bool) -> Any:
        if self.pos >= len(self.pattern):
            raise ValueError("Trailing regular expression escape")
        char = self.pattern[self.pos]
        self.pos += 1
        if char.isdigit() or char in "AbBZG":
            raise ValueError("Backreferences and unsupported anchors are forbidden")
        classes = {
            "d": (set("0123456789"), False),
            "w": (set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"), False),
            "s": (set(" \t\r\n\f\v"), False),
        }
        if char.lower() in classes:
            chars, _ = classes[char.lower()]
            return ("class", frozenset(chars), char.isupper())
        return ("class" if in_class else "char", char) if in_class else ("char", char)

    def _character_class(self) -> Any:
        negate = False
        if self.pos < len(self.pattern) and self.pattern[self.pos] == "^":
            negate = True
            self.pos += 1
        chars: set[str] = set()
        ranges: list[tuple[str, str]] = []
        first = True
        while self.pos < len(self.pattern):
            if self.pattern[self.pos] == "]" and not first:
                self.pos += 1
                return ("class", (frozenset(chars), tuple(ranges)), negate)
            first = False
            if self.pattern[self.pos] == "\\":
                self.pos += 1
                escaped = self._escape(in_class=True)
                if escaped[0] == "class" and isinstance(escaped[1], str):
                    start = escaped[1]
                else:
                    # \d/\w/\s 在类中展开为字符集合（范围端点不适用）。
                    if escaped[0] == "class":
                        chars.update(escaped[1])
                        continue
                    raise ValueError("Invalid character class escape")
            else:
                start = self.pattern[self.pos]
                self.pos += 1
            if self.pos + 1 < len(self.pattern) and self.pattern[self.pos] == "-" and self.pattern[self.pos + 1] != "]":
                self.pos += 1
                end = self.pattern[self.pos]
                self.pos += 1
                if end < start:
                    raise ValueError("Invalid character class range")
                ranges.append((start, end))
            else:
                chars.add(start)
        raise ValueError("Unclosed character class")


def _class_matches(spec: Any, negate: bool, char: str) -> bool:
    if isinstance(spec, frozenset):
        result = char in spec
    else:
        chars, ranges = spec
        result = char in chars or any(start <= char <= end for start, end in ranges)
    return result != negate


class _NFA:
    def __init__(self) -> None:
        # kind, payload, out_a, out_b
        self.states: list[list[Any]] = []

    def state(self, kind: str, payload: Any = None, out_a: int = -1, out_b: int = -1) -> int:
        if len(self.states) >= 512:
            raise ValueError("Compiled regular expression exceeds state budget")
        self.states.append([kind, payload, out_a, out_b])
        return len(self.states) - 1

    def compile(self, node: Any) -> tuple[int, int]:
        kind = node[0]
        if kind == "empty":
            start = self.state("eps")
            end = self.state("eps")
            self.states[start][2] = end
            return start, end
        if kind in ("char", "any", "class"):
            payload = (node[1], node[2]) if kind == "class" else (node[1] if kind == "char" else None)
            start = self.state(kind, payload)
            end = self.state("eps")
            self.states[start][2] = end
            return start, end
        if kind in ("start", "end"):
            start = self.state(kind)
            end = self.state("eps")
            self.states[start][2] = end
            return start, end
        if kind == "cat":
            fragments = [self.compile(child) for child in node[1]]
            for (_, left_end), (right_start, _) in zip(fragments, fragments[1:]):
                self.states[left_end][2] = right_start
            return fragments[0][0], fragments[-1][1]
        if kind == "alt":
            start = self.state("split")
            end = self.state("eps")
            for child in node[1]:
                child_start, child_end = self.compile(child)
                if self.states[start][2] < 0:
                    self.states[start][2] = child_start
                else:
                    split = self.state("split", out_a=self.states[start][2], out_b=child_start)
                    self.states[start][2] = split
                self.states[child_end][2] = end
            return start, end
        if kind == "rep":
            child, minimum, maximum = node[1], node[2], node[3]
            pieces: list[Any] = [child] * minimum
            if maximum is None:
                pieces.append(("star", child))
            else:
                pieces.extend(("optional", child) for _ in range(maximum - minimum))
            if not pieces:
                return self.compile(("empty",))
            return self.compile(("cat", pieces))
        if kind == "optional":
            start = self.state("split")
            end = self.state("eps")
            child_start, child_end = self.compile(node[1])
            self.states[start][2] = child_start
            self.states[start][3] = end
            self.states[child_end][2] = end
            return start, end
        if kind == "star":
            start = self.state("split")
            end = self.state("eps")
            child_start, child_end = self.compile(node[1])
            self.states[start][2] = child_start
            self.states[start][3] = end
            self.states[child_end][2] = start
            return start, end
        raise ValueError("Unsupported regular expression node")

    def search(self, start: int, text: str) -> bool:
        current: set[int] = set()
        text_len = len(text)

        def closure(seeds: set[int], position: int) -> set[int]:
            result: set[int] = set()
            stack = list(seeds)
            while stack:
                state_id = stack.pop()
                if state_id in result:
                    continue
                kind, _, out_a, out_b = self.states[state_id]
                if kind == "eps" and out_a < 0:
                    # 由 compile 返回的唯一 end 被替换为 MATCH 标记。
                    result.add(state_id)
                    continue
                result.add(state_id)
                if kind == "eps" or kind == "split":
                    if out_a >= 0:
                        stack.append(out_a)
                    if out_b >= 0:
                        stack.append(out_b)
                elif kind == "start" and position == 0 and out_a >= 0:
                    stack.append(out_a)
                elif kind == "end" and position == text_len and out_a >= 0:
                    stack.append(out_a)
            return result

        end_id = self._match_end
        for position in range(text_len + 1):
            current.add(start)
            current = closure(current, position)
            if end_id in current:
                return True
            if position == text_len:
                break
            char = text[position]
            following: set[int] = set()
            for state_id in current:
                kind, payload, out_a, _ = self.states[state_id]
                if kind == "char" and char == payload:
                    following.add(out_a)
                elif kind == "any" and char != "\n":
                    following.add(out_a)
                elif kind == "class" and _class_matches(payload[0], payload[1], char):
                    following.add(out_a)
            current = following
            if not current and position > 0:
                # 后续位置仍可能开始新的匹配，不能提前退出。
                current = set()
        return False


def safe_regex_search(pattern: str, text: str) -> bool:
    if not isinstance(pattern, str) or not isinstance(text, str):
        return False
    if len(pattern) > 256 or len(text) > 8192:
        raise ValueError("Regular expression input exceeds safety budget")
    nfa = _NFA()
    fragment_start, fragment_end = nfa.compile(_Parser(pattern).parse())
    nfa._match_end = fragment_end
    return nfa.search(fragment_start, text)
