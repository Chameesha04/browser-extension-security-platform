# Phase 1 - Endpoint Scanner

## Purpose

The Endpoint Scanner discovers installed Chrome based and edge based browser extensions
and collects security-relevant information from each extension.

---

## Responsibilities

- Browser Discovery
- Profile Discovery
- Extension Discovery
- Manifest Parsing
- JavaScript Collection
- File Hash Generation
- JSON Export

---

## Output

The scanner produces structured Extension objects that are consumed
by the Analysis Engine.

The Endpoint Scanner does not determine whether an extension is malicious.
Its responsibility is only to collect evidence.