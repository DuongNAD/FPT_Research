# AI PROMPT: HEURISTIC DETECTION ARCHITECTURE RESEARCH

**[INSTRUCTION FOR THE ASSISTANT]**
I am building a Zero-Trust Multi-Agent Malware Sandbox for identifying malicious PyPI packages. I have a problem balancing False Positives and False Negatives, and I need you to reason step-by-step and propose the most optimal, generalized implementation plan.

## Context & The Problem
We run untrusted `setup.py` packages in a Docker sandbox. We capture kernel trace logs via `sysdig` (tracking socket connections, `open`, `mmap`, `mprotect`, `chmod`, etc.). These raw logs are heavy, so we run a Python pre-filter (`smart_filter_log`) to tag logs with `[TAG_CRITICAL_THREAT]` or `[TAG_SAFE_OPERATION]` before handing them over to an LLM Judge (Gemma/Qwen) for the final "MALICIOUS" or "BENIGN" verdict.

### The Dilemma (Hardcoded Rules fail)
I recently tried to use static boolean regex rules in my Python pre-filter. It failed terribly in edge cases. Here are the 3 major failures:

1. **The "Pip Cache" False Positive (`mock-pytorch-benign`)**
   - **Scenario**: A benign PyTorch extension loads a massive ML Model cache to `/tmp/ml_cache_dir/model.bin`.
   - **Bug**: `pip` automatically unzips source code and builds the package in `/tmp/pip-req-build-xyz/setup.py`. Our Python rule caught "writing to a .py execution file in /tmp/" and instantly flagged it as a Supply Chain Attack `[TAG_CRITICAL_THREAT]`. The benign package was wrongly flagged as MALICIOUS.

2. **The "mprotect" False Positive (`requests-benign`)**
   - **Scenario**: The normal `requests` installation process cleanly runs.
   - **Bug**: Python core dynamically loads library `.so` files using `mprotect(..., PROT_READ)`. Our Python rule panicked because it saw `mprotect` and immediately tagged it `[TAG_CRITICAL_THREAT]`. The benign package was wrongly flagged as MALICIOUS.

3. **The "Fileless Evasion" False Negative (`mmap-fileless-loader` & `dev-debugger-tool`)**
   - **Scenario**: Extreme malware uses `mmap` with `PROT_EXEC` (prot=7) to inject fileless shellcode. Or it reads `/proc/self/maps` to dump memories.
   - **Bug**: Because `PROT_EXEC` gets logged as standard Linux bit flags, or because our string-matching regex was so narrow, these malicious packages completely slipped under the radar. The pre-filter added no tags, and the LLM explicitly declared them 🟢 BENIGN.

## Your Task: Propose the Ultimate Architecture
Regex and boolean IF/ELSE statements are too brittle for Cybersecurity (Tóm lại là dùng Luật tĩnh rất dễ bị lạch luật). I want to migrate `smart_filter_log` to a **Behavioral Heuristic Scoring System (Ma trận đánh giá hành vi)** combined with the LLM's natural reasoning capabilities. 

Please act as a Lead Detection Engineer. Reason logically and provide me with:
1. **A generalized Heuristic Matrix Strategy**: How to parse, group, and score Sysdig log events mathematically (e.g., scoring `+40 points` for touching `/etc/passwd`) instead of absolute tags? How to define the "Threshold" for when it transitions to LLM?
2. **Dynamic Baseline for Pip**: How do we intelligently filter out the noisy behavior of `pip` doing normal compiling (`.pyc` generation, unpacking to `/tmp/pip-build/`), while NOT filtering out a malware dropping a payload in `/tmp/malware.sh`?
3. **LLM Prompt Strategy**: How should the LLM prompt be structured to consume these "Scored Events" effectively and confidently make decisions without being paralyzed by False Positive noise?
4. **Concrete Python Approach**: Provide pseudo-code or architectural outlines for the new version of `smart_filter_log()`.

Analyze deeply. Think outside the box of traditional static signatures. I want an optimal, scalable approach.

---
## [UPDATE: SUCCESSFUL IMPLEMENTATION RESOLUTION]
This architecture has been successfully implemented and validated! 
- **Decoupled JSON Configuration**: The Heuristic matrix has been externalized to `config/heuristic_rules.json`, enabling rapid threshold and pattern updates without altering the Python source code.
- **WINE Integration**: Docker container updated with `wine64` enabling native evaluation of Windows `.exe` payloads through `chickiss-wrapper` while passing raw Sysdig events to the exact same AI multi-agent pipeline.
- **Accurate Scoring**: Successfully hit 100% Accuracy on benchmark benchmarks separating extremely evasive payloads (`ptrace`, `mprotect` manipulation) from standard Python compilations.
