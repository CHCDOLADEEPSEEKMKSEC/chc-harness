
## 3.7.1 — 16 Nov 2026
The working day's fixes, all proven on the box:

- **FIXED: page JavaScript died on a comment.** `/* ... /api/chats/*/since ... */` — the `*/` inside
  the path closed the comment early, so the rest of the sentence was parsed as code. One SyntaxError
  took the whole script down: sidebar never filled, every button dead. `node --check` proves clean now.
- **FIXED: duplicate replies.** The 6-second poller painted the stored assistant row while the reply
  was still streaming into its own bubble, and the "model:" note became the newest element so the
  content guard never matched. Now a `streaming` flag blocks polling mid-stream and the cursor jumps
  past the stored row when the stream ends. A second guard matches `.bub` (was `.bubble`, wrong class).
- **NEW: GPU media.** `/api/gen` + `/api/job` + `/media/gen/<file>`: image and short-video jobs run on
  our hired L40 through `gpu_img.py` / `video_gpu.py`, staged progress polling, delete-after-use in the
  cycle's `finally:`, plus a one-shot retry when a Thunder host never brings SSH up.
- **NEW: DEV mode** — a fourth mode in the row with a real engine-room prompt (tools enumerated, sitrep
  format, honest UP/DOWN), replacing a canned "coder mode" line that overrode the live mode.
- **FIXED: model label** says the model actually loaded (qwen3 14B), not the word "local".
- **FIXED: owner's shell** — with CHC_SHELL_NODROP=1 the tool shell no longer drops to a tenant uid via
  setpriv, which made `sudo -n` fail with "setresuid failed". Owner's box, owner's shell.
- Login: single-step magic link on the private dev build (`CHC_NO_2FA=1`), 2FA unchanged for any public
  install; session cookie still HttpOnly/SameSite=Lax.
