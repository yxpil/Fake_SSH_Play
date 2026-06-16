#!/usr/bin/env python3
"""ffmpeg downscale → pipe raw RGB → ASCII txt, one frame per picture, separated."""
import subprocess
import sys

VIDEO = "/Users/zhenhun/Downloads/FakeSSHPLAY2/FAKESSH.mp4"
OUT   = "/Users/zhenhun/Downloads/FakeSSHPLAY2/FAKESSH.txt"
COLS  = 100
CHARS = "@%#*+=-:. "  # dark → light (len=10)

def main():
    # Step 1: probe height with ffprobe
    import json
    probe = subprocess.run([
        "ffprobe", "-v", "error", "-select_streams", "v:0",
        "-show_entries", "stream=width,height",
        "-of", "json", VIDEO
    ], capture_output=True, text=True)
    info = json.loads(probe.stdout)
    w, h = info["streams"][0]["width"], info["streams"][0]["height"]
    new_h = max(int(h * COLS / w * 0.5), 1)  # 0.5 for char aspect
    print(f"Source: {w}x{h} → ASCII: {COLS}×{new_h} chars", file=sys.stderr)

    # Step 2: ffmpeg pipe — downscale to COLS×h2, raw RGB24
    cmd = [
        "ffmpeg", "-loglevel", "error",
        "-i", VIDEO,
        "-f", "rawvideo",
        "-pix_fmt", "rgb24",
        "-vf", f"fps=fps=30,scale={COLS}:{new_h}",
        "pipe:1"
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    frame_bytes = COLS * new_h * 3
    buf = bytearray(frame_bytes)
    
    with open(OUT, "w", encoding="utf-8") as f:
        n = 0
        sep = f"\n{'='*COLS}\n=== FRAME {{n:05d}} ===\n{'='*COLS}\n"
        while True:
            view = memoryview(buf)
            total = 0
            while total < frame_bytes:
                chunk = proc.stdout.read1(frame_bytes - total)
                if not chunk:
                    break
                view[total:total+len(chunk)] = chunk
                total += len(chunk)
            if total < frame_bytes:
                break
            
            # Convert raw RGB to ASCII (no PIL — direct, fast)
            lines = []
            for y in range(new_h):
                row_start = y * COLS * 3
                line_chars = []
                for x in range(COLS):
                    off = row_start + x * 3
                    r, g, b = buf[off], buf[off+1], buf[off+2]
                    gray = (r * 299 + g * 587 + b * 114) // 1000
                    idx = gray * (len(CHARS) - 1) // 255
                    line_chars.append(CHARS[idx])
                lines.append("".join(line_chars))
            
            f.write(sep.format(n=n))
            f.write("\n".join(lines))
            f.write("\n")
            n += 1
            if n % 200 == 0:
                print(f"  {n} frames...", file=sys.stderr, flush=True)

    proc.terminate()
    print(f"Done! {n} frames → {OUT}", file=sys.stderr)

if __name__ == "__main__":
    main()
