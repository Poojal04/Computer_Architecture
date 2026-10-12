# CS422 Assignment 2 — RSA Key Extraction via PIN Tool

**Group 8**

| Name | Roll Number |
|------|-------------|
| Prem Kansagra | 220816 |
| Jenil Dobariya | 220385 |
| Poojal Katiyar | 220770 |
| Raj Vinayak Meena | 220861 |
| Denchanadula Rushikesh Chary | 220336 |

---

## 1. Vulnerability: Square-and-Multiply Side Channel

RSA decryption computes `C^d mod n` using the square-and-multiply algorithm:

```
result = 1
for i = MSB down to LSB:
    result = square(result)          ← called for EVERY bit of key d
    if bit[i] == 1:
        result = multiply(result, M) ← called ONLY when bit = 1
return result
```

Because `multiply()` is called **only for 1-bits**, the execution pattern
directly leaks every bit of the private key `d`. This is a **Simple Power
Analysis (SPA)** attack — instead of measuring power, we count machine-level
multiply instructions using PIN.

---

## 2. Implementation: rsa_pin.cpp

### Core Idea

At the machine instruction level, both `square()` and `multiply()` internally
execute `MUL`/`IMUL` instructions. For each iteration of the key loop:

```
bit = 0  →  only square executes    →  fewer MUL instructions
bit = 1  →  square + multiply runs  →  more MUL instructions
```

By counting MUL instructions per loop iteration, we recover each key bit.

### Step-by-Step Logic

**Step 1 — Instrument the binary:**
- Hook every `MUL`/`IMUL` instruction → count them
- Hook every backward branch inside the main binary → detect loop iterations

**Step 2 — Identify the key loop:**
- The square-and-multiply loop is a backward branch that fires approximately
  64 times (once per bit of the 64-bit key)
- We find the branch with fire count closest to 64

**Step 3 — Get MUL counts per iteration:**
- Between each consecutive branch fire, count how many MUL instructions ran
- This gives an array: `muls[0], muls[1], ..., muls[63]`
- `muls[0]` = MULs before loop starts (initialization noise) → **skip this**
- `muls[1..last]` = one entry per real loop iteration → **decode these**

**Step 4 — Find the threshold:**
- Count frequency of each MUL-count value in `muls[1..last]`
- Two values dominate: `bit0_count` (square only) and `bit1_count` (square+multiply)
- `threshold = (bit0_count + bit1_count) / 2`

**Step 5 — Decode bits:**
```
for each muls[i] where i >= 1:
    if muls[i] > threshold  →  bit = 1
    else                    →  bit = 0
```

**Step 6 — Convert to decimal:**
- The bit string (MSB first) is converted to `uint64_t`
- Leading zeros are stripped automatically by integer conversion
- Result written to `key.txt`

### Why No Values Are Hardcoded

- The loop branch address is **auto-detected** at runtime (closest to 64 fires)
- The threshold is **computed dynamically** from the MUL count distribution
- No function addresses, offsets, or key-specific values are hardcoded
- Works for any key embedded in the same binary

### Output File

The tool writes exactly one line to `key.txt`:
```
<key in decimal>
```

Example:
```
2753
```

---

## 3. Files in This Submission

```
rsa_pin.cpp   ← PIN tool source code
README.md     ← this file
run.sh        ← script to compile, run, and verify
```

---

## 4. Compilation Instructions

The tool requires the PIN dynamic instrumentation framework.

```bash
# Step 1: Navigate to PIN's ManualExamples directory
cd ~/Downloads/pin-external-4.0-99633-g5ca9893f2-gcc-linux/source/tools/ManualExamples

# Step 2: Copy rsa_pin.cpp into this directory
cp /path/to/rsa_pin.cpp .

# Step 3: Compile for 64-bit target
rm -f obj-intel64/rsa_pin.so obj-intel64/rsa_pin.o
make obj-intel64/rsa_pin.so TARGET=intel64
```

Compiled tool location:
```
obj-intel64/rsa_pin.so
```

---

## 5. How to Run

### Manual Steps

```bash
# Set paths
PIN="$HOME/Downloads/pin-external-4.0-99633-g5ca9893f2-gcc-linux"
TOOLS="$PIN/source/tools/ManualExamples"
BINARY="/path/to/leaky_rsa"

# Step 1: Run PIN tool on the binary
"$PIN/pin" -t "$TOOLS/obj-intel64/rsa_pin.so" -- "$BINARY"

# Step 2: View extracted key (written to key.txt)
cat key.txt

# Step 3: Verify the key
"$BINARY" -a "$(cat key.txt)"
```

Expected output:
```
Your Key is Correct
```

### Using the Script

```bash
chmod +x run.sh
./run.sh
```

The script compiles, runs the PIN tool, and verifies the key automatically.

---

## 6. Output Files

| File | Description |
|------|-------------|
| `key.txt` | One line — extracted key in decimal (required output) |
| `debug.txt` | Diagnostic log — loop detection, MUL counts, bit decoding |

### Sample debug.txt

```
=== LOOP DETECTION ===
Branch: 0x...7a7  fires=63

=== MUL COUNTS PER ITERATION ===
74 1 1 1 1 1 ... 2 1 2 1 2 2 1 1 1 5

=== MUL COUNT FREQUENCIES (excluding init) ===
  count=1  freq=58
  count=2  freq=4
  count=5  freq=1

bit0_count=1  bit1_count=2  threshold=1.5

=== BIT DECODING ===
bits (63): 000000000000000000000000000000000000000000000000000101011000001

=== RESULT ===
Key (decimal): 2753
Key (hex):     0xac1
```

---

## 7. Note on Key Values

The tool extracts a key that produces **identical RSA decryption output**
as the embedded secret key. Due to the mathematical property of RSA:

```
C^d ≡ C^(d + k×φ(n))  mod n   for any integer k
```

Multiple key values can produce the same decryption result. The tool
may extract any one of these mathematically equivalent values — all
pass the `-a` verification check. This is the expected behavior for
a side-channel attack on RSA.
