# ============================================================
# Makefile for rsa_pin PIN tool
#
# Usage:
#   export PIN_ROOT=/path/to/pin-3.x
#   make
#
# This produces:  obj-intel64/rsa_pin.so
# ============================================================

# ---------- Locate PIN -------------------------------------------
# Set PIN_ROOT via environment or override here.
PIN_ROOT ?= $(HOME)/pin

# PIN's own build infrastructure (provides all compiler flags)
include $(PIN_ROOT)/source/tools/Config/makefile.config
include $(TOOLS_ROOT)/Config/makefile.default.rules

# ---------- Our tool ---------------------------------------------
TOOL_ROOTS := rsa_pin

# makefile.default.rules will build obj-intel64/rsa_pin.so automatically
# when TOOL_ROOTS is set and the source file rsa_pin.cpp exists here.
