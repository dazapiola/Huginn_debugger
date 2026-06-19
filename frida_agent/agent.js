'use strict';

// bp registry: hex-addr-string -> { type: 'interceptor'|'int3', listener?, original? }
var _bps = {};
var _pending_rearm = null;   // NativePointer — set by INT3 handler, consumed by single-step handler
var _handler_installed = false;

function toHex(val) {
    var s = val.toString();
    if (s.indexOf('0x') === 0 || s.indexOf('-0x') === 0) return s;
    return '0x' + (parseInt(s, 10) >>> 0).toString(16);
}

function collectRegs(ctx) {
    var names = ['rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp',
                 'r8','r9','r10','r11','r12','r13','r14','r15'];
    var r = {};
    for (var i = 0; i < names.length; i++) {
        var n = names[i];
        try { r[n] = toHex(ctx[n]); } catch (_) { r[n] = '0x0'; }
    }
    try { r.rip    = toHex(ctx.pc);     } catch (_) { r.rip    = '0x0'; }
    try { r.rflags = toHex(ctx.rflags); } catch (_) { r.rflags = '0x0'; }
    try { r.cs     = toHex(ctx.cs);     } catch (_) { r.cs     = '0x0'; }
    try { r.ss     = toHex(ctx.ss);     } catch (_) { r.ss     = '0x0'; }
    return r;
}

function rflagsAsInt(ctx) {
    try {
        var v = ctx.rflags;
        if (typeof v === 'number') return v;
        return parseInt(v.toString(), 16);
    } catch(_) { return 0; }
}

var TF = 0x100;  // x86 Trap Flag in RFLAGS — causes single-step exception after next instruction

function ensureExceptionHandler() {
    if (_handler_installed) return;
    _handler_installed = true;
    try {
        Process.setExceptionHandler(function(details) {

            // ── INT3 breakpoint hit ───────────────────────────────────────────
            if (details.type === 'breakpoint') {
                var hitAddr = details.address;
                var addrHex = hitAddr.toString();
                var bp = _bps[addrHex];
                if (!bp || bp.type !== 'int3') return false;

                // Restore original byte so the instruction can execute on resume
                Memory.protect(hitAddr, 1, 'rwx');
                hitAddr.writeU8(bp.original);

                // On x86/x64 after INT3, hardware sets PC = addr+1.
                // Frida gives details.address = addr, but context.pc = addr+1.
                // Fix it so execution resumes from the correct instruction.
                details.context.pc = hitAddr;

                // Arm single-step: after the original instruction executes, TF fires
                // and the single-step handler re-arms INT3 if the BP still exists.
                _pending_rearm = hitAddr;
                details.context.rflags = rflagsAsInt(details.context) | TF;

                send({ type: 'bp_hit', addr: addrHex, regs: collectRegs(details.context) });
                recv('continue', function(_) {}).wait();
                return true;
            }

            // ── Single-step (TF) — re-arm the INT3 that fired before ──────────
            if (details.type === 'single-step') {
                if (_pending_rearm === null) return false;
                var rearmAddr = _pending_rearm;
                _pending_rearm = null;

                // Only re-arm if the user hasn't removed the BP in the meantime
                var key = rearmAddr.toString();
                if (_bps[key] && _bps[key].type === 'int3') {
                    Memory.protect(rearmAddr, 1, 'rwx');
                    rearmAddr.writeU8(0xcc);
                }

                // Clear TF so the process resumes normally
                details.context.rflags = rflagsAsInt(details.context) & ~TF;
                return true;
            }

            return false;
        });
    } catch(e) {
        send({ type: 'bp_error', addr: '0x0', msg: 'setExceptionHandler failed: ' + e.message });
    }
}

rpc.exports = {

    readMemory: function(addrHex, size) {
        try {
            var buf = ptr(addrHex).readByteArray(size);
            if (buf === null) return null;
            return Array.from(new Uint8Array(buf));
        } catch(_) { return null; }
    },

    writeMemory: function(addrHex, bytes) {
        try {
            var p = ptr(addrHex);
            Memory.protect(p, bytes.length, 'rwx');
            p.writeByteArray(bytes);
            return true;
        } catch(_) { return false; }
    },

    getModules: function() {
        return Process.enumerateModules().map(function(m) {
            return { name: m.name, base: m.base.toString(), size: m.size, path: m.path };
        });
    },

    getRanges: function() {
        return Process.enumerateRanges('r--').map(function(r) {
            return {
                base:       r.base.toString(),
                size:       r.size,
                protection: r.protection,
                file:       (r.file && r.file.path) ? r.file.path : null,
            };
        });
    },

    // Try Interceptor.attach first (clean re-arming, works at function starts).
    // Fall back to INT3 for arbitrary addresses (mid-function, data, etc.).
    setBreakpoint: function(addrHex) {
        if (_bps[addrHex]) return true;

        try {
            var listener = Interceptor.attach(ptr(addrHex), {
                onEnter: function(args) {
                    send({ type: 'bp_hit', addr: addrHex, regs: collectRegs(this.context) });
                    recv('continue', function(_) {}).wait();
                }
            });
            _bps[addrHex] = { type: 'interceptor', listener: listener };
            return true;
        } catch(_) {}

        // Interceptor failed — use INT3
        ensureExceptionHandler();
        try {
            var addr = ptr(addrHex);
            Memory.protect(addr, 1, 'rwx');
            var original = addr.readU8();
            addr.writeU8(0xcc);
            _bps[addrHex] = { type: 'int3', original: original };
            return true;
        } catch(e) {
            send({ type: 'bp_error', addr: addrHex, msg: e.message });
            return false;
        }
    },

    removeBreakpoint: function(addrHex) {
        var bp = _bps[addrHex];
        if (!bp) return true;
        if (bp.type === 'interceptor') {
            try { bp.listener.detach(); } catch(_) {}
        } else {
            // The exception handler may have already restored the byte.
            // Only overwrite if it's still 0xcc.
            try {
                var addr = ptr(addrHex);
                if (addr.readU8() === 0xcc) {
                    Memory.protect(addr, 1, 'rwx');
                    addr.writeU8(bp.original);
                }
            } catch(_) {}
        }
        delete _bps[addrHex];
        return true;
    },
};
