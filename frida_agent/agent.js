'use strict';

var _bps = {};   // hex-addr-string -> InvocationListener

function toHex(val) {
    // NativePointer.toString() always returns '0x...' hex — but guard against
    // plain JS numbers (e.g. rflags on some Frida versions) which return decimal.
    var s = val.toString();
    if (s.indexOf('0x') === 0 || s.indexOf('-0x') === 0) return s;
    // Treat as a decimal integer and convert to hex
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

// NOTE: Python's script.exports_sync converts snake_case → camelCase,
//       so readMemory is called via backend.exports_sync.read_memory(...)

rpc.exports = {

    readMemory: function (addrHex, size) {
        try {
            var buf = ptr(addrHex).readByteArray(size);
            if (buf === null) return null;
            return Array.from(new Uint8Array(buf));
        } catch (_) { return null; }
    },

    writeMemory: function (addrHex, bytes) {
        try {
            var p = ptr(addrHex);
            Memory.protect(p, bytes.length, 'rwx');
            p.writeByteArray(bytes);
            return true;
        } catch (_) { return false; }
    },

    getModules: function () {
        return Process.enumerateModules().map(function (m) {
            return { name: m.name, base: m.base.toString(), size: m.size, path: m.path };
        });
    },

    getRanges: function () {
        return Process.enumerateRanges('r--').map(function (r) {
            return {
                base:       r.base.toString(),
                size:       r.size,
                protection: r.protection,
                file:       (r.file && r.file.path) ? r.file.path : null,
            };
        });
    },

    // addr is a hex string like "0x401234"
    setBreakpoint: function (addrHex) {
        if (_bps[addrHex]) return true;
        try {
            _bps[addrHex] = Interceptor.attach(ptr(addrHex), {
                onEnter: function (args) {
                    send({ type: 'bp_hit', addr: addrHex, regs: collectRegs(this.context) });
                    recv('continue', function (_) {}).wait();
                }
            });
            return true;
        } catch (e) {
            send({ type: 'bp_error', addr: addrHex, msg: e.message });
            return false;
        }
    },

    removeBreakpoint: function (addrHex) {
        if (_bps[addrHex]) {
            try { _bps[addrHex].detach(); } catch (_) {}
            delete _bps[addrHex];
        }
        return true;
    },
};
