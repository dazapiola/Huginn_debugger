'use strict';

var _bps = {};   // hex-addr-string -> InvocationListener

function collectRegs(ctx) {
    var r = {
        rax: ctx.rax.toString(),
        rbx: ctx.rbx.toString(),
        rcx: ctx.rcx.toString(),
        rdx: ctx.rdx.toString(),
        rsi: ctx.rsi.toString(),
        rdi: ctx.rdi.toString(),
        rbp: ctx.rbp.toString(),
        rsp: ctx.rsp.toString(),
        r8:  ctx.r8.toString(),
        r9:  ctx.r9.toString(),
        r10: ctx.r10.toString(),
        r11: ctx.r11.toString(),
        r12: ctx.r12.toString(),
        r13: ctx.r13.toString(),
        r14: ctx.r14.toString(),
        r15: ctx.r15.toString(),
        rip: ctx.pc.toString(),
    };
    try { r.rflags = ctx.rflags.toString(); } catch (_) { r.rflags = '0x0'; }
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
