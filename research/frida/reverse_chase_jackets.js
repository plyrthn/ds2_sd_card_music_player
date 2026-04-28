// Given one captured music-jacket dst, reverse-chase pointers through the
// UITexture chain to find ALL music jacket dsts.
//
// Chain forward: UITex+0x08 -> A+0x18 -> B+0x00 -> C+(0x08..0x48) = dst
// Chain reverse:
//   1. find ptr to dst -> location is C + (0x08..0x48)
//   2. find ptr to C -> location is B+0x00
//   3. find ptr to B -> location is A+0x18 -> A = match - 0x18
//   4. find ptr to A -> location is UITex+0x08 -> UITex = match - 0x08
//   5. find ptr to UITex inside an Array<UITex*>'s data block
//   6. read Array header (count, cap, data) to get all sibling UITex ptrs
//   7. forward-chase each sibling to get all its dsts

const ANCHOR_DST = ptr('0x1AAB395AC10');
const OUT_PATH = 'J:\\SteamLibrary\\steamapps\\common\\DEATH STRANDING 2 - ON THE BEACH\\albumjacket\\music_jacket_dsts.txt';
console.log('Anchor:', ANCHOR_DST);

function isHeapPtr(p) {
    if (!p || p.isNull()) return false;
    const hi = p.shr(40).toUInt32();
    if (hi < 1 || hi > 7) return false;
    if (p.and(7).toUInt32() !== 0) return false;
    return true;
}

function ptrPattern(p) {
    const lo = p.toUInt32();
    const hi = p.shr(32).toUInt32();
    function bx(x, i) { return ((x >>> (i * 8)) & 0xFF).toString(16).padStart(2, '0'); }
    return [bx(lo, 0), bx(lo, 1), bx(lo, 2), bx(lo, 3),
            bx(hi, 0), bx(hi, 1), bx(hi, 2), bx(hi, 3)].join(' ');
}

const ranges = Process.enumerateRanges({ protection: 'rw-', coalesce: false })
    .filter(r => {
        const hi = r.base.shr(40).toUInt32();
        return r.size >= 0x1000 && r.size <= 0x4000000 && hi >= 1 && hi <= 7;
    });
console.log('eligible ranges:', ranges.length);

function scanForPointer(target, maxHits, callback) {
    const pat = ptrPattern(target);
    let hits = [];
    let idx = 0;
    function next() {
        if (idx >= ranges.length || hits.length >= maxHits) {
            callback(hits);
            return;
        }
        const r = ranges[idx];
        Memory.scan(r.base, r.size, pat, {
            onMatch: function(addr) {
                if ((addr.and(7)).toUInt32() === 0) {
                    hits.push(addr);
                    if (hits.length >= maxHits) return 'stop';
                }
            },
            onError: function() {},
            onComplete: function() { idx++; setImmediate(next); }
        });
    }
    next();
}

// Step 1: find ptrs to anchor dst.
console.log('STEP 1: scan for ptrs to anchor', ANCHOR_DST);
scanForPointer(ANCHOR_DST, 50, function(hits) {
    console.log('  found', hits.length, 'ptrs to anchor');
    if (hits.length === 0) return;
    // Each hit X is at C + (0x08..0x48). Try offset 0x08 first (most likely).
    // But we don't know which slot. Let's try all viable C candidates:
    //   for each offset in {0x08,0x10,0x18,0x20,0x28,0x30,0x38,0x40,0x48}:
    //     C = hit - offset
    // Then scan for ptrs to C (each B+0x00). B is the actual scan target.
    //
    // Heuristic: pick the FIRST hit, try offset 0x08, see if subsequent
    // chase works. If not, try other offsets.

    function tryHit(hitIdx, slotIdx) {
        if (hitIdx >= hits.length) {
            console.log('exhausted all hits; no chain found');
            return;
        }
        const slots = [0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48];
        if (slotIdx >= slots.length) {
            tryHit(hitIdx + 1, 0);
            return;
        }
        const off = slots[slotIdx];
        const hit = hits[hitIdx];
        const C = hit.sub(off);
        if (!isHeapPtr(C)) {
            tryHit(hitIdx, slotIdx + 1);
            return;
        }
        console.log('  trying hit#' + hitIdx + ' slot=0x' + off.toString(16),
            'C =', C);
        // STEP 2: find ptrs to C (those are B+0x00)
        scanForPointer(C, 8, function(bHits) {
            console.log('    ptrs to C:', bHits.length);
            if (bHits.length === 0) {
                tryHit(hitIdx, slotIdx + 1);
                return;
            }
            // Each bHit is B+0x00, so B = bHit
            tryB(0, bHits, C);
        });
    }

    function tryB(bIdx, bHits, C) {
        if (bIdx >= bHits.length) { return; }
        const B = bHits[bIdx];
        console.log('    trying B =', B);
        // STEP 3: find ptrs to B; those are A+0x18 -> A = match - 0x18
        scanForPointer(B, 8, function(aHits) {
            console.log('      ptrs to B:', aHits.length);
            if (aHits.length === 0) { tryB(bIdx + 1, bHits, C); return; }
            tryA(0, aHits.map(h => h.sub(0x18)).filter(isHeapPtr));
        });
    }

    function tryA(aIdx, As) {
        if (aIdx >= As.length) return;
        const A = As[aIdx];
        console.log('      trying A =', A);
        scanForPointer(A, 8, function(uHits) {
            console.log('        ptrs to A:', uHits.length);
            if (uHits.length === 0) { tryA(aIdx + 1, As); return; }
            tryU(0, uHits.map(h => h.sub(0x08)).filter(isHeapPtr));
        });
    }

    function tryU(uIdx, UITexs) {
        if (uIdx >= UITexs.length) return;
        const UITex = UITexs[uIdx];
        console.log('        trying UITex =', UITex);
        scanForPointer(UITex, 16, function(arrHits) {
            console.log('          ptrs to UITex:', arrHits.length);
            // each match is array_data_ptr + slot*8 for some slot >= 0.
            // Try to detect Array header: if a hit minus N*8 has a uint32
            // count + uint32 cap pattern, with data ptr matching, that's
            // the array.
            for (const h of arrHits) {
                tryFindArray(h, UITex);
            }
            tryU(uIdx + 1, UITexs);
        });
    }

    let foundAny = false;
    function tryFindArray(arrEntryAddr, originalUITex) {
        // Walk back up to 200 slots (a Decima Array can have up to 200ish
        // entries) to find a place where a struct {count, cap, dataPtr}
        // points back to this address.
        for (let slot = 0; slot < 200; slot++) {
            const dataStart = arrEntryAddr.sub(slot * 8);
            // search nearby memory for array headers pointing to dataStart.
            // Array header is somewhere with data field == dataStart.
            // We don't want to scan ALL memory again; instead, just
            // probe locations: array headers are typically in objects,
            // their offset to data field is +0x08 in the 16-byte struct.
            // So if dataStart is at addr X, header struct is at some Y
            // with Y+0x08 == X. We don't know Y directly.
            //
            // Easier: scan memory for ptrs to dataStart. Each match Z is
            // at Y+0x08 for some Y. Then read Y as Array<X>.
        }
        // Simpler: just scan for ptrs to this array_entry's containing data ptr.
        // Skip this complexity; report the UITex chain we found instead.
        if (!foundAny) {
            foundAny = true;
            harvestFromUITexNeighbors(arrEntryAddr, originalUITex);
        }
    }

    // Once we have UITex pointer location inside an Array's data block,
    // assume the data block is contiguous (Decima Array<X*>). Walk +/- N
    // entries to find sibling UITex pointers, walk each forward chain to
    // get its dsts.
    function harvestFromUITexNeighbors(arrEntryAddr, originalUITex) {
        console.log('          HARVEST starting at array entry', arrEntryAddr,
            '(originalUITex=' + originalUITex + ')');
        const allDsts = new Set();
        // Find array header: scan backward for {count u32, cap u32, ptr->arrEntryAddr}
        // The data ptr in the header is the START of the data block. arrEntryAddr is
        // somewhere inside that block. We need to find the start.
        // Step back 8 bytes at a time, see if anywhere matches an Array layout.
        let arrayStart = null;
        let arrayCount = 0;
        for (let back = 0; back < 200; back++) {
            const dataCandidate = arrEntryAddr.sub(back * 8);
            // scan for ptrs == dataCandidate; one of those locations is at
            // (header_addr + 8). header_addr+0 is the count/cap.
            // To avoid ANOTHER scan, we just probe sideways for an Array
            // header whose data field == dataCandidate.
            // Look at the 16-byte block at (dataCandidate - 16): if that
            // looks like {count, cap} and dataCandidate matches the data ptr,
            // we found the header.
            try {
                const headerCandidate = dataCandidate.sub(16);
                const probeData = headerCandidate.add(8).readPointer();
                if (probeData.equals(dataCandidate)) {
                    const cnt = headerCandidate.readU32();
                    const cap = headerCandidate.add(4).readU32();
                    if (cnt > 0 && cnt <= 1000 && cap >= cnt && cap <= 4096) {
                        arrayStart = dataCandidate;
                        arrayCount = cnt;
                        console.log('          ARRAY found: header=', headerCandidate,
                            'count=' + cnt + ' cap=' + cap + ' data=' + dataCandidate);
                        break;
                    }
                }
            } catch (e) {}
        }
        if (!arrayStart) {
            // fallback: assume arrEntryAddr is the start, walk forward as far
            // as readable
            arrayStart = arrEntryAddr;
            arrayCount = 200;
            console.log('          no header found; using arrEntryAddr as start, scanning fwd');
        }
        // Walk all entries in the array
        for (let i = 0; i < arrayCount; i++) {
            try {
                const u = arrayStart.add(i * 8).readPointer();
                if (!isHeapPtr(u)) continue;
                const A = u.add(0x08).readPointer();
                if (!isHeapPtr(A)) continue;
                const B = A.add(0x18).readPointer();
                if (!isHeapPtr(B)) continue;
                const C = B.readPointer();
                if (!isHeapPtr(C)) continue;
                for (let s = 0; s < 9; s++) {
                    try {
                        const d = C.add(0x08 + s * 8).readPointer();
                        if (isHeapPtr(d)) allDsts.add(d.toString());
                    } catch (e) {}
                }
            } catch (e) {}
        }
        console.log('          HARVEST collected', allDsts.size, 'unique dst ptrs');
        if (allDsts.size > 0) {
            try {
                const f = new File(OUT_PATH, 'w');
                f.write('# reverse-chased from anchor ' + ANCHOR_DST + '\n');
                f.write('# array=' + arrayStart + ' count=' + arrayCount + '\n');
                for (const d of allDsts) f.write(d + '\n');
                f.close();
                console.log('          WROTE ' + allDsts.size + ' addrs to ' + OUT_PATH);
            } catch (e) { console.log('          write failed:', e); }
        }
    }

    tryHit(0, 0);
});
