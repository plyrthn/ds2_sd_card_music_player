// Reverse chase but ONLY in the memory range containing the anchor dst
// (and a few neighbor ranges). InstallMenu's UITextures + their D3D12
// resources live in the same heap arena.

const ANCHOR_DST = ptr('0x1AAB395AC10');
const OUT_PATH = 'J:\\SteamLibrary\\steamapps\\common\\DEATH STRANDING 2 - ON THE BEACH\\albumjacket\\music_jacket_dsts.txt';

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

const allRanges = Process.enumerateRanges({ protection: 'rw-', coalesce: false });
console.log('total rw- ranges:', allRanges.length);

// Find the range CONTAINING the anchor.
const containing = allRanges.find(r => ANCHOR_DST.compare(r.base) >= 0 &&
    ANCHOR_DST.compare(r.base.add(r.size)) < 0);
if (!containing) {
    console.log('ANCHOR not found in any range; it is stale or the address is invalid.');
    console.log('Re-trigger capture and update the anchor in this script.');
    throw new Error('stale anchor');
}
console.log('Anchor range:', containing.base, 'size 0x' + containing.size.toString(16));

// Search ONLY this range for ptrs to anchor.
function scanRange(r, target, maxHits, cb) {
    let hits = [];
    Memory.scan(r.base, r.size, ptrPattern(target), {
        onMatch: function(addr) {
            if ((addr.and(7)).toUInt32() === 0) hits.push(addr);
            if (hits.length >= maxHits) return 'stop';
        },
        onError: function() {},
        onComplete: function() { cb(hits); }
    });
}

console.log('Scanning anchor range for ptrs to', ANCHOR_DST);
scanRange(containing, ANCHOR_DST, 32, function(dstHits) {
    console.log('  found', dstHits.length, 'ptrs to anchor in containing range');
    if (dstHits.length === 0) {
        // Try the neighbor heap pages -- maybe the holder is in a sibling
        // arena. Filter to same hi-prefix as anchor.
        const pHi = ANCHOR_DST.shr(40).toUInt32();
        const nbrs = allRanges.filter(r => {
            const rh = r.base.shr(40).toUInt32();
            return rh === pHi && r.size <= 0x4000000;
        });
        console.log('  trying', nbrs.length, 'neighbor ranges with same hi=' + pHi);
        let i = 0; let allHits = [];
        function nbrNext() {
            if (i >= nbrs.length || allHits.length >= 32) {
                console.log('  scanned neighbors; total hits=' + allHits.length);
                if (allHits.length === 0) return;
                proceed(allHits);
                return;
            }
            scanRange(nbrs[i], ANCHOR_DST, 32 - allHits.length, function(h) {
                for (const x of h) allHits.push(x);
                i++;
                setImmediate(nbrNext);
            });
        }
        nbrNext();
    } else {
        proceed(dstHits);
    }
});

function proceed(dstHits) {
    console.log('PROCEED with', dstHits.length, 'anchor hits');
    for (const h of dstHits) {
        // hit is at C+(0x08..0x48). We don't know which slot, so dump
        // the surrounding context.
        console.log('\nAnchor hit @', h);
        for (let off = -0x50; off <= 0x10; off += 8) {
            try {
                const v = h.add(off).readPointer();
                console.log('  +' + off.toString(16).padStart(3) + ': ' + v +
                    (v.equals(ANCHOR_DST) ? '  <<<<<<<<' : ''));
            } catch (e) {}
        }
    }

    // For each hit, try slot offsets and chase forward to validate.
    // Once we find a valid C struct, scan its containing range for
    // ptrs to C.
    const slotOffsets = [0x08, 0x10, 0x18, 0x20, 0x28, 0x30, 0x38, 0x40, 0x48];
    const triedC = new Set();

    function next(idx, slotIdx) {
        if (idx >= dstHits.length) {
            console.log('No valid chain found from any hit; giving up.');
            return;
        }
        if (slotIdx >= slotOffsets.length) {
            next(idx + 1, 0);
            return;
        }
        const C = dstHits[idx].sub(slotOffsets[slotIdx]);
        if (!isHeapPtr(C) || triedC.has(C.toString())) {
            next(idx, slotIdx + 1);
            return;
        }
        triedC.add(C.toString());
        // Validate C: read all 9 slots and check they all are heap pointers.
        let validSlots = 0;
        for (let s = 0; s < 9; s++) {
            try {
                const v = C.add(0x08 + s * 8).readPointer();
                if (isHeapPtr(v)) validSlots++;
            } catch (e) {}
        }
        if (validSlots < 4) { next(idx, slotIdx + 1); return; }
        console.log('  C =', C, 'has', validSlots, 'heap ptrs in slots 0..8');
        // STEP 2: find ptrs to C in same range / neighbors
        scanRangeMulti(C, function(bHits) {
            console.log('    ptrs to C:', bHits.length);
            if (bHits.length === 0) { next(idx, slotIdx + 1); return; }
            tryB(0, bHits, C, idx, slotIdx);
        });
    }

    function scanRangeMulti(target, cb) {
        // scan the containing range first.
        const inRange = allRanges.find(r => target.compare(r.base) >= 0 &&
            target.compare(r.base.add(r.size)) < 0);
        const toScan = [];
        if (inRange) toScan.push(inRange);
        let allHits = [];
        let i = 0;
        function step() {
            if (i >= toScan.length || allHits.length >= 8) { cb(allHits); return; }
            scanRange(toScan[i], target, 8 - allHits.length, function(h) {
                for (const x of h) allHits.push(x);
                i++;
                setImmediate(step);
            });
        }
        step();
    }

    function tryB(bIdx, bHits, C, parentIdx, parentSlot) {
        if (bIdx >= bHits.length) { next(parentIdx, parentSlot + 1); return; }
        const B = bHits[bIdx];
        scanRangeMulti(B, function(aHits) {
            console.log('      ptrs to B:', aHits.length);
            if (aHits.length === 0) { tryB(bIdx + 1, bHits, C, parentIdx, parentSlot); return; }
            const As = aHits.map(h => h.sub(0x18)).filter(isHeapPtr);
            tryA(0, As, parentIdx, parentSlot, bHits, bIdx, C);
        });
    }

    function tryA(aIdx, As, parentIdx, parentSlot, bHits, bIdx, C) {
        if (aIdx >= As.length) { tryB(bIdx + 1, bHits, C, parentIdx, parentSlot); return; }
        const A = As[aIdx];
        scanRangeMulti(A, function(uHits) {
            console.log('        ptrs to A:', uHits.length);
            if (uHits.length === 0) { tryA(aIdx + 1, As, parentIdx, parentSlot, bHits, bIdx, C); return; }
            const UITexs = uHits.map(h => h.sub(0x08)).filter(isHeapPtr);
            tryU(0, UITexs, parentIdx, parentSlot, As, aIdx, bHits, bIdx, C);
        });
    }

    function tryU(uIdx, UITexs, parentIdx, parentSlot, As, aIdx, bHits, bIdx, C) {
        if (uIdx >= UITexs.length) { tryA(aIdx + 1, As, parentIdx, parentSlot, bHits, bIdx, C); return; }
        const UITex = UITexs[uIdx];
        console.log('        UITex =', UITex);
        scanRangeMulti(UITex, function(arrHits) {
            console.log('          ptrs to UITex:', arrHits.length);
            if (arrHits.length === 0) {
                tryU(uIdx + 1, UITexs, parentIdx, parentSlot, As, aIdx, bHits, bIdx, C);
                return;
            }
            // Each match is array.data + slot*8. Find array header (look
            // back for {count u32, cap u32, ptr to dataStart}).
            let foundOne = false;
            for (const h of arrHits) {
                if (foundOne) break;
                for (let back = 0; back < 200; back++) {
                    const dataStart = h.sub(back * 8);
                    try {
                        const probe = dataStart.sub(8).readPointer();
                        if (probe.equals(dataStart)) {
                            // header_addr is dataStart - 16 (count, cap, ptr)
                            const hdr = dataStart.sub(16);
                            const cnt = hdr.readU32();
                            const cap = hdr.add(4).readU32();
                            if (cnt > 0 && cnt <= 1000 && cap >= cnt && cap <= 4096) {
                                console.log('          Array header @', hdr,
                                    'count=' + cnt + ' cap=' + cap +
                                    ' data=' + dataStart);
                                harvest(dataStart, cnt);
                                foundOne = true;
                                break;
                            }
                        }
                    } catch (e) {}
                }
            }
            if (!foundOne) {
                tryU(uIdx + 1, UITexs, parentIdx, parentSlot, As, aIdx, bHits, bIdx, C);
            }
        });
    }

    function harvest(dataStart, count) {
        const dsts = new Set();
        for (let i = 0; i < count; i++) {
            try {
                const u = dataStart.add(i * 8).readPointer();
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
                        if (isHeapPtr(d)) dsts.add(d.toString());
                    } catch (e) {}
                }
            } catch (e) {}
        }
        console.log('          HARVEST collected', dsts.size, 'unique dst ptrs');
        if (dsts.size > 0) {
            try {
                const f = new File(OUT_PATH, 'w');
                f.write('# reverse-chased followup from ' + ANCHOR_DST + '\n');
                f.write('# array data=' + dataStart + ' count=' + count + '\n');
                for (const d of dsts) f.write(d + '\n');
                f.close();
                console.log('          WROTE ' + dsts.size + ' addrs to ' + OUT_PATH);
            } catch (e) { console.log('          write failed:', e); }
        }
    }

    next(0, 0);
}
