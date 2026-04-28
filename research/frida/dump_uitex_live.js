// Walk live custom-track borrowed UITextures and dump their structure
// to figure out where the D3D12 dst pointer actually lives. Our chain
// (UITex+0x08 -> A+0x18 -> B+0x00 -> C+0x08..0x48) returned 0 dsts in
// per-track polling. Need to find the right offsets.

const UITEX_PTRS = [
    { addr: ptr('0x0000036B2FC91840'), name: 'OG[19] Dont Be So Serious' },
    { addr: ptr('0x0000036B2FC927E0'), name: 'OG[38] St. Eriksplan' },
    { addr: ptr('0x0000036B2FC92B70'), name: 'OG[52] Tonight Tonight Tonight' },
    { addr: ptr('0x0000036B2FC92790'), name: 'OG[45] template' },
];

function isHeapPtr(p) {
    if (!p || p.isNull()) return false;
    const hi = p.shr(40).toUInt32();
    if (hi < 1 || hi > 7) return false;
    if (p.and(7).toUInt32() !== 0) return false;
    return true;
}

function dumpQwords(addr, name, count) {
    console.log('\n=== ' + name + ' @ ' + addr + ' ===');
    for (let i = 0; i < count; i++) {
        try {
            const v = addr.add(i * 8).readPointer();
            const isHeap = isHeapPtr(v);
            console.log('  +' + (i*8).toString(16).padStart(3, '0') + ': ' +
                v + (isHeap ? '  [heap]' : ''));
        } catch (e) {
            console.log('  +' + (i*8).toString(16).padStart(3, '0') + ': <unreadable>');
            break;
        }
    }
}

function tryChain(name, uitex, offsets) {
    console.log('\n--- chain attempt for ' + name + ' offsets=' + JSON.stringify(offsets));
    let cur = uitex;
    let label = 'UITex';
    for (let i = 0; i < offsets.length; i++) {
        try {
            const next = cur.add(offsets[i]).readPointer();
            console.log('  ' + label + '+0x' + offsets[i].toString(16) + ' -> ' + next);
            if (!isHeapPtr(next)) {
                console.log('  STOP: not a heap ptr');
                return;
            }
            cur = next;
            label = 'next';
        } catch (e) {
            console.log('  STOP: read fail');
            return;
        }
    }
    console.log('  FINAL ' + label + ' @ ' + cur);
    dumpQwords(cur, 'final node', 16);
}

for (const ent of UITEX_PTRS) {
    dumpQwords(ent.addr, ent.name, 16);
}

// Try the canonical chain on first one
const u = UITEX_PTRS[0].addr;
console.log('\n\n=== chain walk attempts on ' + UITEX_PTRS[0].name + ' ===');

// Original assumption: UITex+0x08 -> A+0x18 -> B+0x00 -> C
tryChain('A=+0x08, B=A+0x18, C=B+0x00', u, [0x08, 0x18, 0x00]);

// Try other plausible chains
tryChain('A=+0x10, B=A+0x18, C=B+0x00', u, [0x10, 0x18, 0x00]);
tryChain('A=+0x08, B=A+0x10, C=B+0x00', u, [0x08, 0x10, 0x00]);
tryChain('A=+0x08, B=A+0x08, C=B+0x00', u, [0x08, 0x08, 0x00]);

// Per UITexture serialized struct breakdown:
// SmallTexture is at field offset (varies in runtime), LargeTexture next.
// Each TextureInfo has a TextureData with EmbeddedData blob ptr.
// At RUNTIME these become D3D12_Resource pointers.
// Walk every plausible chain offset combo to find one ending at a heap ptr
// with vtable in d3d12 area (0x7FFA-0x7FFB range).

const d3d12 = Process.enumerateModules().find(m => /D3D12Core\.dll/i.test(m.name));
const d3d12dll = Process.enumerateModules().find(m => /^d3d12\.dll$/i.test(m.name));
console.log('\nd3d12 module ranges:',
    d3d12 ? (d3d12.base + ' - ' + d3d12.base.add(d3d12.size)) : 'none',
    d3d12dll ? (d3d12dll.base + ' - ' + d3d12dll.base.add(d3d12dll.size)) : 'none');

function isD3D12Vtable(p) {
    if (!isHeapPtr(p)) {
        // d3d12 vtables live in d3d12.dll/D3D12Core.dll address range
        if (d3d12 && p.compare(d3d12.base) >= 0 &&
            p.compare(d3d12.base.add(d3d12.size)) < 0) return true;
        if (d3d12dll && p.compare(d3d12dll.base) >= 0 &&
            p.compare(d3d12dll.base.add(d3d12dll.size)) < 0) return true;
    }
    return false;
}

function isD3D12Resource(p) {
    if (!isHeapPtr(p)) return false;
    try {
        const vtbl = p.readPointer();
        return isD3D12Vtable(vtbl);
    } catch (e) { return false; }
}

console.log('\n\n=== brute-force chain search for d3d12 resources reachable from ' + UITEX_PTRS[0].name + ' ===');
function bruteSearch(start, maxDepth) {
    const visited = new Set();
    const queue = [{ addr: start, path: ['UITex'], depth: 0 }];
    let found = 0;
    while (queue.length > 0 && found < 10) {
        const { addr, path, depth } = queue.shift();
        const key = addr.toString();
        if (visited.has(key)) continue;
        visited.add(key);
        if (depth > maxDepth) continue;
        if (isD3D12Resource(addr)) {
            console.log('  FOUND D3D12 resource at depth ' + depth + ': ' + addr +
                ' via ' + path.join(' -> '));
            found++;
            continue;
        }
        // Walk this object's pointer slots
        for (let off = 0; off < 0x80; off += 8) {
            try {
                const v = addr.add(off).readPointer();
                if (isHeapPtr(v) || isD3D12Vtable(v)) {
                    queue.push({ addr: v, path: path.concat(['+0x' + off.toString(16)]), depth: depth + 1 });
                }
            } catch (e) { break; }
        }
    }
    if (found === 0) console.log('  NO D3D12 resources found within depth ' + maxDepth);
}
bruteSearch(u, 4);
