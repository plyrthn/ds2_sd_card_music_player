// Hook ID3D12GraphicsCommandList::ResourceBarrier to capture the steady
// state of music jacket dsts. After 20s of capture we report the LAST
// state each tracked dst was transitioned TO.
//
// Method: hook the vtable slot. We get the cmdList vtable by searching
// modules for d3d12 cmd lists. Easier: use the fact that the ASI already
// hooked CopyTextureRegion at vtable slot 16. So vtable slot 26 (next
// to CTR) is ResourceBarrier on the same vtable.

const ds2 = Process.findModuleByName('DS2.exe');
const d3d12core = Process.enumerateModules().find(m => /D3D12Core\.dll/i.test(m.name));
console.log('DS2:', ds2.base, 'D3D12Core:', d3d12core ? d3d12core.base : 'missing');

// We need a live cmdList pointer to read its vtable. Best source: when
// CTR fires, the `this_` arg IS a cmdList. Hook the ASI's installed CTR
// indirectly by hooking the d3d12.dll function that we know the ASI
// trampolined.
//
// Actually simpler: scan recent memory for objects whose +0x00 vtable
// pointer falls in d3d12.dll AND have specific layout. But that's heavy.
//
// Easiest: hook ID3D12CommandQueue::ExecuteCommandLists. Each call
// passes an array of cmd lists. Read the first one's vtable -> slot 26.

const d3d12 = Process.enumerateModules().find(m => /^d3d12\.dll$/i.test(m.name));
if (!d3d12) {
    console.log('d3d12.dll not loaded; aborting');
    throw new Error('no d3d12');
}
console.log('d3d12.dll:', d3d12.base, 'size 0x' + d3d12.size.toString(16));

// Per-dst tracking: dst -> {lastStateAfter, totalBarriers}
const stateMap = new Map();

let installed = false;
function installResourceBarrierHook(cmdListPtr) {
    if (installed) return;
    const vtbl = cmdListPtr.readPointer();
    if (vtbl.compare(d3d12.base) < 0 ||
        vtbl.compare(d3d12.base.add(d3d12.size)) >= 0) {
        // not in d3d12.dll, skip
        return;
    }
    const rbFn = vtbl.add(26 * 8).readPointer();
    console.log('cmdList=' + cmdListPtr + ' vtbl=' + vtbl + ' ResourceBarrier=' + rbFn);
    Interceptor.attach(rbFn, {
        onEnter: function(args) {
            // ResourceBarrier(this, NumBarriers, pBarriers)
            const num = args[1].toInt32();
            const pb = args[2];
            for (let i = 0; i < num && i < 8; i++) {
                const b = pb.add(i * 0x20);  // sizeof(D3D12_RESOURCE_BARRIER)
                try {
                    const type = b.readU32();
                    if (type !== 0) continue;  // only TRANSITION
                    // Transition struct at +0x10:
                    //   pResource, Subresource, StateBefore, StateAfter
                    const pRes = b.add(0x10).readPointer();
                    const subres = b.add(0x18).readU32();
                    const sBefore = b.add(0x1C).readU32();
                    const sAfter = b.add(0x20).readU32();
                    if (pRes.isNull()) continue;
                    const key = pRes.toString();
                    let s = stateMap.get(key);
                    if (!s) { s = { count: 0, lastBefore: 0, lastAfter: 0 }; stateMap.set(key, s); }
                    s.count++;
                    s.lastBefore = sBefore;
                    s.lastAfter = sAfter;
                } catch (e) {}
            }
        }
    });
    installed = true;
    console.log('ResourceBarrier hook installed');
}

// Hook ExecuteCommandLists to grab a cmdList pointer.
// ID3D12CommandQueue::ExecuteCommandLists is vtable slot 10.
// Need a ID3D12CommandQueue pointer first. Same chicken-egg issue.
// Workaround: scan d3d12.dll exports for the CreateDevice address ASI
// already hooked, then trampoline back to find a queue. Too hard.
//
// Easier: the ASI's CTR hook fires often. Each call passes (this_=cmdList).
// We hook the ASI's TRAMPOLINE -- but Frida doesn't have its address.
//
// Brute force: scan rwx memory for vtables of size matching cmdList that
// have ptrs into d3d12.dll. First found = cmdList. Read vtable[26] = RB.

const allRanges = Process.enumerateRanges({ protection: 'rw-', coalesce: false });
console.log('searching rw- ranges for cmdList vtable ptrs...');
let found = false;
let scanned = 0;
for (const r of allRanges) {
    if (found) break;
    const hi = r.base.shr(40).toUInt32();
    if (hi < 1 || hi > 7) continue;
    if (r.size < 0x1000 || r.size > 0x4000000) continue;
    scanned++;
    if (scanned > 800) break;
    try {
        let off = 0;
        while (off + 0x100 < r.size && !found) {
            const obj = r.base.add(off);
            try {
                const vtbl = obj.readPointer();
                if (vtbl.compare(d3d12.base) >= 0 &&
                    vtbl.compare(d3d12.base.add(d3d12.size)) < 0) {
                    // candidate vtbl in d3d12.dll. Check vtable[16] (CTR)
                    // and [26] (ResourceBarrier) both in d3d12 too.
                    const slot16 = vtbl.add(16 * 8).readPointer();
                    const slot26 = vtbl.add(26 * 8).readPointer();
                    if (slot16.compare(d3d12.base) >= 0 &&
                        slot16.compare(d3d12.base.add(d3d12.size)) < 0 &&
                        slot26.compare(d3d12.base) >= 0 &&
                        slot26.compare(d3d12.base.add(d3d12.size)) < 0)
                    {
                        console.log('candidate cmdList obj=' + obj +
                            ' vtbl=' + vtbl + ' rb=' + slot26);
                        installResourceBarrierHook(obj);
                        if (installed) found = true;
                    }
                }
            } catch (e) {}
            off += 0x10;
        }
    } catch (e) {}
}

if (!installed) {
    console.log('no cmdList found in scan; aborting');
} else {
    console.log('=== capturing for 25 seconds ===');
    setTimeout(function() {
        console.log('=== capture done; ' + stateMap.size + ' unique resources ===');
        // Print states. Group by lastAfter for analysis.
        const byState = {};
        for (const [k, v] of stateMap.entries()) {
            const key = '0x' + v.lastAfter.toString(16);
            byState[key] = (byState[key] || 0) + 1;
        }
        console.log('histogram of lastAfter states:');
        for (const k in byState) {
            console.log('  state ' + k + ': ' + byState[k] + ' resources');
        }
    }, 25000);
}
