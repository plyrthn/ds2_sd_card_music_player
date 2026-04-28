// Hook ID3D12GraphicsCommandList::CopyTextureRegion via Frida and capture
// every dst that receives a 512x512 BC7 upload while the user navigates
// the music menu. Dump unique dst addresses to music_jacket_dsts.txt for
// the ASI to consume.
//
// USAGE: open music menu in DS2, run this script, then immediately scroll
// through the music tracks (each scroll re-uploads visible jackets). Let
// it run for 20 seconds, then it writes the file.

const ds2 = Process.findModuleByName('DS2.exe');
const OUT_PATH = ds2.path.substring(0, ds2.path.lastIndexOf('\\')) +
    '\\albumjacket\\music_jacket_dsts.txt';
console.log('Will write to:', OUT_PATH);

// Find the cmd list vtable. The ASI logged "CopyTextureRegion @ 0x..." but
// we don't have access to that here. Easiest: scan DS2 for an instance of
// our own pattern -- find any ID3D12GraphicsCommandList that the game uses.
// We'll do this by hooking ID3D12Device::CreateCommandList or by reading
// the cmdList vtable from a known source.

// Simpler: hook D3D12CreateDevice export then chain through.
// But device may already be created. Alternative: search modules for
// d3d12.dll, find ID3D12GraphicsCommandList vtable signature.

// Most reliable: hook ID3D12CommandQueue::ExecuteCommandLists - any cmd
// list passed to it is what we want. Then dig out vtbl[16] = CTR.

// Actually simplest of all: Frida can iterate modules. Look at d3d12.dll
// imports/exports... won't have the vtable directly. Vtables are in C++
// metadata, not exports.

// Easiest path: scan the heap for `g_origCopyTextureRegion` style trampoline.
// The ASI already installed a hook so the CTR vtable slot is patched. We
// can't intercept the same slot.

// Fallback approach: write a marker file with "CAPTURE:N", the ASI sees
// it, captures N CTRs to its own dst-set. Then writes it out.

// Even simpler approach, just write a TRIGGER file. ASI sees trigger,
// captures CTRs for next 10 seconds, dumps dst list to music_jacket_dsts.txt
const TRIGGER_PATH = ds2.path.substring(0, ds2.path.lastIndexOf('\\')) +
    '\\albumjacket\\music_jacket_capture.trigger';
console.log('Trigger path:', TRIGGER_PATH);

try {
    const f = new File(TRIGGER_PATH, 'w');
    f.write('CAPTURE\n');
    f.close();
    console.log('Trigger written. ASI should capture CTRs for 10s then write dst list.');
} catch (e) {
    console.log('Trigger write failed:', e);
}
