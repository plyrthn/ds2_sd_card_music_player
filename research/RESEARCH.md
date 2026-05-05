# DS2 Music Player Research

Notes I took while figuring out how DS2's music player works. Two
chunks: the part I got working (custom music plays through the in-game
player) and the part I didn't (per-track custom album art without
breaking the OG jackets). Writing this up in case anyone picks up where
I stopped.

The shipping mod plays your tracks under whatever OG cover the engine
happens to bind. The album-art stuff in section 4 is unfinished.

## 1. Decima resource system

DS2 is built on Guerrilla's Decima engine. Every resource (texture,
sound, music track, etc.) is a typed object with:

- a 16-byte `GGUUID` (`ObjectUUID`)
- a vtable for the runtime type
- a refcount at instance offset `+0x08`
- whatever type-specific fields after that

Resources deserialize from `.core` files in `LocalCacheWinGame/`. At
runtime they sit in a UUID-keyed cache. References between resources
use `StreamingRef<T>`, a 32-byte inline struct.

### StreamingRef layout (32 bytes inline)

```
+0x00: serialized data ptr (mmap'd .core region, ~0x046D... range)
+0x08: runtime resolved Resource ptr (heap, ~0x0001-0x0003... range)
+0x10: vtable for the StreamingRef type
+0x18: flag + hash
```

`+0x08` is the "loaded" ptr. It's null until the engine resolves the
ref the first time. After that, walking `customTrack +0x58` (= the
`+0x08` slot inside the inline StreamingRef at `+0x50`) gets you the
runtime UITexture for that track's jacket.

### Generic resource allocator

`sub_140103b50(typedesc)` is Decima's `ResourceFactory::Create`. Reads
size from `typedesc+0x10` (or via a custom sizer at `typedesc+0x18`
for kind-4 types like UITexture), allocates from the per-thread Decima
allocator, returns a zero-initialized buffer.

You can call it from your own thread, the TLS bootstrap is automatic,
but for variable-size types like UITexture the size it reports is
wrong (see section 4).

## 2. Music player architecture

The in-game music player is a `DSUIMusicMenuFunction` UI node bound to
ringmenu type `0x0B` (string `"RingMenu_MusicPlayer"`). High-level:

```
RingMenu opens MusicPlayer
  -> reads DSMusicPlayerSystemResource (+0x30 = AllTracks array)
  -> for each visible row, looks up the JacketUITexture for that track
  -> binds the texture to the row slot
```

The system resource is `DSMusicPlayerSystemResource_1179_9026`.
`AllTracks` is an `Array<DSMusicPlayerTrackResource>` with 58 entries
in the base game.

### DSMusicPlayerTrackResource layout

From the Decima reflection metadata at `0x143d7d098`:

| Offset | Field |
|---:|---|
| `+0x10` | ObjectUUID (16 bytes) |
| `+0x20` | TrackId (uint32) |
| `+0x24` | Seconds / duration (uint16) |
| `+0x26` | MenuDisplayPriority (int16) |
| `+0x30` | AlbumResource pointer |
| `+0x38` | TitleText resource |
| `+0x40` | SoundResource (the playable sound) |
| `+0x48` | TrialSoundResource |
| `+0x50` | JacketUITexture (StreamingRef<UITexture>, inline 32B) |
| `+0x58` | StreamingRef.loaded (cached UITexture pointer once resolved) |

### How tracks get injected

`InjectCustomTracks` clones the `AllTracks` array, appends one cloned
TrackResource per user audio file, writes the array back. Each custom
track's `+0x40` (SoundResource) points at our cloned music chain
rooted in a custom Wwise bank. `MenuDisplayPriority` gets jacked up
(`30000+i`) so customs sort to the bottom of the music player list.

## 3. Wwise integration

DS2 uses Audiokinetic Wwise. The chain looks like:

```
DSMusicPlayerSystemResource
  -> DSMusicPlayerTrackResource
    -> DSWwiseSoundResource (+0x40)
      -> DSWwiseEventResource
        -> DSLO[0] = WwiseID (the AK::SoundEngine event id)
```

For a custom track:

1. Decode user audio to int16 stereo PCM, write a `WAVE_FORMAT_EXTENSIBLE`
   RIFF file (`.wem`). No external encoder needed - Wwise's PCM source
   plugin reads this directly.
2. Build a minimal custom Wwise bank with a music chain
   (MusicRanSeqCntr -> MusicSegment -> MusicTrack)
   cloned from the M61 trial chain (event id `3056202008`). Every HIRC
   object gets a fresh `ulID` so the engine doesn't dedup against the OG.
3. Patch durations inside the cloned HIRC items (see below).
4. Hook `AK::SoundEngine::LoadBankMemoryCopy` to load the custom bank.
5. Hook `AK::SoundEngine::SetMedia` to feed our WEM bytes for the
   media IDs the bank expects.
6. The custom TrackResource's `SoundResource` is a clone of a music-
   capable OG track's, with the WwiseID swapped to point at our bank.

### Duration patching

The M61 template chain has a fixed playback length of ~43.576 seconds
(the length of the BB's theme preview). Without patching, every custom
track cuts off at 43 seconds. Three places need to change:

**CAkMusicTrack (type 0x0B), body+0x3F:**
`AkTrackSrcInfo.fSrcDuration` (double, ms). This is what Wwise actually
uses to stop reading PCM from the source WEM. The struct layout is:
```
trackID      u32  +0x00
sourceID     u32  +0x04
fPlayAt      f64  +0x08
fBeginTrim   f64  +0x10
fEndTrim     f64  +0x18
<unknown>    u32  +0x20
fSrcDuration f64  +0x24   <- body+0x3F relative to full HIRC body start
```
Wwise reads this and stops decoding the clip when it reaches
`fSrcDuration` milliseconds.

**Important:** don't just slam this to 36000000ms (10 hours). If you do,
Wwise's in-memory PCM source exhausts the buffer but thinks it still has
~10 hours to play, so it loops the buffer from the start. The track
never ends - it loops indefinitely because the musicend marker that
signals "advance to next track" is also far in the future.

The fix is to set `fSrcDuration = actual track duration + 2000ms`. That
way the PCM plays to its natural end, and Wwise only has 2 seconds of
"expected data" left when the buffer runs dry, so the source closes
cleanly. The mod computes exact duration from the decoded sample count:
`durationMs = (double)frames / sampleRate * 1000.0`.

There are also float copies of the duration (in seconds) at body+0x67
and body+0x73 that we patch for good measure, but empirically the
double at 0x3F is the actual cutoff driver.

**CAkMusicSegment (type 0x0A), body+0x4C:**
`fDuration` (double, ms) - the segment's declared length. Set to
`durationMs + 1000ms`.

**CAkMusicSegment markers:**
The "musicend" marker position (another double, ms) controls when the
Decima music player advances to the next track. It needs to match the
actual track duration. The marker sits near 43576ms in the template;
we scan for doubles in the range `[origDur*0.5, origDur*1.5]` and set
them to `durationMs`. If this is left at 36000000ms the player never
gets the "ended" signal and sits idle for hours between tracks.

### Non-ASCII filenames

`WideToAcp()` converts wide chars to the ANSI code page. On Western
Windows (CP1252) Japanese/Korean/Chinese characters become `?`, so
`fopen(acpPath)` fails and the track is skipped silently.

Fix: store the file path as `std::wstring filepath_w` and use
`CreateFileW` + `ReadFile` into a `std::vector<uint8_t>`, then decode
from the buffer using the `*_from_memory` / `*_open_memory` variants
in dr_mp3, dr_flac, dr_wav, and stb_vorbis. For ffmpeg, pass a wide
commandline to `CreateProcessW`. The cached WEM path is always ASCII-
safe (based on the wemPath which uses non-Unicode filenames), so the
cache-hit path can still use `fopen`.

The "music-capable" filter (`pre-scan OG list, borrow only from
music-capable rows`) is needed because not all OG tracks route through
the music engine the same way. Some have sentinel WwiseIDs (e.g.
`82`) that go through a different play path. Borrowing one of those
makes the custom track silent or play through the wrong system.

`bb_theme_Preview` (Wwise event id `3993410792`) is the canonical
known-good source. The injection code preferentially borrows it.

### Why all tracks share a custom album

So all custom tracks group together in the menu under one artist
heading. Every custom track is registered against the same cloned
`DSMusicPlayerAlbumResource`. The album resource doesn't affect
playback, only menu sorting and the album cover shown in some
contexts.

### LEA-relocation is a dead end (confirmed)

Tried full LEA relocation of the slot table from +0x1970 to +0x4000
with TWO different buffer allocators:

1. VirtualAlloc'd buffer + LEA patches: crashed in `sub_14284ede0`
   (jemalloc arena helper) at `buf & ~0x3FFFFF + 0x60`. VirtualAlloc
   memory has no jemalloc chunk header, so when the engine handed a
   pointer-into-our-buffer to the heap free path, jemalloc's
   `addr & ~0x3FFFFF` chunk lookup hit unmapped memory.

2. Game-allocator buffer (`sub_1400a18a0`) + LEA patches: crashed
   IDENTICALLY at the same address with the same signature.

Same crash signature with proper jemalloc chunks rules out buffer
provenance as the root cause. The remaining hypothesis is the engine
has implicit pointer arithmetic somewhere - probably
`idx = (slot_ptr - &singleton[0x1970]) / 24` or
`singleton = slot_ptr - 0x1970` style code. Patched LEAs change WHERE
slot pointers come from, but unrelated arithmetic sites still assume
the original `0x1970` offset and produce wildly wrong indices that
get fed into other lookup tables, returning garbage pointers, eventually
crashed by the heap free path.

To proceed, would need to find every site doing that arithmetic. Sites
look like `lea reg, [slot_ptr - 0x1970]`, `sub reg, 0x1970`, or
computed-via-LEA negative offsets. They're scattered across multiple
functions and not enumerable without exhaustive disassembly + careful
testing. The buffer-redirect-via-game-allocator scaffolding stays in
the code (gated behind `.extend_cap`) for future work but the LEA
patch path is disabled.

### Background notes (the steps that led to the dead end)

Tried allocating a larger 0x6000-byte buffer via VirtualAlloc, redirecting
the music engine ctor to use it, and patching all the
`lea reg, [base+0x1970]` + `add reg, 0x960` instructions in
sub_140c11d50 / sub_140c10d90 to relocate the slot table to +0x4000
(well into the slack region).

Buffer-redirect alone (no patches) ran cleanly. Adding the LEA patches
crashed in `sub_14284ede0` (jemalloc arena helper) called from
`sub_140c10d90`'s realloc path. Crash diagnostics:
- Faulting address: our_buf base masked to 4MB alignment
  (`buf & ~0x3FFFFF + 0x60`)
- That's the jemalloc chunk-metadata location for our buffer's chunk
- VirtualAlloc memory has NO jemalloc chunk header, so the read gets
  garbage

Two interlocking problems:

1. **Buffer provenance** - the VirtualAlloc'd buffer has no jemalloc
   metadata, so any code path that hands a pointer-into-our-buffer to
   the heap (free, realloc) crashes when the heap looks up the arena.
   Fix: allocate via the game's own allocator (`sub_1400a18a0`) instead
   of VirtualAlloc - same heap, same arena, same metadata.

2. **Implicit pointer arithmetic on table bases** - the music engine
   may have code like `idx = (slot_ptr - &singleton[0x1970]) / 24` to
   recover slot indices. We can patch the LEAs that LOAD the table base,
   but this arithmetic might use the original `0x1970` baked into other
   instructions (or computed via `lea + sub`). Relocating the table
   would make those calculations produce wildly wrong indices that get
   fed to other lookup tables, returning bogus pointers, eventually
   crashing.

Path forward:

- Switch buffer allocator to `sub_1400a18a0` (sig already known). Test
  if buffer redirect still works. If yes, jemalloc is happy.
- Then attempt LEA patches with the proper allocator. If it STILL
  crashes, problem #2 is real and the LEA-relocation strategy is doomed.
- If problem #2 is real, switch to a hook approach: intercept the
  slot-table-walking functions (sub_140c11d50, sub_140c10d90) entirely
  and re-implement them with our own larger backing store. ~500 lines
  of reimplementation but avoids implicit-arithmetic mismatches.
- OR alternate cap dodge: intercept the music-engine "register track"
  function (haven't found it yet) so only 100 tracks ever go through,
  but they're swapped out at runtime as the user picks different tracks
  in the player UI. "Paged" track set rather than truly extended cap.

Knowledge captured: alloc site found, struct mapped (10440 bytes), all
~50 cap immediates and 11 LEAs identified, jemalloc interaction
diagnosed. Future work picks up at "switch allocator, attempt LEA
patches, evaluate if pointer-arithmetic problem is real".

### The hardcoded 100-track cap (still working on it)

The Wwise music engine has a 100-track total limit. OG game ships with
58 tracks, so user libraries cap at 42 customs. Going past 100 corrupts
engine state and crashes a few bank loads later in `sub_140c164b0`
(byte refcount decrement on a stale pointer reloaded from
`*(arg1+0x1918)`, register dump shows `rax=7f7fffff7f80000f` which is
the FLT_MAX bit pattern from neighboring data bleeding in).

The cap lives in the music engine singleton. Findings so far:

- Singleton is heap-allocated, **exactly 10440 bytes** (`0x28c8`).
  Allocated by `sub_1400a18a0(0x28c8)` inside `sub_141eb9500` at
  `141ebae6e`. Constructor `sub_140c0fef0` initializes the layout.
  Pointer stored in `data_146230fa8`.
- Cap enforced via `0x64` (decimal 100) immediates in
  `sub_140c11d50`, `sub_140c10d90`, and `sub_140c12320`. ~30 of them
  total, mostly in unrolled 8-element copy loops.
- The struct contains **three 100-cap arrays + one 32-cap array** at
  fixed offsets:
  ```
  +0x000..+0x960 : 100-entry x 24B  table (init 0/0/0x4b/0x4b/...)
  +0x960..+0x1900: 10 buckets x 400B (10x100 uint32 IDs)
  +0x1908..+0x1968: scalar state
  +0x1970..+0x22D0: 100-entry x 24B main slot table
  +0x22D0..+0x27D0: 32-entry x 40B (transition history?)
  +0x27D0..+0x28C8: tail state (volumes, SRWLock, etc.)
  ```
- Each table is sandwiched against state fields, so in-place extension
  collides. To go past 100, all three tables need relocation to a
  trailing slack region in an enlarged singleton allocation.

The path that needs implementing:

1. Hook `sub_1400a18a0` to detect `size == 0x28c8` and return an
   enlarged buffer (e.g., 0x6000 = 24576 bytes, gives ~14KB slack).
2. Find every LEA (`lea reg, [rcx+0x1970]`, `[rcx+0x968]`,
   `[rcx+0x000]`, `[rcx+0x22D0]`) across all music-engine functions
   and patch the disp32s to redirect to the slack region.
3. Patch the ~30 `0x64`/`0x63` cap immediates to a higher value.
4. Test every music engine state transition (battle music, scene
   change, alt-tab, save/load, music player UI) at >100 tracks - the
   bug only shows after a few bank loads, not immediately.

#### Cap immediates and LEAs mapped so far

Constructor `sub_140c0fef0` (only 5 LEAs total - clean):

```
140c0ff02  mov edi, 0x64                       ; MASTER COUNTER (reused twice)
140c0ff07  mov ecx, edi                        ; first loop count = 100
140c0ff0b  lea rax, [rbx+0x8]                  ; LEA: first table base+8
                                               ; [loop fills 100 x 24B at +0x000]
140c0ff3c  lea rcx, [rbx+0x960]                ; LEA: bucket array base
140c0ff45  mov r8d, 0xfa0                      ; bucket array size (4000 bytes)
                                               ; [memset(arg1+0x960, 0, 0xfa0)]
140c0ff57  lea rax, [rbx+0x1970]               ; LEA: slot table base
                                               ; [loop reuses rdi (still 100) - 100 x 24B]
140c0ffc4  lea rcx, [rbx+0x22d0]               ; LEA: transition history base
140c0ffcb  mov edx, 0x20                       ; transition history cap (32 entries)
                                               ; [loop fills 32 x 40B at +0x22d0]
```

Trick: the constructor reuses `edi=0x64` as count for BOTH the first
table (+0x000) and the slot table (+0x1970). Patching one immediate
extends both. Convenient.

Caller `sub_141eb9500` line 141ebae6e:

```
141ebae6e  void* rax_150 = sub_1400a18a0(0x28c8)        ; ALLOC SITE
141ebae80  rbx_36 = sub_140c0fef0(rax_150)              ; ctor
141ebae8b  data_146230fa8 = rbx_36                      ; assign global
141ebae92  sub_140c14d70(rbx_36)                        ; post-init #1
141ebae9f  sub_140c10300(rbx_36, sub_140c109f0(rbx_36)) ; post-init #2
141ebaea7  sub_140c10880(rbx_36)                        ; post-init #3
141ebaeaf  sub_140c10d90(rbx_36)                        ; post-init #4 - bucket fill
141ebaeb7  sub_140c11ee0(rbx_36)                        ; post-init #5 - slot fill
```

Refcount/walk function `sub_140c11d50`:

```
140c11d6d  lea rdi, [rcx+0x1978]               ; LEA: slot table head (+8)
140c11d74  mov esi, 0x64                       ; CAP: 100 iterations
140c11dbc  lea rax, [rbp+0x1970]               ; LEA: slot table base
140c11dc3  lea rdx, [rax+0x960]                ; LEA: end-of-table marker (size=100*24)
```

Bucket walk `sub_140c11fa0`:

```
140c11fdd  call sub_14017ebe0(arg3, 0x64)      ; alloc capacity hint (NOT a hard cap -
                                               ;  array grows via sub_1400dcd20)
140c11ff1  rdi = 9                             ; bucket idx capped at 9 (10 buckets)
140c12001  lea i = (rdi+6)*0x190 + arg1        ; bucket base = arg1 + (rdi+6)*0x190
140c1200e  while (i != &i[0x64])               ; CAP: 100 entries per bucket
```

Bucket-walk + slot-update function `sub_140c12320` (heavily unrolled,
~17 cap immediates):

```
140c12330  mov eax, [rcx+0x1900]               ; load current bucket idx (0..9)
140c12351  cmovg eax, ecx                      ; cap at 9
140c1235d  imul rax, rax, 0x190                ; bucket stride (400)
140c123d6  add rax, 0x968                      ; bucket base = arg1 + idx*0x190 + 0x968
                                               ;   (with imul output already including arg1)
140c123ea  cmp r11, 0x63                       ; CAP CHECK x16 in unrolled body
140c1240b  ja 0x140c12410                      ;   (each branch with `cmp r11, 0x63` /
140c12407  cmp r11, 0x63                       ;    `cmp ecx, 0x64` repeated)
... [16 more cap branches in 8-element-unrolled copy loop]
140c125ba  cmp r11, 0x64                       ; OUTER LOOP CAP

140c125c4  mov r8, [r9+0x1940]                 ; +0x1940 = a state pointer
140c125cb  movsxd rax, [r9+0x1938]             ; +0x1938 = a state count
140c125d2  imul rdi, rax, 0x38                 ; 56-byte stride iteration
140c12631  add r8, 0x38                        ; iterates through 56-byte entries
140c1265b  lea rcx, [r9+0x1930]                ; LEA: another field
140c12688  lea rcx, [r9+0x1930]                ; (same)
140c126b1  mov [r9+0x1930], ebx                ; writes to +0x1930
140c126c8  jmp 0x140c12120                     ; tail-call to dynamic-array helper
```

Note: the `0x190 + 0x968` pattern in `sub_140c12320` is the bucket
base formula: `arg1 + bucket_idx*0x190 + 0x968`. The formula assumes
buckets are 0x190 (400) bytes each starting at +0x968. Patching to
support more entries per bucket changes 0x190.

Total enforcement points found so far:

| Function       | Cap immediates | Tables touched (LEA / arith)        |
|----------------|----------------|-------------------------------------|
| sub_140c0fef0 (ctor)   | 1 (master 0x64) + 1 (0x20)| 4 LEAs: +0x008, +0x960, +0x1970, +0x22d0 |
| sub_140c14d70 (post-init) | 2 (i_2/i_3=0xa) + ~10 unrolled blocks | inline writes, no relocation possible |
| sub_140c10d90 (post-init) | ~20 (mix 0x64/0x63 + outer 0xa) | 3 walks of slot table, 1 walk of bucket array, allocates per-bucket via sub_1400b69a0(0x190) |
| sub_140c11d50 (refcount walk) | 1 (0x64) | 3 LEAs: +0x1970, +0x1978, +0x960 size |
| sub_140c11fa0 (bucket walker) | 1 walk (0x64) + 1 alloc hint | 1 imul-based bucket compute |
| sub_140c12320 (unrolled copy) | ~17 (mix 0x64/0x63) | imul+add for buckets, 9 LEA-like base computations |
| sub_140c11ee0 (post-init #5) | 0 (uses dyn arrays at +0x1948) | walks +0x1940 array (38B stride - separate structure) |
| sub_140c11fa0 callees... | TBD | TBD |

Conservative total: **~50 cap immediates + 11 LEAs** across the
post-init and runtime functions. Plus whatever lives in
sub_140c10300, sub_140c10880, sub_140c109f0 (also called from the
init sequence at sub_141eb9500).

Critical detail learned from `sub_140c14d70`: the first table at
+0x000 is initialized via **10 nested unrolled wmemcpy blocks per
outer iteration** (10 outer × 10 unrolled = 100 entries). Extending
this past 100 isn't a single immediate patch - the unrolling is
structural. Same for several other init paths.

Critical detail from `sub_140c10d90`: the slot table at +0x1970 is
walked **THREE times** in this single function via the pattern
`lea rax, [rcx+0x1970]; add rcx, 0x960; while (rax != rcx) ... rax
+= 0x18`. The 0x960 is the END pointer (100*24). To extend the slot
table we'd need to patch 0x960 → larger AND ensure the table physically
extends to the new boundary.

Strategy options ranked from simplest to most invasive:

A. **Just patch the 1 master 0x64 in the constructor** to a smaller
   value (e.g., 0x32 = 50) and see what happens. Safe experiment - if
   the engine then crashes at 50 tracks, that proves the constructor's
   cap matters and the other immediates need patching too. If it still
   works at 100, the constructor cap is just for init scope and other
   walks self-limit.

B. **Hook sub_1400a18a0(0x28c8)** to allocate larger but DON'T move
   tables - just enlarges trailing slack. Patch ONLY the master 0x64
   in the constructor + the 2 caps in sub_140c11d50. Tables grow into
   adjacent state regions (corrupting them) but maybe specific
   downstream code doesn't care if those state fields are nonzero.
   High crash risk but quick experiment.

C. **Full relocation**: Hook alloc to enlarge, move all 3 tables to
   trailing slack, patch every LEA + every cap immediate. Multi-day,
   high test burden, real fix.

Trick option D: **two-stage cap**. Keep tables at 100 cap. Make the
mod's InjectCustomTracks register only 42 customs with the music
engine but show ALL custom tracks in the AllTracks UI list. When user
clicks track 43+, swap a registered slot to point at the requested
track at runtime. Effectively a paged cache. Loses state of the
swapped-out track but keeps unlimited library. Worth considering as
an alternative to the relocation.

#### Corruption mechanism - working theory

The engine's allocator `sub_1400a18a0` is the GAME-WIDE allocator
called from thousands of places (390KB of xrefs). Cannot hook safely.
Cleaner intercept is `sub_140c0fef0` (the constructor) called once
with the 0x28c8 buffer.

The +0x1918 pointer that crashes is written by `sub_140c14480` line
140c14699: `*(rdi+0x1918) = sub_140ac64d0(...)`. `sub_140ac64d0`
internally calls `sub_14268afb0(data_14a1a1020, 0, arg1, 0)` and
returns the result. So the corruption could be either:

1. `sub_14268afb0` returns garbage when arg1 is something the engine
   can't resolve (e.g., a music context for a track that doesn't fit
   in the 100-bucket lookup).
2. Some other code writes garbage directly to +0x1918 (haven't found
   such a write yet).

The bucket arrays at +0x968 hold 10 x 100 uint32 IDs. With 101 OG+
custom tracks, only 100 fit in the bucket. Track lookup queries the
bucket; with one missing track, the lookup returns null/garbage. If
the music engine doesn't null-check the lookup result, garbage gets
written to +0x1918 and crashes later.

Ramifications:

- The 100-cap isn't really a "table cap" - it's a lookup table cap.
- Extending requires either bigger buckets (per-bucket cap > 100) OR
  more buckets (count > 10) OR both.
- The bucket walks (sub_140c11fa0 etc.) use `while (i != &i[0x64])`
  where 0x64 is element count for bucket scan (= 400 bytes of int32s).
  Extending buckets means patching this immediate AND making each
  bucket physically larger.
- The 32-entry transition history at +0x22D0 is unrelated to track
  count - it's a runtime state buffer. Doesn't need extension.

Cleanest concrete attempt path:

```cpp
// Hook sub_140c0fef0 (the music engine ctor).
// Original signature: ctor(void* buf_0x28c8) -> void* singleton.
// Sig: 48 89 5c 24 08 48 89 74 24 10 57 48 83 ec 20 48 8b d9 bf 64 00 00 00 8b cf 33 f6 48 8d 43 08

static void* __cdecl Hook_MusicCtor(void* origBuf) {
    // 1. Allocate larger buffer (+ trailing slack for relocated tables)
    void* big = VirtualAlloc(nullptr, 0x6000, MEM_COMMIT|MEM_RESERVE,
                             PAGE_READWRITE);
    if (!big) return g_origMusicCtor(origBuf); // graceful fallback

    // 2. Run original constructor on our larger buffer (it inits the
    //    standard 0x28c8 region, leaving trailing 0x3738 untouched).
    void* ret = g_origMusicCtor(big);

    // 3. Patch in-place: the cap immediates and LEAs in this same
    //    function and the runtime walkers. Done via sig-scanned
    //    addresses + VirtualProtect + byte writes.
    //    Specifically:
    //      sub_140c0fef0 +0x12: BF 64 00 00 00 -> BF C8 00 00 00 (master 200)
    //      sub_140c0fef0 +0xDB: BA 20 00 00 00 (transition history cap, may stay)
    //      sub_140c0fef0 +0xCD: 48 8D 8B D0 22 00 00 -> relocate to +0x4000
    //                                                  (transition history relocated
    //                                                   to slack, freeing +0x22D0)
    //      sub_140c11d50 +0x24: BE 64 00 00 00 -> BE C8 00 00 00 (walk cap 200)
    //      sub_140c11d50 +0x73: 48 8D 90 60 09 00 00 -> 48 8D 90 C0 12 00 00 (size 0x12C0 = 200*24)
    //      sub_140c10d90: 3 slot-table walks need same cap+size patches
    //      sub_140c12320: heavily unrolled, ~17 cap immediates - skip first pass
    //      sub_140c11fa0: bucket cap 0x64 stays for now (only extending slot table)

    // 4. (Optional) Free the orig buf - but we don't know the right
    //    deallocator. Leak it for now (10440 bytes, one-time cost).
    return ret;
}
```

Risks for the first attempt:

- Sub_140c12320 is heavy unrolled with ~17 0x64 caps; if NOT patched,
  it'll continue treating the slot table as 100-entry and will skip
  rows 100-199. That's tolerable for read but BAD if it does writes.
- The first table at +0x000 also has a 100-cap (uses the same master
  0x64 in ctor). Patching master to 200 also extends THAT table -
  which would then write past +0x960 into bucket region (bucket
  region gets memset right after, so first-table extension is wiped).
  Net effect: first table effectively only has 100 entries even if we
  ask for 200. Probably fine since the first table isn't directly
  involved in the crash mechanism.
- Bucket arrays stay at 100/bucket. If the 101st track lookup goes to
  buckets, it still won't find the track and returns garbage. So
  extending JUST the slot table might not actually fix the crash.
- The bucket lookup needs separate attention. We may need to extend
  bucket count (10 -> 20+) or per-bucket size (100 -> 200) too.

Verdict: even the minimal viable attempt has multiple correlated
patches with uncertain side effects. Each iteration needs in-game
testing because the bug only manifests after a few bank loads.

Failed attempts that got recorded so they don't get retried:

- **Self-hosting the MRSC parent** (clone OG `CAkMusicSwitchCntr`
  629350378 into our bank with a new ID, point custom MRSCs at the
  clone). The cloned parent keeps its child list and switch refs
  pointing at OG MRSCs Wwise can't resolve, so every custom event
  returns `playingId=0`. Doesn't help with the 100-cap anyway since
  the cap is enforced one layer above bank loading. Code stays in
  for reference but force-disabled at the call site.
- **Diagnostic dump piggybacked on `LoadBankMemoryView`/`PostEvent`
  hooks**, and the same dump from a separate watcher thread. Both
  consistently crashed the game during early bank loading (around
  bank #18-#24, ~10s into startup) even though the dump function
  early-returns when the singleton is null. Cause unclear - smells
  like MinHook trampoline interaction or a static-local init guard
  in the dump helper. Worked fine when called from the existing
  `InjectCustomTracks` PRE/POST checkpoints.

## 4. Album art binding (the part I didn't finish)

The plan was: each custom track displays its own cover art (from MP3
ID3 APIC tag or a sidecar PNG) without messing up the OG track
jackets.

### Why it's hard

DS2 binds music jacket textures by `UITexture.ObjectUUID`. The custom
tracks all clone OG TrackResources, including the JacketUITexture
StreamingRef's UUID. So the engine's UUID cache returns the **same**
runtime UITexture for the custom row as the OG row. They share a
texture, they share a D3D12 dst, they share an SRV. Anything I do to
that dst affects both rows.

### What I tried

**Attempt 1: CTR upload-source substitution.** Hook
`ID3D12GraphicsCommandList::CopyTextureRegion`. When the engine
uploads BC7 bytes to a known music-jacket dst, swap the source bytes
for our custom BC7. Visually it works, custom rows show whatever
custom art I pick. But every OG row sharing that dst gets the same
custom art too. Hash-rotating per-dst gives some variety but the
collateral is fundamental. This is what the album-art codepath was
doing before I gated it off.

**Attempt 2: SRV redirect.** Hook
`ID3D12Device::CreateShaderResourceView` for known music-jacket dsts
and re-call with a different resource pointer. Works, but the SRV
chain (`sub_140d14d90` and friends) only fires at LOAD time, once per
UITexture. The renderer reuses the same SRV slot for every row that
references the texture, so redirecting doesn't help with per-row
distinction. Stack trace from the auto-locked music-jacket SRV chain:

```
frame[2] DS2+0x210cfff
frame[3] DS2+0x20ca614
frame[4] DS2+0x1458a2f  (sub_1414589a0 = Texture wrapper factory)
frame[5] DS2+0x145afb0  (sub_14145af80 = serialized -> runtime convert)
frame[6] DS2+0xcf775    (job dispatcher level)
frame[7] DS2+0xcf602
```

**Attempt 3: StreamingRef getter hook.** Hook `sub_1426d96a0`, the
`StreamingRef<UITexture>::get()` virtual. Build a clone UITexture per
custom track, register `(customTr+0x50, clone)`, return the clone for
matching srefs. Result: `hits=0`. The music UI never goes through this
getter. It reads the resolved pointer some other way, probably via
`DSUIInstallMenuDataSourceResource.MusicJacketImageTextures` at
install-menu-singleton + 0x60. The array exists, but my singleton
finder kept hitting too many false positives during validation.

**Attempt 4: UITexture clone + tr+0x58 patch.** Allocate a fresh
UITexture, memcpy bytes from an OG, patch `customTr +0x58` to point
at the clone. Game survives but the engine ignores the patch
(consistent with attempt 3, it's not reading +0x58 for music UI).

Layout from a runtime deep-dump of an OG UITexture (absolute offsets):

```
+0x00: vtable (RTTIRefObject base)
+0x08: refcount + flags (lo32 = refcount, hi32 = 0x49C flags)
+0x10..+0x18: ObjectUUID (16 bytes)
+0x20: uint32 flags
+0x30: vtable (Resource sub-object base, multiple inheritance)
+0x38: refcount + flags (sub-object)
+0x40..+0x48: sub-object UUID
+0x50, +0x58: heap ptrs (engine pool sub-resources)
+0x80: heap ptr in D3D12 driver pool (~0x2BA... range), small TextureDX12 wrapper
+0x140: heap ptr in D3D12 driver pool, large TextureDX12 wrapper
+0x158, +0x168, +0x170, +0x180, +0x188: more sub-resource ptrs
+0x1D0, +0x1D8: more
```

Total instance size is at least `0x1E0` bytes. The Decima
type-descriptor reports size `0x38` for UITexture (kind=4, size at
typedesc+0x10), which is wrong for the runtime instance. The
deserializer must know the real size from on-disk metadata, I didn't
trace that path.

Two more allocator gotchas if you go this route:

- DS2's allocator returns 0x50-byte slots. memcpy'ing 0x200 bytes
  overruns into the next allocator block and corrupts internal state,
  the allocator returns null for everything afterward.
  `HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0x200)` works fine
  for a clone buffer.
- Don't blindly bump refcounts at `+0x08` of every embedded heap
  pointer. Not all of them are RTTIRefObjects, some are internal
  allocator blocks, and bumping the wrong field zaps allocator
  metadata. Skipping the bump is fine for clones that live the whole
  session.

### The path I'd try next

Inject our own UITexture instances under fresh UUIDs into DS2's
resource cache, then patch `customTr +0x50` (the UUID inside the
StreamingRef) to those UUIDs. Engine's UUID lookup misses the OG
cache, finds our injection, allocates per-clone D3D12 dsts. No
collateral.

Steps (none done):

1. Find the resource cache (UUID -> Resource* map). Probably
   reachable from the streaming-manager pointer the StreamingRef
   vtable's resolve path touches at
   `(*ref)[1] & 0xfffffffffffff`.
2. Build a complete UITexture clone with proper sub-object pointers
   (the sub-resources at +0x50, +0x58, +0x80, +0x140, etc), which
   probably means cloning the inner `Texture` wrapper too. Texture is
   constructed via `sub_14210d6c0` and references TextureView slots
   at instance offsets `+0x78..+0x118` (stride 0x50, up to 8 slots).
3. Allocate our own D3D12 dsts
   (`ID3D12Resource::CreateCommittedResource` with the same desc as
   OG dsts), upload custom BC7 bytes, wrap in a TextureDX12 wrapper
   compatible with what `Hook_DS2WrapResource` tracks.
4. Inject into the cache, patch the UUID in our StreamingRef.

The render-thread crash in section 5 means iterating on this is slow,
sessions only last 30-150 seconds before DS2 blows its own stack.

## 5. The render-thread `__chkstk` crash

Persistent silent crash 30-150 seconds into a session, regardless of
what I had hooked. Crash dump:

```
rip = game+0x2ABCCF7  (= __chkstk)
frame[5] = game+0x11C755C  (sub_1411c7550, allocates 0x144210 bytes on stack)
frame[6] = game+0x11BF800  (per-frame render pipeline)
frame[7] = game+0x11BCE40  (thin wrapper)
frame[8] = game+0xCF775   (CallableJob dispatcher)
```

`sub_1411c7550` allocates a 1.27MB stack frame. DS2's job worker
threads have ~880KB stack reserve (computed from rsp at crash minus
the AV address). When the function calls `__chkstk` to commit guard
pages down to `rsp - 0x144210`, it reads off the bottom of the
reserved stack and the stack-overflow exception kills the process
before our VEH can run.

This crash exists in vanilla DS2, just rarer. Hooks add enough frames
+ per-call overhead to push it over the threshold reliably.

What I tried that didn't fix it:

- `MH_DisableHook` on every D3D12 hook once the initial diagnostic
  pass was done. Verified hooks fully detach (CTR call counter froze
  at the disable moment), still crashed in `__chkstk`.
- Hooking `kernel32!CreateThread` to bump stack reserve to 4MB.
  Doesn't help, the offending render threads come up via
  `NtCreateThreadEx` (or before our hook installs). Got
  `g_threadStackBumps = 85` but the render thread isn't in there.
- `SetThreadStackGuarantee`. Only extends the post-overflow guarantee,
  not the actual reserve.

What would probably fix it:

- Hook `ntdll!NtCreateThreadEx` to bump stack reserve at the lowest
  layer DS2 uses for thread creation.
- Or find DS2's job-thread-pool init and patch the stack reserve
  there.

The shipped build (SHIP_MODE 1) only runs Wwise hooks, which don't
fire on the render hot path, so the threshold doesn't get crossed in
normal use.

## 6. Music jacket fingerprinting (research-mode only)

When SHIP_MODE 0, the ASI loads known-good BC7 bytes from
`albumjacket/fingerprints/large_*.bc7` (extracted via Odradek from
each song's UITexture resource), hashes them, and compares the hash
during CTR upload events.

Each match identifies a `(D3D12 dst, song name)` pair. Across a
session you build a complete map of "which dst contains which song's
jacket" without needing to chase static type info.

This is what proved attempt 1 has full collateral: once a dst is
identified, modifying it affects every UI surface that reads it
(menu rows, now-playing widget, anywhere else).

The identified dsts also form a contiguous block in DS2's D3D12
driver allocator pool (`~0x000002BA...` range), so the music jacket
cluster has a geometric signature too. Limited use, the cluster has
other UI textures (player profile icons) interleaved with the album
art.

## 7. Useful binja addresses

Static (image-base relative; subtract `0x140000000` for RVA, add
`g_gameBase` at runtime):

| Address | What |
|---|---|
| `0x140103b50` | `ResourceFactory::Create` (generic Decima allocator) |
| `0x140103970` | resource size lookup (kind switch) |
| `0x140103a90` | resource custom-alloc prelude (kind=4 path) |
| `0x140d113e0` | per-UITexture loader (creates the small + large D3D12 dsts) |
| `0x140d11830` | 512x512 BC7 dst creator |
| `0x140d15680` | 256x256 BC7 dst creator |
| `0x14210d6c0` | Texture instance constructor (`Texture::Init`) |
| `0x14145ac92` | the canonical Texture+UITexture construction sequence |
| `0x142701ba0` | UITexture default zero-constructor |
| `0x142701d50` | UITexture initializer (writes Texture pointer at +0x30) |
| `0x1426d96a0` | `StreamingRef<UITexture>::get()` (slot 2 of vtable) |
| `0x1411c7550` | the 1.27MB stack-frame render function (crash culprit) |

Type descriptors (`data_*` symbols):

| Address | What |
|---|---|
| `0x1460584d0` | UITexture |
| `0x145e12460` | TextureResource |
| `0x14418f920` | StreamingRef<UITexture> |
| `0x143d7d098` | DSMusicPlayerTrackResource reflection metadata |
| `0x143ee97c8` | DSUIInstallMenuDataSource MusicJacketImageTextures field metadata |

## Credits

@ShadelessFox, for [odradek](https://github.com/ShadelessFox/odradek),
[decima-native](https://github.com/ShadelessFox/decima-native), and
[death-stranding-2-localizer](https://github.com/ShadelessFox/death-stranding-2-localizer).
The `RTTIKind` enum and `Array<T>`/`Ref<T>` struct layout in the mod
source came directly from the localizer / decima-native headers. The
Odradek type schema is what produced all the DSMusicPlayer* field offsets
used throughout the injection code.

@rudowinger, for running Odradek against the live game and sharing the
resulting dumps - the UITexture layout, StreamingRef details, and
MusicJacketImageTextures field discovery all came from those.

The Decima reverse engineering community, particularly the work on
Horizon Zero Dawn / Death Stranding 1 that established the resource
format and RTTI patterns.
