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

#### Slot table populator: `sub_140c10c50` (the actual root cause)

After re-reading the disasm with fresh eyes, the corruption mechanism
is much simpler than the bucket-overflow theory above. The slot table
at `+0x1970` is populated by `sub_140c10c50`. Its loop body:

```
0x140c10d24:  lea r8, [rcx+0x1970]        ; r8 = slot_table_base
0x140c10d30:  mov rcx, [r9]                ; rcx = current TrackResource ptr
0x140c10d33:  test rcx, rcx                ; null check
0x140c10d3f:  mov eax, [rcx+0x20]          ; eax = track id (uint32)
0x140c10d49:  mov [r8],     eax            ; slot[+0]    = track id (lo32)
0x140c10d4c:  mov [r8+0x8], rcx            ; slot[+8]    = track ptr
0x140c10d50:  mov [r8+0x10], rdx           ; slot[+0x10] = first-table self-ptr
0x140c10d54:  mov [rdx],    eax            ; first_table[i] = track id
0x140c10d7d:  add r8, 0x18                 ; slot += 24
0x140c10d81:  add r9, 0x8                  ; track++
0x140c10d85:  cmp r9, r10                  ; r10 = array_end (count-bounded)
0x140c10d88:  jne 0x140c10d30
```

**There is no cap check on `r8`.** The loop iterates the full OG
TrackResource array and writes one slot per entry. The OG array has
58 entries by default; with our `InjectCustomTracks` extension to
142, the loop writes 142 slot entries.

The slot table region between `+0x1970` and `+0x22D0` only holds 100
entries (100*24 = 0x960). Slot writes 100..141 (= our custom slots
42..83) spill into the **transition history at `+0x22D0`** (32
entries, 40 bytes each).

Because slot stride (24) and transition stride (40) are coprime, the
spilled slot writes land at misaligned positions inside transition
entries. The Ref<T> field at `transition[N]+0x18` (the destructor
target zeroed via `sub_1400ba3c0` from `sub_140c109f0`) ends up
holding partially-overwritten bytes - sometimes a real cloned-resource
pointer (works), sometimes the upper 32 bits of one slot's fields
merged with adjacent data, which materializes as `0xAD......` or
`0x00000000xxxxxxxx`-shaped garbage that AVs when dereferenced as a
vtable pointer at +0x90.

This is the crash we've been chasing. The dtor-router shim on
`sub_1400ba3c0` only catches the cases where the +8 field cleanly
holds a custom ID; misaligned partial overwrites leak through with
non-`AD8` patterns and AV in the obfuscated dispatcher.

##### Why the existing hard-cap-at-42 release works

`InjectCustomTracks` caps customs at `MUSIC_ENGINE_TRACK_CAP - 58 = 42`.
With 100 total tracks, `sub_140c10c50` writes exactly 100 slots, fills
the slot table to the boundary at `+0x22D0`, and never spills into the
transition history. No corruption.

##### Concrete fix paths (in order of cost)

1. **Hook `sub_140c10c50` and add a 100-iter cap.** Same outcome as
   the release version (only first 100 tracks playable) but the
   experimental branch's 200-cap upstream becomes safe to enable
   without crashing the engine. Customs in slots 100+ show in the UI
   but won't play through the slot-routed dispatch. Trivial. ~10 lines.

2. **Hook `sub_140c10c50` and rewrite the loop to write to a
   relocated 200-slot table** (in trailing slack at e.g. `+0x4000`).
   Then patch every other site that reads the slot table to use the
   new base. The reader sites we know:
   - `sub_140c10d90`  (bucket fill: `lea ..., [rdi+0x1970]` and ends
     at `+0x960`; iterates 100 in inner loop)
   - `sub_140c11d50`  (slot walk: `arg1+0x1978` plus `+0x1970` and
     `+0x960`, count `0x64`)
   - `sub_140c10c50`  (the populator itself - rewrite via hook)
   - Plus the `r8 - 0x1970` recovery in the populator that writes
     `first_table[i]` - need to keep that delta consistent or skip
     the first-table writes entirely.
   - Plus the 32-entry transition history INIT in `sub_140c109f0`
     at `arg1 + 0x22e8 + i*0x28` - this stays at +0x22D0; it's not
     part of the slot table, just adjacent.
   This is the real path forward but is the LEA-relocation work the
   prior section concluded was hard. The new finding makes it easier
   because we now know we ONLY need to relocate the slot table, not
   also the bucket arrays (the bucket caps come from the populator's
   slot_index, so if the populator runs, buckets get filled without
   needing larger size).

3. **Reimplement `sub_140c10c50` in our hook to write to BOTH a
   relocated 200-entry table AND maintain the original 100-entry
   table for the readers we don't patch.** Most invasive but
   minimizes patch surface. Probably overkill.

Recommended next step: do (1) immediately so the experimental branch
stops crashing on 142 tracks. That gives us a working baseline to
iterate (2) on top of.

##### `sub_140c10c50` xrefs (for hooking)

- Called from `sub_140c109f0` at `+0x10a32`. This is the music engine
  init path. `sub_140c109f0` immediately follows the populator with
  a 32-iteration loop calling `sub_1400ba3c0(transition[i]+0x18, 0)`
  and `sub_1400ba3c0(transition[i]+0x28, 0)` to destroy any pre-
  existing Ref<T> in the transition history. With our spilled slot
  writes corrupting the transition region, those destructor calls
  see partial overwrites and AV.
- Called from `sub_141ebc650` at `+0x1ebda70`. This is an event/state-
  machine handler (massive function, 9-case switch) - one case path
  performs a full music engine refresh: `sub_140c10c50` →
  `sub_140c10d90` (bucket fill) → `sub_140c11ee0` → `sub_140c12090` →
  `sub_140c12120` (playlist shuffle). Same spill problem applies
  here. Probably triggered by save-load / scene change / similar
  state-reset events.

Both callers pass the singleton pointer (`data_146230fa8` typically,
or via `rsi`/`rbx_42` after singleton getter). Hook target is
`sub_140c10c50` itself - both call sites then become safe.

Sig for `sub_140c10c50` prologue: `4C 8B 05 ?? ?? ?? ?? 4D 85 C0 0F 84 ?? ?? ?? ?? 48 8D 81 98 19 00 00 BA 0A 00 00 00`

##### Sister-corruption: the first table at `+0x000`

`sub_140c10c50` ALSO writes `first_table[i] = track_id` via
`mov [rdx], eax` where `rdx = r8 - 0x1970` (= singleton + i*24, the
first 24-byte-per-entry table at `+0x000`). The first table is sized
for 100 entries (ends at `+0x960`), and writes for i>=100 spill into
the **bucket array at `+0x968`**. So for each spilled slot we corrupt
TWO regions: transition history at `+0x22D0+` and bucket array at
`+0x968+`. The corrupted bucket array then makes downstream bucket
lookups return our custom IDs as if they were real slot indices,
which gets dereferenced as object pointers and AVs.

This compounds the failure modes. A simple iteration cap on the
populator fixes both at once because nothing past slot 99 gets
written.

##### Singleton layout (full map, post sub_140c0fef0 ctor)

Confirmed by reading the ctor disassembly end-to-end:

```
+0x0000 - +0x0960  First table  (100 × 24B)
+0x0960 - +0x1900  Bucket array (10 pages × 100 × 4B = 10 × 0x190)
+0x1900 - +0x1910  Small scalar headers (page idx, magic 0x46, etc)
+0x1910 - +0x1938  More scalars (current track, runtime state)
+0x1938 - +0x1968  0x30-byte "current playback" struct
+0x1968 - +0x1970  scalar
+0x1970 - +0x22D0  Slot table   (100 × 24B)              <-- target for extension
+0x22D0 - +0x27D0  Transition history (32 × 40B)
+0x27D0 - +0x28C8  Tail state (current track ref/refs, SRW, etc)
```

Total ctor-initialized = 0x28C8 (the original buffer size we observed).

The slot table and first table are **coupled**: each slot at
`+0x1970+i*24` has its `+0x10` field point to the corresponding
first-table entry at `+0x000+i*24`. The bucket array at `+0x968+`
stores `track_id` values per bucket page (10 pages × 100 entries),
used as a hash-table-style lookup to find tracks by id.

##### Save-game compatibility constraint

`sub_140714000` is the music-state save-game serializer (called
during the global save flow at `+0x140714e37` + `+0x140714e5d`).
It does:
```
(*(*rcx_137 + 8))(rcx_137, rbx_20, 0x1910)   // write 0x1910 bytes
sub_140c11d50(rbx_20)                          // walk slots
```

So the saved blob is **the first 0x1910 bytes** of the singleton:
first table + bucket array + a few scalars. The slot table at
`+0x1970+` is NOT in the save - it's rebuilt from the OG track
resource array via `sub_140c10c50` on every game launch / save
load.

`sub_140c15080` is the corresponding loader. It reads back the
0x1910 byte block, then walks each entry to recover slot
back-pointers (the heavy unrolled `j s< 0x64` loops at lines
`+0x140c159...+0x140c15c..`).

**Implication for extending:**
- Slot table can be extended to 200 entries in trailing slack
  WITHOUT breaking save compat (it's rebuilt every load anyway).
- First table CANNOT be extended in place - its size is baked into
  the 0x1910 save blob. Extending breaks save backward compatibility.
- Bucket array same story (it's part of the 0x1910 blob).

So a save-compatible uncap leaves the first table and bucket array
at 100 entries and only widens the slot table. Slots 100..199 would
not have first-table back-pointers (slot+0x10 = NULL or unused) and
would not be findable via bucket lookup.

That's an open architectural question: does the music player UI
dispatch play via direct track-resource pointer (so slots 100..199
work fine), or via bucket-id lookup (so they don't)? Need to trace
the click→play path to know. Suspect the former because the player
already iterates the track resource array directly to render the
list, so it has the resource pointer in hand at click time.

##### Complete site enumeration for slot-table extension

Patch displacement `0x1970` → new slot-table base
(suggested `+0x4000` in the 0x6000 buffer):

| Function          | Offset(s) | Asm pattern                              |
|-------------------|-----------|------------------------------------------|
| `sub_140c0fef0`   | +0x67     | `lea rax, [arg1+0x1970]` (ctor init)     |
| `sub_140c10c50`   | +0xD4     | `lea r8,  [rcx+0x1970]` (populator)      |
| `sub_140c10c50`   | +0xF2     | `lea rdx, [r8-0x1970]`  (back-ptr calc)  |
| `sub_140c10d90`   | x3 sites  | slot-table base loads (bucket fill)      |
| `sub_140c11d50`   | +0x1D     | `lea rdi, [arg1+0x1978]` (= base+8)      |
| `sub_140c11d50`   | +0x6C     | `lea rax, [arg1+0x1970]`                 |
| `sub_140c15080`   | x10+      | slot-table base loads in load-game unroll|

Patch immediate `0x960` → new slot-table size (`0x12C0` for 200 entries):

| Function          | Pattern                                       |
|-------------------|-----------------------------------------------|
| `sub_140c11d50`   | `lea rdx_1, [rax+0x960]` (end calc)           |
| `sub_140c10d90`   | end calc(s) for inner walk loop               |

Patch immediate `0x64` → new slot count (`0xC8` for 200):

| Function          | Sites | Notes                                       |
|-------------------|-------|---------------------------------------------|
| `sub_140c0fef0`   | x2    | `i_5=0x64` and `i_3=0x64` (init two tables) |
| `sub_140c10d90`   | x1+   | inner slot walk bound                       |
| `sub_140c11d50`   | x1    | `rsi = 0x64`                                |
| `sub_140c12120`   | x1    | `sub_14017ebe0(arg1+0x1958, 0x64)` - vector |
|                   |       | resize cap; semantics unclear, may stay     |
| `sub_140c15080`   | x10   | one per per-page load loop (j s< 0x64)      |

What stays untouched (because save compat / orthogonal to slot table):
- `sub_140c12320` (playlist copy, 17 caps - bucket-page-sized, not
  slot-count-sized)
- Bucket array layout (10 pages × 100 × 4B, sized 0xFA0) - keeps OG
  size, only first 100 slots get bucket entries
- First table at `+0x000` - keeps 100 entries
- Transition history, tail state - unrelated to track count

##### The save compat path forward

Architecture:
1. Hook `sub_140c10c50` to write to relocated slot table at
   `+0x4000`. Cap output at 200. For slots 0..99, ALSO write the
   first-table entries at `+0x000+i*24` (preserves OG behavior for
   readers that only know about the first table). For slots
   100..199, skip first-table write (out of bounds) and skip the
   `slot+0x10 = first_table[i]` self-pointer (set to NULL or to a
   harmless dummy).
2. Hook `sub_140c10d90` (bucket fill) and `sub_140c11d50` (slot
   walk) to use the relocated base + extended cap. Bucket fill
   would still only emit bucket entries for slots 0..99 (because
   bucket page size is 100 and we're not extending it). Slots
   100..199 are visible to the slot walker but not bucket-lookupable.
3. Save game: still writes 0x1910 byte block (unchanged). Saves
   created with our extension are backward-compatible with stock.
4. Load game: hook `sub_140c15080` only if needed - the load path
   already calls `sub_140c10c50` which we hook, so the slot table
   gets repopulated correctly post-load.

Rather than patching N sites of the original functions, we
re-implement them in our hooks. That's ~150 lines of C++ but each
function is small, and we sidestep the displacement-encoding
mechanics entirely.

##### Click→play path: SLOT-RESOLVED, not direct (decided)

Traced via `sub_140c126e0` (music engine state-machine tick at
+0x140c126e0, reads `data_146230f88` 4 times). It maintains a
"current playback queue" at:
- `singleton + 0x1938`: count
- `singleton + 0x1940`: pointer to entries (56B each)
- `singleton + 0x1948`: ID array count
- `singleton + 0x1950`: pointer to int32 ID array
- `singleton + 0x1924`: currently-selected track id

The play loop iterates `+0x1940` looking for `*(entry+0x10)+0x20`
matching `*(*(rdi+0x1950) + idx*4)`. The `+0x1940` entries are
populated by `sub_140c10d90` (bucket fill) FROM the slot table at
+0x1970. So:

```
slot_table[i]            -> populated by sub_140c10c50 from trackArr
+0x1940 playback queue   -> populated by sub_140c10d90 from slot_table
+0x1924 selected id      -> set by user click via state machine
play tick                -> walks +0x1940 looking for selected id
```

If slots 100..199 are empty (because we hard-cap the populator
at 100), `sub_140c10d90` skips them, no playback queue entries
exist for those tracks, and the play tick can't find them when
selected. **Customs at trackArr index 100+ won't play through
the music player UI.**

##### Path forward (decided)

The cheap cap-hook fix (currently in place on this branch) stops
the corruption crash so users can run extend_cap with > 42 customs
without the engine destroying itself. But customs 43..N (N=84 at
file count) will appear in the UI and not play - confusing UX.

For actual >100 PLAYABLE customs, the slot table must be relocated
to trailing slack with capacity 200 AND `sub_140c10d90` /
`sub_140c11d50` must be hooked to walk the relocated table. The
patch surface is enumerated above. ~150 lines of hook code, all
mechanical work after the architecture is settled.

Recommended order:
1. **Test the current cap-hook build** with 84 tracks loaded.
   Confirms the corruption is fixed (game doesn't crash, doesn't
   freeze, doesn't black-screen).
2. **If 1 works**: customs 43..84 will appear in UI but not play.
   That's expected. Now we know the cap-hook is safe to ship as a
   "safety net" so future big libraries don't crash even if the
   real fix isn't done yet.
3. **Then start the relocation work**: hook `sub_140c10c50` to
   write to `+0x4000` instead of `+0x1970` (200 slot capacity),
   hook `sub_140c10d90` to walk the relocated table (200 inner-
   iter cap), hook `sub_140c11d50` similarly. The save-compat is
   preserved because none of these touch the +0x000..+0x1910
   region that gets serialized.
4. **Edge cases to handle in the hooks**:
   - `slot[i].back_ptr` (slot+0x10) for i>=100 should be NULL
     since first table doesn't have entries past 99 (preserves
     save compat). Bucket fill checks `if (rdx_1 != 0)` so this
     is safe.
   - Bucket array stays 100-entry (not extended). Bucket lookups
     keyed by track id can only point to slots 0..99. Need to
     understand if `+0x1940` queue size matters - it's `*0x38`
     stride, count from `+0x1938`, dynamically sized. Should
     accommodate 200 entries fine if `sub_140c10d90` writes
     them all.
   - The save game's `+0x1910` byte block doesn't include slot
     table or playback queue - both are rebuilt every load. So
     slot table relocation has zero save-compat impact.

##### Status

Cap-hook on `sub_140c10c50` is in working tree - safety net so the
engine doesn't crash with > 100 trackArr entries. Real fix is the
slot-table relocation: hook `sub_140c10c50` to write to `+0x4000`
instead of `+0x1970` (200 capacity), hook `sub_140c10d90` and
`sub_140c11d50` to walk the relocated table. None of it touches
the save-compat region (+0x0000..+0x1910), so existing saves keep
working. ~150 lines of hook code total.

##### Stage 2 in-game test results (2025-05-05)

Stage 2 tested live with 84 customs:
- All 21 byte patches landed cleanly.
- `slot-populator(reloc): wrote 142 slots at sing+0x4000 (origCount=142)` - all
  142 entries (58 OG + 84 customs) populated into the relocated table.
- Engine reads from `+0x4000` correctly via the patched bucket-fill;
  every track played through the music player UI produced a clean
  PE → playingId without errors.
- No crash, no hang, ~10 minutes of gameplay including combat and
  save/load cycles. Clean log.

Open question: **the music player UI may not be exposing tracks at
trackArr index 100+ (= our customs[42..83])**. The user couldn't find
"Gorillaz Pirate Radio Take Over (6)" (custom[83]) in the in-game
list, even though it's loaded into trackArr at index 141, has full
metadata (title, duration=132s, sound resource, MenuDisplayPriority
30083), and is in the relocated slot table.

**Most likely explanation: bucket array overflow.**

The bucket array at `+0x968` is 10 pages × 100 entries × 4B
(= 0xFA0 bytes, baked into the save-game blob layout - we don't
extend it). Bucket-fill in `sub_140c10d90` walks the slot table
and emits one bucket entry per slot, with a `cmp esi, 0x64; jge`
per-page cap that stops at 100 entries per page.

After our slot-table relocation:
- Slot table at `+0x4000` holds 200 entries (all 142 tracks).
- Bucket-fill walks all 142 entries.
- Per-page cap of 100 means bucket entries are emitted only for
  the first 100 tracks across all pages. Tracks 100..141 (=
  trackArr indices) get NO bucket entries.

Mapping: customs are appended after OG tracks, so:
- trackArr[0..57]   = OG (always have bucket entries)
- trackArr[58..99]  = customs[0..41]  (have bucket entries)
- trackArr[100..141] = customs[42..83] (NO bucket entries)

If the music player UI's track-listing or click-to-play resolves
via the bucket array (likely - it's the engine's primary lookup
table by track id), customs at index 42+ would be invisible /
non-clickable. This **exactly matches the observed behavior**:
custom[34] visible+playable, custom[83] not findable.

Verifications to do next session:
- Add diagnostic log to `sub_140c10d90` hook output: dump bucket
  array entries post-fill, count how many our customs got slots.
- Decompile any function that reads bucket-array entries by track
  id (search xrefs to displacement +0x968 within the engine
  cluster) - confirm UI uses bucket lookup.

##### Fix paths for bucket array

Same 3-tier escalation as the slot table:
1. **Relocate the bucket array too.** Move from `+0x968` to
   somewhere in slack (+0x5000 say) with 200 entries per page
   (10 × 200 × 4 = 0x1F40 bytes). Patch every reader that uses
   the `+0x968` displacement OR the `+0x190` per-page stride.
   Per-page cap immediates (`cmp esi, 0x64`) need bumping too -
   and they're imm8 sign-extended so we hit the same encoding
   problem we hit with the slot walk in section 3 (need imm32
   form, can't fix in place without longer encoding).
2. **Hook the bucket lookup function** and reimplement in C.
   Slower lookup (O(N) instead of O(1)) but flexible.
3. **Increase per-page count, decrease page count.** Keep the
   total bucket array size the same (0xFA0). Use 5 pages × 200
   entries = same 0xFA0 bytes. Avoids relocation but requires
   patching the page-stride (+0x190 → +0x320) and per-page cap
   sites. Might still hit the imm8/imm32 encoding wall.
4. **Just don't hide tracks.** Hook the music player UI's track-
   listing function directly and bypass bucket lookup entirely.
   Most invasive but cleanest.

Recommended: option 2 (hook + reimplement bucket lookup). The
bucket lookup is one specific function with a defined signature.
Reimplementing it as O(N) walk over the 200-slot table is a
~30-line hook.

Next session priority: identify the bucket-lookup function from
xrefs to data_146230fa8 + read of bucket entries at `+0x968+
page*0x190 + idx*4`.

##### Other unverified theories for the UI invisibility

The bucket-overflow theory above is the strongest match but
unverified. Other plausible theories worth eliminating before
spending hooks on bucket extension:

- **DSCatalogueRewardResource gate.** Each OG track has a
  CatalogueRewardResource that ties to the music-player UI's
  unlock list. Our custom TrackResources aren't registered in
  any CatalogueRewardResource. If the UI lists tracks via
  CatalogueRewardResource, only OG would show - but the user
  CAN see custom[34], so this likely isn't a hard gate. Maybe
  a partial filter (some UI mode shows trackArr, another shows
  Catalogue list).

- **Some unset byte field in our cloned TrackResource.** The
  resource is 0x300 bytes copied from source; we override
  TrackId / Seconds / MenuDisplayPriority / Flag / TitleText /
  OpenConditionFact. Anything else (unknown fields at +0x60..
  +0x300) inherits from source. If source has a field that
  encodes "hidden in UI past index N", customs would inherit
  whatever value the source had. Worth dumping all 0x300 bytes
  of an OG vs custom track and diffing.

- **Music player UI render cap somewhere distinct from engine.**
  The Decima UI scroll viewport may have a hardcoded N visible
  rows. Doesn't explain it being deterministic on track index
  though.

- **`sub_140c11fa0`-style page selection in UI.** Bucket pages
  might be category buckets (one per UI tab/album-style
  grouping). If our customs cluster in just one or two pages
  and exceed the per-page cap there, only those overflowing
  pages have hidden tracks. UI shows other pages fine.

Verifying the bucket-overflow theory takes 10 minutes:
1. Add diagnostic to dump the bucket array post-fill.
2. Check how many of our custom IDs (0xAD......) are in the
   bucket array vs the slot table.
3. If slot table has 142, bucket has < 142 → bucket overflow
   confirmed. Hook + reimplement bucket lookup.

If bucket has all 142 but UI still hides some → it's something
else and we need to look at the UI render path (call stack from
a UI scroll click capture).

##### UI render path identified: `sub_1416e4020`

Found it. The music player menu UI iterates **NOT** the trackArr,
but the **int32 array** at `data_146230fa8 + 0x1950` (count at
`+0x1948`):

```c
sub_1416e4020:
    int r12 = max(5, *(singleton + 0x1948))   // visible row count
    for (rdi_1 = 0; rdi_1 < r12; rdi_1++) {
        // walk playback queue at +0x1940 looking for matching slot
        while (i != end) {
            if (i.valid && i.track.id == int32_array[rdi_1]) break
            i += 0x38
        }
        sub_14180b1d0(arg1, ..., i, rdi_1, ...)  // render row
    }
```

The int32 array stores TRACK IDs (uint32). The UI shows one row per
entry. Click-to-play (`sub_14180d6e0`) also uses this array via
`sub_140c12290` to add new entries.

**The int32 array is populated by walking the bucket array.** When a
slot makes it into the bucket (via `sub_140c10d90`'s filter), its
track ID is appended to the int32 array via something like
`sub_140c12290` (or similar - need to confirm the chain).

So the chain is:
```
slot table (+0x4000, 200 entries with our reloc patch)
   |
   v   sub_140c10d90 (bucket fill, filtered by album.+0x50 match)
   |
bucket array (+0x968, 10 pages × 100, only 35 entries observed)
   |
   v   ??? (some function that walks bucket and appends to int32)
   |
int32 array (+0x1950, count at +0x1948, dynamic-sized via sub_140c12290)
   |
   v   sub_1416e4020 (UI iter)
   |
music player menu list (only ~35 visible rows)
```

**Why bucket fill filters most slots:**

The inner check in `sub_140c10d90` has two gates:

```c
if (rcx_2 != 0 && (*(rdx_1 + 4) & 1) != 0) {     // back-ptr flag
    rcx_3 = *(rcx_2 + 0x30);                      // slot.track.album
    if (rcx_3 != 0 && *(rcx_3 + 0x50) == rsi_1)  // album.+0x50 == outer track
        ... write bucket entry ...
}
```

The check `*(album + 0x50) == outer_track` requires the ALBUM's
"primary track" reference to match the OUTER LOOP's current track.
For OG tracks this matches because each album's `+0x50` points to
its primary track and the album-track linkage is consistent.

For our customs, we keep the source track's ALBUM (don't clone it).
Album.+0x50 still points to the SOURCE track, not our custom. So
the outer iteration on our custom: `album.+0x50 (= source) ==
our_custom` is FALSE. Skip. No bucket entry. Not in int32 array.
Not in UI list.

The 8 customs that DID make it in: probably borrowed from source
tracks that were the album's primary, AND those albums got hit
during outer iteration because outer included OG tracks or somehow
the linkage worked out. Coincidental match.

##### The fix - hook the int32-array builder

Best path forward: **hook `sub_140c12290` (the int32-array
appender)** and after the engine's normal population, manually
append all our custom track IDs to the array.

Approach:
1. After bucket fill runs (e.g. detected via heartbeat or hooking
   the right caller), iterate our `g_tracks` vector
2. For each custom whose ID is NOT already in the int32 array,
   call `sub_140c12290(singleton, custom_id)` to append it
3. The UI then iterates the int32 array (now containing all 84
   customs) and renders all of them

Critical question: does the UI render `sub_14180b1d0` need the
playback queue (+0x1940) to also have an entry, or does it work
with the int32 array alone? Looking at the code, it walks the
queue looking for a matching ID and falls back to `singleton +
0x27e0` (a default state) on miss. So clicks on tracks not in the
queue would dispatch via the default path. May or may not play
correctly - need to test.

If queue entry is required, we additionally need to hook the
queue builder or reimplement the bucket→int32→queue chain.

##### Sigs collected for next session

- `sub_1416e4020` (UI render): begins with `int32_t arg_8 = 0x6565a4ff`
  literal followed by `sub_142320530(arg1+0x20, ...)`. Let me confirm
  the byte sequence with disasm.
- `sub_140c12290` (int32 array appender): we already xref'd it from
  `sub_14180d6e0` and `sub_14180d560`. Sig signature TBD.
- `sub_14180d6e0` (click-to-play handler): the calling convention is
  `(arg1, arg2)` but I haven't traced what arg2 represents yet -
  probably the UI element clicked.

##### The bigger picture

Stage 2 (slot-table relocation) is solid at the engine layer. The
play dispatch works. The remaining problem is purely UI visibility:
the bucket-fill's album-primary check is the root filter, not a
size cap. Even if we extended bucket pages to 1000 entries each,
the album-primary check would still filter out our customs.

Two viable approaches for the next iteration:
1. **Hook int32-array appender** to bypass bucket fill entirely.
   Most flexible, doesn't require fighting the album-primary check.
2. **Make our cloned tracks' albums point back at our custom**
   instead of inheriting the source's album. That requires cloning
   the album resource per-custom and patching its +0x50. Larger
   surface, may have other downstream effects.

Approach 1 wins on cost.

##### Sigs and exact mechanics for the int32-array fix

`sub_140c12290` (int32-array appender, the `g_origAppendInt32`):

```
prologue:  48 89 5C 24 10 56 48 83 EC 20 48 8B 5A 10 48 8B 35 ?? ?? ?? ?? 48 85 DB 74 ??
```

API: `void __cdecl(void* arg1_unused, void* arg2_with_track_at_+0x10)`.
Reads `track = *(arg2 + 0x10)`, then `track_id = *(track + 0x20)`.
Linearly scans `singleton+0x1950` (count `singleton+0x1948`) for
matching ID; if not found, calls `sub_1400ae140` to grow the
vector, appends the ID, increments count, calls `sub_140c12320`
(playlist resort).

Calling our customs through this is awkward because we need to
pass a stack-allocated 0x18-byte stub with `[+0x10] = custom_track_ptr`.

`sub_1416e4020` (UI render):

```
prologue:  48 89 5C 24 10 55 56 57 41 54 41 55 41 56 41 57 48 8D 6C 24 D9 48 81 EC 90 00 00 00 4C 8B F1 C7 45 67 FF A4 65 65
```

The literal `0xFFA4_6565` is unique enough to make the sig stable.

##### The actual root cause (clearer take)

The bucket-fill outer loop iterates the OG TrackResource array
(which we extend to 142). For each entry, the inner walks the
slot table looking for a slot whose `slot.track.album.+0x50 ==
outer_loop_track`.

For our customs, `slot.track.album` is the source track's album
(we don't clone albums - all customs borrow). `album.+0x50`
points to the SOURCE track. So the match condition fires only
when outer_loop_track == source track. That's a side effect of
inheritance, not what we want.

Result: when outer iterates OG track 45 ("bb_theme"), all the
30 customs that borrowed from track 45 match in the inner loop.
The bucket page for that OG track fills with up to 100 entries
(1 OG + 30 customs + others). Per-page cap.

When outer iterates OUR custom track, no slot's album.+0x50
points at our custom. No match. No bucket entry for our customs
that didn't share an OG outer.

##### Fix strategy: hook `sub_140c109f0` (the engine init wrapper)

Best path: hook the function that calls `sub_140c10c50` (populator)
and `sub_140c10d90` (bucket fill) in sequence. After bucket fill
runs, scan the int32 array. For each custom track ID not present,
manually append.

```cpp
// sketch:
static void __cdecl Hook_MusicEngineInit(void* singleton) {
    g_origMusicEngineInit(singleton);  // runs populator + bucket fill

    if (!g_extendCapEnabled || !g_relocateSlots) return;

    uint8_t* sing = (uint8_t*)singleton;
    int32_t  count = *(int32_t*)(sing + 0x1948);
    uint32_t* arr = *(uint32_t**)(sing + 0x1950);

    for (auto& t : g_tracks) {
        // skip if already present
        bool found = false;
        for (int i = 0; i < count; i++) if (arr[i] == t.stableId) { found = true; break; }
        if (found) continue;

        // append: needs vector grow first. The vector struct is at
        // +0x1948 (count) / +0x1950 (ptr). sub_1400ae140 grows it.
        // Easier: just call sub_140c12290 with a fake stub.
        struct Stub { char pad[0x10]; void* track; };
        Stub stub = {};
        stub.track = t.pTrackResource;
        sub_140c12290(nullptr, &stub);
    }
}
```

We need `g_origMusicEngineInit` resolved (sub_140c109f0). Sig
should be straightforward - it's the function that calls
`sub_140c10110` then `sub_140c10c50` then 32× `sub_1400ba3c0`.

`sub_140c109f0` xrefs to `data_146230f88`:
- `+0x140c10a10` (assignment of singleton ptr)
- `+0x140c10a69`, `+0x140c10bd6`, `+0x140c10c1c`

Caller of sub_140c109f0 → ?? (need to check).

##### Open questions for next session

1. Will the rendered UI rows for our manually-appended IDs work
   when clicked? Click-to-play uses `sub_14180d6e0` which pulls
   queue entries by index. If queue (+0x1940) doesn't have an
   entry for our custom, click might fall back or fail silently.
   May need to also populate the queue.

2. Or: hook `sub_14180d6e0` (the click handler) to detect clicks
   on our custom track IDs and route them through the existing
   PostEvent path that already plays customs correctly.

3. Album cloning approach (alternative): clone each source's
   album per-custom and set `cloned_album.+0x50 = custom_track`.
   Then bucket-fill's natural check passes. Tradeoff: 84 × 0x80
   = 10.5KB album allocations. May have other downstream filter
   effects we haven't seen yet.

##### Bottom line

Stage 2 (slot relocation) gives us all 200 slots populated with
our tracks - that part is solid. The UI cap is purely the
bucket-fill album-primary filter. Two clean fix routes:

1. **Hook sub_140c109f0**, post-process int32 array to inject
   missing custom IDs. UI shows them. Click handler may need
   extra hook to dispatch correctly. ~50 lines.

2. **Clone each custom's album** with proper primary-track-ref.
   Bucket-fill naturally includes them. Heavier, may have other
   effects. ~60 lines plus diagnosis of any side effects.

Approach 1 is the cleaner first attempt.

##### Final hookpoint identified: `sub_140c11ee0`

Tracing the music engine init from `sub_141eb9500` (global game
init), the music engine is set up in this exact sequence at
`+0x141ebae6e..+0x141ebaeb7`:

```
1. sub_1400a18a0(0x28c8)             // alloc singleton (we hook this)
2. sub_140c0fef0(buf)                // ctor (we hook this)
3. data_146230fa8 = singleton
4. sub_140c14d70(singleton)          // clear-init regions
5. sub_140c10300(singleton, sub_140c109f0(singleton))  // some init w/ return value
6. sub_140c10880(singleton)          // another init
7. sub_140c10d90(singleton)          // bucket fill (we patched)
8. sub_140c11ee0(singleton)          // playback queue + int32-array setup
```

After step 8, `+0x1948/+0x1950` (the int32 array the UI iterates)
is fully populated with whatever bucket-fill produced. **This is
the hook target.**

`sub_140c11ee0` body (already decompiled earlier):
```
sub_140c11fa0(arg1, *(arg1 + 0x1900), arg1 + 0x1948)  // grows int32 array via dedup-append
sub_140c12090(arg1, 0)                                 // ?
sub_140c12120(arg1)                                    // playlist shuffle (+0x1958/+0x1960 array)
// then iterate +0x1940 playback queue, set flags
```

**Hook plan:**

```cpp
typedef void (__cdecl* QueueSetupFn)(void* singleton);
static QueueSetupFn g_origQueueSetup = nullptr;

static void __cdecl Hook_QueueSetup(void* singleton) {
    g_origQueueSetup(singleton);  // builds int32 array from bucket entries

    if (!g_relocateSlots) return;

    // Append our custom track IDs to the int32 array if not already present.
    uint8_t* sing = (uint8_t*)singleton;
    int32_t*  countPtr = (int32_t*) (sing + 0x1948);
    uint32_t** arrPtrPtr = (uint32_t**)(sing + 0x1950);
    int32_t   curCount = *countPtr;
    uint32_t* arr = *arrPtrPtr;

    for (auto& t : g_tracks) {
        // dedup: already present?
        bool found = false;
        for (int32_t i = 0; i < curCount; i++) {
            if (arr[i] == t.stableId) { found = true; break; }
        }
        if (found) continue;

        // append. easiest path: call sub_140c12290 with a stub that has
        // our track ptr at +0x10. the function handles vector grow +
        // count increment + dedup itself.
        struct Stub { uint8_t pad[0x10]; void* trackPtr; };
        Stub stub = {};
        stub.trackPtr = t.pTrackResource;
        g_appendInt32(nullptr, &stub);
    }

    // re-read since g_appendInt32 grew the array
    Log("[MUSICMOD] [extend] queue-setup: int32 array now has %d entries\n",
        *countPtr);
}
```

Sigs needed:
- `sub_140c11ee0`: prologue. Need to fetch.
- `sub_140c12290`: prologue (already have above).

##### Open question: does click-to-play work for added entries?

The UI render at `sub_1416e4020` looks up each int32 entry against
the playback queue (`+0x1940`) by track ID. For our customs whose
slot ISN'T in the queue (because bucket-fill skipped them), the
fallback is `singleton + 0x27e0` (a default entry in the tail
state region).

`sub_14180d6e0` (click handler) uses queue index. If our custom
ends up routed through the fallback default, click might dispatch
the default entry's track instead of our custom.

If clicks fail, the additional fix is: also populate the playback
queue (`+0x1940`) with our customs. Each entry is 0x38 bytes:
- `+0x10`: track resource pointer
- `+0x35`: valid byte (0 = valid for matching)
- other fields probably needed too

Would need to disasm `sub_140c10d90`'s bucket-write logic and
mirror it.

Or simpler: hook `sub_14180d6e0` to detect clicks on our custom
track IDs and dispatch via the existing PostEvent path that
already plays customs correctly.

##### Implementation that landed

Two changes to `Hook_SlotPopulator` and one new hook on `sub_140c11ee0`:

1. **Extended first-table at `singleton+0x5400`.** The album-primary
   filter at `sub_140c10d90+0x113` reads `(slot+0x10).+4 & 1`. Slots
   100..199 used to have `slot+0x10 = nullptr` so the filter failed,
   keeping customs out of the playback queue. The slot populator now
   writes a parallel first-table at `+0x5400` (100*24 bytes, 0x140
   margin from slot-table end at 0x52C0, 0x2A0 margin to buffer end
   at 0x6000). Each entry gets `trackId` at `+0` and music-capable
   bit at `+4`, mirroring what the original populator does for slots
   0..99.

2. **`Hook_QueueSetup` on `sub_140c11ee0`.** After the original runs
   (which calls `sub_140c11fa0` to populate the int32 array at
   `+0x1948`/`+0x1950` from one bucket page filtered by playback-
   queue match), iterate `g_tracks`, and for each `stableId` not
   already in the array, call `sub_1400ae140(sing+0x1948, count+1)`
   to grow it, write the ID at `[count]`, then increment count. This
   is the same call sequence the engine itself uses inside
   `sub_140c11fa0`. The UI iterator at `sub_1416e4020` reads
   `count = *(sing+0x1948)`, walks `*(sing+0x1950)`, and for each
   entry walks the playback queue at `+0x1940` to find a matching
   `(queue.+0x10).+0x20 == id` to render the row.

Two new sigs:
- `sub_140c11ee0`: prologue + `mov edx, [rcx+0x1900]; lea r8, [rcx+0x1948]; mov rbx, rcx`
- `sub_1400ae140`: prologue + `mov r14d, edx; mov rbp, [rcx+8]; mov rsi, rcx; cmp edx, [rcx+4]`

Both gated behind `.relocate_slots` so Stage 1 (cap-fix-only) is
unaffected. If clicks on customs past index 42 don't play correctly
even with the row visible, the next thing to check is
`sub_14180d6e0` (click handler) - we may need to redirect to
PostEvent there too.

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
