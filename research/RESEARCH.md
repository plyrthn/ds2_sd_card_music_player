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
