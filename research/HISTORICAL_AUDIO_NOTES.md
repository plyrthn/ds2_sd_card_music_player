# DS2 Music Player Audio - Reverse Engineering Notes

These are notes from poking at the music player's audio system in Death Stranding 2.
Goal was to add custom tracks that play custom audio.

**The injection side works.** I got brand new track slots to show up in the actual
music player UI, with custom title and artist text, alongside the OG tracks. Both
custom tracks are selectable, displayable, and the music player UI treats them as
real entries. As far as I know this is the first time anyone has added new
DSMusicPlayerTrackResource entries to the in-game music player.

The audio playback side is not finished. The slots are there but pressing Y still
plays the source track's audio (whichever existing track i cloned from). Sharing
in case it helps someone else pick this up.

Tested against the Steam build of DS2, manifest `3400946842679455339`
(version current as of April 2026). Image base 0x140000000. Specific function
offsets here are from that build and will drift on updates.

## Setup

DS2.exe is a tiny launcher stub (~1.2 MB). The actual game is mapped a second time
into the same process as a much larger module (>80 MB). All addresses below are
relative to the base of that large module unless noted otherwise. Find it at runtime
by enumerating loaded modules and picking the one with `SizeOfImage > 0x5000000`.

DS2.exe statically links Wwise and exports the AK::* symbols. Use GetProcAddress on
the mangled names to grab the real function pointers, e.g.

```
?PostEvent@SoundEngine@AK@@YAII_KIP6AXW4AkCallbackType@@PEAUAkCallbackInfo@@@ZPEAXIPEAUAkExternalSourceInfo@@I@Z
```

## Music Player Object Graph

The Decima RTTI types i care about:

```
DSMusicPlayerSystemResource
  +0x20: AllArtists  (RawArray of DSMusicPlayerArtistResource*)
  +0x30: AllTracks   (RawArray of DSMusicPlayerTrackResource*)

DSMusicPlayerTrackResource (size 0x300)
  +0x20: TrackId           (uint32)
  +0x24: Seconds           (uint16, displayed duration)
  +0x26: MenuDisplayPriority (int16) -- NOT actually used by UI sort
  +0x28: Flag              (uint8)
  +0x30: AlbumResource     (Ref<AlbumResource>)
  +0x38: TitleText         (Ref<LocalizedTextResource>)
  +0x40: SoundResource     (Ref<SoundResource>) -- full play
  +0x48: TrialSoundResource (Ref<SoundResource>) -- sample preview
  +0x50: JacketUITexture   (StreamingRef<UITexture>)
  +0x58: OpenConditionFact (Ref<BooleanFact>)

DSMusicPlayerAlbumResource
  +0x28: TitleText           (Ref<LocalizedTextResource>)
  +0x30: ArtistNameText      (Ref<LocalizedTextResource>)
  +0x40: ArtistNameTextForTelop (Ref<LocalizedTextResource>) -- shown in HUD overlay
```

Adding a track to the player works by appending a `DSMusicPlayerTrackResource*` to
`AllTracks` after `DSMusicPlayerSystemResource` finishes loading. I hook
`IStreamingSystem::Events::OnFinishLoadGroup` to catch the load.

The trick to making the UI accept the new entries is that the cloned object has to
be 0x300 bytes copied verbatim from an existing track (vtable matters, refcounts
matter, internal padding matters). Allocate via the Decima allocator if possible;
HeapAlloc seems to work in practice but i didn't stress test it.

The UI groups tracks by their `AlbumResource` reference, not by `MenuDisplayPriority`
(despite the field name). Setting prio to 30000 had no visible effect. To force a
custom track to a specific position you probably need to assign it a unique
AlbumResource that sorts where you want.

## The Audio Chain (what i'm sure of)

When the user presses Y on a track in the music player, the engine posts a Wwise
event. The chain looks like this:

```
DSMusicPlayerTrackResource
  -> SoundResource (at +0x48 for sample, +0x40 for full)
    -> [resolution step i don't fully understand]
      -> LocalizedSimpleSoundResource
        -> AK::SoundEngine::PostEvent(eventId from LSSR+0xD8, gameObj, ...)
```

The play event ID lives at offset 0xD8 of the LocalizedSimpleSoundResource. Each
track in the player has its own LSSR with its own event ID. (`+0x6c` on the LSSR is
a float `1.0f`, almost certainly a volume scalar, not an event ID. I had this wrong
for a while.)

Stop is the universal Wwise event `0x61605A9D` (1633704605). All tracks share it.

## The Wwise Wrapper Stack (current build offsets)

```
sub_1426b5ef0   game-side PostEvent wrapper (0x3D7 bytes)
                  - inserts a per-event tracking entry
                  - calls AK::SoundEngine::PostEvent with:
                      flags |= 0x100001
                      callback = sub_1426b5080  (always)
                      cookie   = pulled from the tracker entry

sub_1426a6000   thin wrapper that hard-codes some flags     (PLAY path)
sub_1426a6050   wrapper variant 2 with arg7 fconvert        (STOP path)
sub_1426a60d0   wrapper variant 3 with extra setup
sub_14269b270   stateful wrapper used by SoundInstance methods

sub_1426b5080   PostEvent completion callback. Handles
                  AK_EndOfEvent (cleanup tracker)
                  AK_Marker     (matches "MusicEnd" / "MusicTelop" strings,
                                 sets flags 0x1000 / 1 on the instance)
```

The callback `sub_1426b5080` is the most reliable signal that a PostEvent is from the
music player. Every music event uses it.

## WwiseSimpleSoundInstance

Allocated by the music player as a per-track audio instance. 0x340 bytes total.
vtable at `0x143440FA0` (static).

Useful instance fields:

```
+0x00   vtable (== WwiseSimpleSoundInstance::vftable for SoundInstance)
+0x30   flag byte (bit0 = playing, bit1 = ?)
+0x66   reentrancy guard
+0x178  pointer to AudioNodeHolder (Decima Ref<AudioNode>)
+0x32C  current playing ID (set by Play, cleared by Stop)
+0x334  PER-INSTANCE EVENT OVERRIDE (default 0; if non-zero, Play uses this instead
        of the default audio_node[+0xD8])
```

The factory functions are `sub_14269A710` and `sub_14028DB70`. They are not called
directly; they are stored in Decima type descriptor tables (e.g. `0x143440F20`,
`0x143453DE8`, `0x1431251C0`) and the Decima type system invokes them.

Vtable highlights:

```
[0x40]  sub_142696410   IsPlaying  (1-line: returns *(arg1+0x187) & 1)
[0x90]  sub_142686C80   UpdatePosition
[0xF0]  sub_14269A5D0   HasOverride  (3-line: returns *(arg1+0x334) != 0)  <-- KEY
[0xF8]  sub_142685FF0   Init/RegisterGameObj/SetPosition
[0x108] sub_14269B3D0   Play
[0x110] sub_14269B4E0   Stop, 30 ms fade
[0x118] sub_14269B680   Stop variant
[0x120] sub_14269B7C0   Stop wrapping sub_14269B6B0 (uses ExecuteActionOnEvent)
[0x128] sub_14269B7E0   Play, spatial setup
[0x130] sub_14269B540   Stop, 100 ms fade
[0x138] sub_14269B5A0   Generic stop (caller-supplied fade)
```

The `+0x334` override is the cleanest hijack point, IF you can identify which
instance corresponds to your custom track. I could not, because (see below) my
cloned tracks share their LSSR with their source.

## Globals Worth Knowing

```
data_1462591F8   pointer to DSMusicPlayerSystem singleton
                   +0x47C8 = collection that the WSSI factory adds new instances to
                   +0x49E8 = something the AK_Marker callback writes into

data_146259260   pointer to the audio resource manager
                   vtable[0x20] is the resolver that binds a SoundResource into an
                   AudioNodeHolder on a fresh WwiseSimpleSoundInstance. I didn't
                   disassemble this in depth. UNKNOWN whether it materializes a new
                   LSSR or looks one up by GUID.
```

Both globals are zero at load time. They get initialized at runtime by the audio
system init. There are 499 reads of `data_146259260` and 37 reads of
`data_1462591F8` across the binary.

## What Worked

- **Adding new track slots to the music player UI.** Cloning
  DSMusicPlayerTrackResource (full 0x300 bytes) and appending to AllTracks makes
  the new entry visible, selectable, and treated as a real track by the UI. The
  jacket art, title text, artist label, and album grouping all render. This is
  the part nobody (that I know of) had cracked before.
- Writing custom title/artist text via cloned LocalizedTextResource.
- Loading a custom Wwise bank at runtime via `AK::SoundEngine::LoadBankMemoryCopy`.
  I use an "extended" bank built by copying a real audio bank from memory, finding
  its HIRC chunk, and appending custom Sound/Action/Event items so they inherit the
  bank's working bus routing. Loads cleanly, returns AK_Success.
- `AK::SoundEngine::SetMedia` to provide PCM audio data for custom source IDs.
  Returns AK_Success.
- `AK::SoundEngine::PostEvent` with my custom event IDs returns a non-zero playing
  ID, meaning Wwise recognizes the event chain.
- MinHook integration (after my naive 14-byte JMP trampoline kept getting
  defeated by relative branches in function prologues).

## What Did Not Work

- `MenuDisplayPriority` for sort. UI groups by album reference instead.
- Hooking `AK::SoundEngine::ExecuteActionOnEvent`. Function has a conditional jump
  at byte ~0x14 of the prologue and my installs were unstable. Even with MinHook,
  hooking it crashed mid-frame. Worked around it by hooking the four caller-side
  wrappers above, which in any case turned out to only ever post Stop / Pause
  actions, not Play.
- Substituting the event ID inside my PostEvent hook. The substitution fires
  cleanly (visible in logs, returns valid playing IDs) but i don't hear any
  difference. Two suspects, i didn't finish narrowing it down:
    * My custom Sound items in the extended bank produce silence (bus routing,
      DirectParentID inheritance, or codec mismatch).
    * My cloned tracks share the same LSSR as their source, so even when the
      music player triggers play it uses the source's gameObj/event and i'm
      hijacking the wrong call.

## Open Questions

These are the things you'd want to figure out next.

1. **The SoundResource -> LocalizedSimpleSoundResource resolution.**
   `TrackResource[+0x48]` is a SoundResource (vtable 0x143444xxx area). The
   factory receives a LocalizedSimpleSoundResource (vtable 0x1431251A0). Something
   between them resolves one to the other, almost certainly through
   `data_146259260.vtable[0x20]`. I didn't disassemble that resolver. Once you
   know how it works you can either clone an LSSR with a unique GUID per custom
   track, or hook the resolver directly to swap in your own.

2. **Why my extended bank's custom Sound items appear silent.** My Sound items
   are copied verbatim from the captured audio bank (so bus refs and parent IDs
   match the bank's actual structure) and i replace `ulID` (+0x00), `sourceID`
   (+0x09) and `streamType` (+0x0D). I tried both Vorbis (template default) and
   PCM (`0x00010001`) for the codec at +0x04 with no audible result. SetMedia is
   feeding RIFF WAV; might need true Wwise WEM Vorbis. There may also be a
   per-sound NodeBaseParam that ties the sound to a specific bus that does not
   exist in our extended-bank context.

3. **Whether the music player creates a separate WSSI instance for my cloned
   tracks at all.** Factory log only shows ~17 LSSRs (matching visible OG tracks).
   My cloned tracks' trial sound pointers never appear. Might be that the player
   skips creating an instance because validation fails on my cloned trial sound,
   or it just lazy-creates per visible row and my row never loaded.

4. **Where (if anywhere) the music player stores "currently selected track index".**
   That would let a hook know which TrackResource is "active" without doing object
   identification.

## Hooks Worth Setting Up

If you are picking this up, install these as a starting point. Use MinHook (the
in-place 14-byte JMP approach kept blowing up on functions with conditional jumps
in their prologue).

| What                  | Address (this build) | Why                                |
|-----------------------|----------------------|------------------------------------|
| AK::PostEvent (ID)    | export by name       | Captures every Wwise event posted  |
| WSSI factory A        | 0x14269A710          | Track which LSSR -> instance       |
| WSSI factory B        | 0x14028DB70          | Same, alternate constructor        |
| WSSI Play (vtable)    | 0x14269B3D0          | See per-instance state on play     |
| LoadBankMemoryView    | export by name       | Capture banks for analysis         |

The WSSI Play hook is useful for the chase but only fires for the full-song
playback path, not the sample preview. Sample preview goes through the task
queue (`sub_1426A30E0` / `sub_1426A3620`) and ultimately calls
`sub_1426A604B` (inside `sub_1426A6000`) for play. The stop path goes through
`sub_1426A60C7` (inside `sub_1426A6050`).

## A Diagnostic That Was Useful

I added a poll thread that watches GetAsyncKeyState(VK_Y), and when it sees a
press transition it sets a 3-second window. During that window, my PostEvent hook
dumps full args plus a 12-frame stack trace via `RtlCaptureStackBackTrace`. Frames
inside the game module are printed as `game+0xOFFSET` so you can paste them into
your disassembler. This gave me the call chain for sample play:

```
sub_1426B6146  PostEvent call site
sub_1426A604B  inside sub_1426A6000 (PLAY wrapper)
[game-internal callback frames]
sub_1423E9032  generic dispatcher (182 callers - red herring)
sub_1426A3324  inside sub_1426A30E0 (task queue processor)
sub_1426A378E  inside sub_1426A3620
sub_14269 73E1 inside sub_142697390
... (up to the system tick)
```

Originally i had a 500 ms window. Increase it to at least 1.5 s; the play event
fires noticeably after the keypress because it is queued through the audio task
processor.

## Closing Notes

`PostEvent` with flag `0x100001` and callback `sub_1426B5080` is the universal
"music player sample" signature. The actual event ID is per-track. Multiple events
fire for one Y press (likely one per layer/voice). Stop is always `0x61605A9D`.

Sharing this in case the next person picking this up gets further than i did.
The TrackResource cloning side is solid. The audio routing side needs someone with
more Wwise bank-format expertise than i have. If you do crack it, drop the
findings somewhere public so this doesn't get lost again.
