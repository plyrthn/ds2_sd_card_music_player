# SD Card - Music Player

Adds an SD Card to your music player so you can add your own music!

A mod for Death Stranding 2. Drop audio files into a folder, launch the
game, your tracks show up alongside the OG ones with proper artist/title
labels.

> **Heads up:** custom album art isn't working yet. Your tracks display
> whatever OG cover the game happens to bind. The reverse engineering for
> per-row jacket binding got pretty far but didn't reach the finish line
> - notes in `research/RESEARCH.md` if you want to pick it up.

## How to Use

The mod creates an `sd_music` folder next to `DS2.exe` on first launch
(or you can make it yourself). Drop your audio files in there. Launch
the game. Open the music player from the in-game menu. Your tracks will
be at the bottom of the list under whatever artist names came from the
file tags.

Filename convention is `Artist - Title.ext` (e.g.
`Low Roar - I'm Leaving.mp3`). ID3 tags override filename if they're
present, so a properly tagged MP3 will use those.

The mod loads via Ultimate ASI Loader (`version.dll`). The release
artifact bundles a pinned copy alongside the `.asi` so you can just
drop both files next to `DS2.exe`.

## Supported Formats

- mp3 (native decoder, full speed)
- flac (native decoder)
- ogg vorbis (native decoder)
- wav (native decoder)
- m4a / opus / wma / etc: falls back to ffmpeg if it's on PATH

The decoded audio is wrapped in a standard `WAVE_FORMAT_EXTENSIBLE` PCM
container that Wwise's PCM source plugin reads natively. No proprietary
encoder needed - the whole pipeline is open source.

## Build

Clone with submodules:

```
git clone --recurse-submodules https://github.com/plyrthn/ds2_sd_card_music_player
```

If you already cloned without submodules:

```
git submodule update --init --recursive
```

Then run `do_build.bat` from the repo root. Needs VS 2022 Build Tools.

ffmpeg on PATH is optional, only used as a fallback for formats outside
the native four (mp3/flac/ogg/wav).

## Layout

```
src/                       main C++ source
vendor/
  minhook/                 submodule -> TsudaKageyu/minhook
  single_header/           dr_libs + stb_vorbis single-header drop-ins
research/
  RESEARCH.md              architecture + RE notes
  HISTORICAL_AUDIO_NOTES.md  earlier audio-injection writeup
  frida/                   diagnostic frida scripts from the album-art work
  reference/               extracted Wwise bank json (reference data)
do_build.bat               build script
```

## Third-party libraries

All compiled into the .asi, no runtime dependencies.

- **MinHook** by Tsuda Kageyu (`vendor/minhook`, submodule).
  https://github.com/TsudaKageyu/minhook
- **dr_mp3 / dr_flac / dr_wav** by David Reid (mackron), in
  `vendor/single_header/`. https://github.com/mackron/dr_libs
  (dr_mp3 wraps minimp3 by lieff, CC0.)
- **stb_vorbis** by Sean Barrett, in `vendor/single_header/`.
  https://github.com/nothings/stb

The release artifact also bundles a pinned copy of:

- **Ultimate ASI Loader** by ThirteenAG (MIT). The `version.dll` proxy
  that loads the `.asi` into the game.
  https://github.com/ThirteenAG/Ultimate-ASI-Loader

## Credits

@rudowinger, for the Decima inspector dumps that nailed down the
UITexture schema and the music player track resource layout.
