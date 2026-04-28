// DS2 Custom Music Player Mod
// Adds custom music tracks to the in-game music player.
// Load via Ultimate ASI Loader (version.dll).
//
// Place audio files in sd_music/ next to DS2.exe. Folder is created
// automatically on first launch if missing.
// Filename format: "Artist - Title.ext" or just "Title.ext".

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include <vector>
#include <functional>
#include <string>
#include <mutex>
#include <algorithm>
#include <urlmon.h>
#include <unordered_map>
#include <unordered_set>
#include "MinHook.h"
#define DR_MP3_IMPLEMENTATION
#include "dr_mp3.h"
#define DR_FLAC_IMPLEMENTATION
#include "dr_flac.h"
#define DR_WAV_IMPLEMENTATION
#include "dr_wav.h"
#define STB_VORBIS_HEADER_ONLY
extern "C" {
#include "stb_vorbis.c"
}
// pull in stb_vorbis impl in this TU only
#undef STB_VORBIS_HEADER_ONLY
extern "C" {
#include "stb_vorbis.c"
}
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "urlmon.lib")

// ============================================================
// Logging
// ============================================================

static FILE* g_log = nullptr;
static std::mutex g_logMtx;
static volatile bool g_shuttingDown = false;

static LARGE_INTEGER g_perfFreq = {};
static LARGE_INTEGER g_perfStart = {};

// SEH body extracted into its own function so we can use __try without
// running into C2712 (lock_guard requires C++ unwinding in the caller).
static void LogImplSEH(const char* fmt, va_list args) {
    __try {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        double elapsed = (double)(now.QuadPart - g_perfStart.QuadPart) / g_perfFreq.QuadPart;
        fprintf(g_log, "[%7.2fs] ", elapsed);
        vfprintf(g_log, fmt, args);
        fflush(g_log);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        if (g_log) { fputs("[%LOG FAULT - swallowed]\n", g_log); fflush(g_log); }
    }
}

static void Log(const char* fmt, ...) {
    if (!g_log || g_shuttingDown) return;
    std::lock_guard<std::mutex> lock(g_logMtx);
    if (g_shuttingDown) return;
    va_list args;
    va_start(args, fmt);
    LogImplSEH(fmt, args);
    va_end(args);
}

// ============================================================
// Pattern Scanner (from localizer's XUtil, simplified)
// ============================================================

static uintptr_t ScanPattern(uintptr_t base, size_t size, const char* mask) {
    struct PatByte { uint8_t val; bool wild; };
    std::vector<PatByte> pat;

    for (size_t i = 0; mask[i]; ) {
        while (mask[i] == ' ') i++;
        if (!mask[i]) break;
        if (mask[i] == '?') {
            pat.push_back({0, true});
            i++;
            if (mask[i] == '?') i++;
        } else {
            pat.push_back({(uint8_t)strtoul(&mask[i], nullptr, 16), false});
            i += 2;
        }
    }

    if (pat.empty()) return 0;

    auto data = (const uint8_t*)base;
    size_t scanEnd = (size > pat.size()) ? size - pat.size() : 0;

    for (size_t i = 0; i <= scanEnd; i++) {
        bool match = true;
        for (size_t j = 0; j < pat.size(); j++) {
            if (!pat[j].wild && data[i + j] != pat[j].val) {
                match = false;
                break;
            }
        }
        if (match) return base + i;
    }
    return 0;
}

// resolve RIP-relative operand: addr of instruction, byte offset to the rel32
static uintptr_t ResolveRip(uintptr_t instrAddr, uint32_t operandOffset) {
    int32_t rel = *(int32_t*)(instrAddr + operandOffset);
    return instrAddr + operandOffset + 4 + rel;
}

// ============================================================
// x64 Trampoline Hook (no external deps)
// ============================================================
// Writes a 14-byte JMP [rip+0] at target, copies stolenBytes to trampoline.
// stolenBytes must be >= 14 and land on an instruction boundary.
// stolenBytes must NOT contain RIP-relative instructions.

struct HookInfo {
    void* original;
};

static HookInfo InstallHook(void* target, void* detour, int stolenBytes) {
    if (stolenBytes < 14) {
        Log("[MUSICMOD] hook error: need >= 14 stolen bytes, got %d\n", stolenBytes);
        return {nullptr};
    }

    auto tramp = (uint8_t*)VirtualAlloc(nullptr, stolenBytes + 14,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!tramp) {
        Log("[MUSICMOD] hook error: VirtualAlloc failed\n");
        return {nullptr};
    }

    // copy original prologue to trampoline
    memcpy(tramp, target, stolenBytes);

    // append JMP [rip+0] back to target+stolenBytes
    uint8_t* jmpBack = tramp + stolenBytes;
    jmpBack[0] = 0xFF; jmpBack[1] = 0x25;
    *(uint32_t*)(jmpBack + 2) = 0;
    *(uint64_t*)(jmpBack + 6) = (uint64_t)((uint8_t*)target + stolenBytes);

    // overwrite target with JMP [rip+0] to detour
    DWORD oldProt;
    VirtualProtect(target, stolenBytes, PAGE_EXECUTE_READWRITE, &oldProt);
    auto p = (uint8_t*)target;
    p[0] = 0xFF; p[1] = 0x25;
    *(uint32_t*)(p + 2) = 0;
    *(uint64_t*)(p + 6) = (uint64_t)detour;
    for (int i = 14; i < stolenBytes; i++) p[i] = 0x90; // NOP remainder
    VirtualProtect(target, stolenBytes, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), target, stolenBytes);

    return {tramp};
}

// ============================================================
// MinHook integration - safer hooking for hot game code
// (handles relative branches in prologue properly via HDE disassembly)
// ============================================================
static volatile LONG g_mhInitDone = 0;

static bool EnsureMinHook() {
    if (InterlockedCompareExchange(&g_mhInitDone, 1, 0) == 0) {
        MH_STATUS s = MH_Initialize();
        if (s != MH_OK && s != MH_ERROR_ALREADY_INITIALIZED) {
            Log("[MUSICMOD] MinHook init failed: %d\n", s);
            g_mhInitDone = 2; // failed
            return false;
        }
        Log("[MUSICMOD] MinHook initialized\n");
    }
    return g_mhInitDone == 1;
}

// Install a hook via MinHook. Returns trampoline pointer (call this to invoke
// original) or nullptr on failure.
static void* InstallHookMH(void* target, void* detour, const char* name) {
    if (!EnsureMinHook()) return nullptr;
    if (!target) {
        Log("[MUSICMOD] MH(%s) target is null\n", name);
        return nullptr;
    }
    void* trampoline = nullptr;
    MH_STATUS s = MH_CreateHook(target, detour, &trampoline);
    if (s != MH_OK) {
        Log("[MUSICMOD] MH(%s) CreateHook failed at %p: %d\n", name, target, s);
        return nullptr;
    }
    s = MH_EnableHook(target);
    if (s != MH_OK) {
        Log("[MUSICMOD] MH(%s) EnableHook failed at %p: %d\n", name, target, s);
        MH_RemoveHook(target);
        return nullptr;
    }
    Log("[MUSICMOD] MH(%s) hooked @ %p (trampoline=%p)\n", name, target, trampoline);
    return trampoline;
}


// ============================================================
// PE helpers
// ============================================================

static bool GetPESection(uintptr_t moduleBase, const char* name,
                         uintptr_t* start, uintptr_t* end) {
    auto dos = (PIMAGE_DOS_HEADER)moduleBase;
    auto nt = (PIMAGE_NT_HEADERS64)(moduleBase + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (uint32_t i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (memcmp(sec->Name, name, strlen(name)) == 0) {
            if (start) *start = moduleBase + sec->VirtualAddress;
            if (end) *end = moduleBase + sec->VirtualAddress + sec->Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

static size_t GetModuleImageSize(uintptr_t moduleBase) {
    auto dos = (PIMAGE_DOS_HEADER)moduleBase;
    auto nt = (PIMAGE_NT_HEADERS64)(moduleBase + dos->e_lfanew);
    return nt->OptionalHeader.SizeOfImage;
}

// ============================================================
// Decima engine RTTI helpers
// ============================================================

// RTTI kind values (from localizer RTTI.h)
enum RTTIKind : uint8_t {
    RTTI_Atom      = 0,
    RTTI_Pointer   = 1,
    RTTI_Container = 2,
    RTTI_Enum      = 3,
    RTTI_Compound  = 4,
};

// RTTICompound layout (from localizer):
//   +0x00: mId (int32)
//   +0x04: mKind (uint8)
//   +0x05: mFactoryFlags (uint8)
//   +0x06: mNumBases, mNumAttrs, etc.
//   +0x40: mTypeName (const char*)

static const char* RTTIGetTypeName(void* rtti) {
    if (!rtti) return "<null rtti>";
    uint8_t kind = *((uint8_t*)rtti + 4);
    if (kind == RTTI_Compound) {
        return *(const char**)((uint8_t*)rtti + 0x40);
    }
    return "<non-compound>";
}

// RTTIObject vtable:
//   [0] GetRTTI() -> returns RTTI*
//   [1] ~RTTIObject() (scalar deleting destructor)
// RTTIRefObject adds:
//   [2] Unk01
//   [3] Unk02

typedef void* (__fastcall* Fn_GetRTTI)(void* thisPtr);

static void* ObjGetRTTI(void* obj) {
    if (!obj) return nullptr;
    auto vtable = *(void***)obj;
    if (!vtable) return nullptr;
    auto fn = (Fn_GetRTTI)vtable[0];
    return fn(obj);
}

static const char* ObjTypeName(void* obj) {
    return RTTIGetTypeName(ObjGetRTTI(obj));
}

// ============================================================
// Decima Array / Ref layout (from localizer PCore)
// ============================================================
// Array<T>:  { uint32 count, uint32 capacity, T* entries }  = 16 bytes
// Ref<T>:    { T* ptr }                                      = 8 bytes

struct RawArray {
    uint32_t count;
    uint32_t capacity;
    void** entries;  // array of pointers (Ref<T> = T*)
};

// Global pointer to trackArr (= DSMusicPlayerSystemResource +0x30 AllTracks
// array). Set in InjectCustomTracks once sysRes is captured. Used by the
// per-track polling thread to walk JacketUITexture references for ALL OG
// music tracks (58 entries) once their UITextures are streamed in.
static RawArray* g_musicTrackArr = nullptr;

// ============================================================
// DSMusicPlayer RTTI field offsets (from Odradek types.json)
// ============================================================
// All offsets relative to object start (includes RTTIRefObject base = 32 bytes)

// RTTIRefObject layout:
//   +0x00: vtable*
//   +0x08: RefCount (uint32)
//   +0x0C: mUnk0C (uint32)
//   +0x10: ObjectUUID (GGUUID, 16 bytes)
//   total: 0x20 (32 bytes)

// DSMusicPlayerSystemResource:
//   +0x20 (32): AllArtists = Array<Ref<ArtistResource>>
//   +0x30 (48): AllTracks = Array<Ref<TrackResource>>

// DSMusicPlayerArtistResource:
//   +0x20 (32): ArtistId (uint32)
//   +0x24 (36): MenuDisplayPriority (int16)
//   +0x28 (40): ArtistNameText (Ref<LocalizedTextResource>)

// DSMusicPlayerAlbumResource:
//   +0x20 (32): MenuDisplayPriority (int16)
//   +0x28 (40): TitleText (Ref<LocalizedTextResource>)
//   +0x30 (48): ArtistNameText (Ref<LocalizedTextResource>)
//   +0x38 (56): CreditNameText (Ref<LocalizedTextResource>)
//   +0x40 (64): ArtistNameTextForTelop (Ref<LocalizedTextResource>)
//   +0x48 (72): CreditNameTextForTelop (Ref<LocalizedTextResource>)
//   +0x50 (80): ArtistResource (Ref<ArtistResource>)

// DSMusicPlayerTrackResource:
//   +0x20 (32): TrackId (uint32)
//   +0x24 (36): Seconds (uint16)
//   +0x26 (38): MenuDisplayPriority (int16)
//   +0x28 (40): Flag (uint8)
//   +0x30 (48): AlbumResource (Ref<AlbumResource>)
//   +0x38 (56): TitleText (Ref<LocalizedTextResource>)
//   +0x40 (64): SoundResource (Ref<SoundResource>)
//   +0x48 (72): TrialSoundResource (Ref<SoundResource>)
//   +0x50 (80): JacketUITexture (StreamingRef<UITexture>)
//   +0x58 (88): OpenConditionFact (Ref<BooleanFact>)

// LocalizedTextResource:
//   +0x20 (32): mText (const char*)
//   +0x28 (40): mTextLength (uint16)
//   +0x2A (42): mSubtitleMode (enum, 4 bytes)
//   +0x30 (48): mEntry (Entry*)
//   total: 0x38 (56 bytes)

// ============================================================
// Custom track data
// ============================================================

struct CustomTrack {
    std::string artist;
    std::string title;
    std::string album;
    std::string filepath;     // original file (mp3/ogg/wav/flac)
    std::string wemPath;      // cached PCM WEM (WAVE_FORMAT_EXTENSIBLE)
    std::vector<uint8_t> wemBytes; // loaded WEM bytes (for SetMedia)
    uint32_t stableId = 0;    // FNV-1a hash of source filename, used as TrackResource.id
                              // so playlists / favorites persist across boots even
                              // if the user adds/removes/reorders files in sd_music/.
    uint16_t durationSec = 0;
    uint16_t channels = 2;
    uint32_t sampleRate = 48000;
    uint16_t bitsPerSample = 16;
    bool isReady = false;     // WEM encoded and ready to play

    // set during injection
    void* pTrackResource = nullptr;
};

static std::vector<CustomTrack> g_tracks;
static bool g_injected = false;

static size_t GetTrackCount() { return g_tracks.size(); }

char g_gameDir[MAX_PATH] = {};
static uintptr_t g_gameBase = 0;
static std::vector<uint32_t> g_borrowedWwiseIds;

// forward-declare Wwise function types (defined fully later)
typedef uint32_t (__cdecl* GetIDFromStringFn)(const char* name);
static GetIDFromStringFn g_getIDFromString = nullptr;

// forward declarations for HW breakpoint system used in InjectCustomTracks
static volatile uintptr_t g_watchAddrs[8] = {};
static volatile int g_watchCount = 0;
static LONG CALLBACK MusicVEH(PEXCEPTION_POINTERS ep);
static void InstallHwBreakpoints();

// forward declarations for Wwise bank loading
typedef int32_t (__cdecl* LoadBankMemoryFn)(const void* bankData, uint32_t bankSize, uint32_t* outBankId);
static LoadBankMemoryFn g_loadBankMemoryCopy = nullptr;
static uint8_t* BuildCustomBank(int numTracks, uint32_t* outSize);
static uint8_t* g_capturedBank = nullptr;
static uint32_t g_capturedBankSize = 0;
static uint32_t g_capturedBankCount = 0;
static uint8_t* g_audioBank = nullptr;
static uint32_t g_audioBankSize = 0;
static uint8_t* BuildExtendedBank(int numTracks, uint32_t* outSize, uint32_t newBankId);
static const uint8_t* FindHircItemById(const uint8_t* bank, uint32_t bankSize,
                                        uint8_t wantType, uint32_t wantUlId,
                                        uint32_t* outBodySize);

// PostEvent forward decl
typedef uint32_t (__cdecl* PostEventByIdFn)(
    uint32_t eventId, uint64_t gameObjId, uint32_t flags,
    void* callback, void* cookie,
    uint32_t numExtSrc, void* extSrc, uint32_t playingId);
static PostEventByIdFn g_origPostEvent = nullptr;

#define CUSTOM_EVENT_BASE       0xAD100000u
// music-engine HIRC IDs appended per custom track (iteration 1: chain-from-M61)
#define CUSTOM_MUSICRSC_BASE    0xAD500000u
#define CUSTOM_MUSICSEG_BASE    0xAD600000u
#define CUSTOM_MUSICTRACK_BASE  0xAD700000u
// M61 TRIAL chain IDs in bank 727071332 (from 727071332-10035-event_trial.txtp).
// Using trial because the music player UI plays the trial on Y ("Listen to
// Sample"), so cloning the trial chain matches the context the music engine
// expects (state/RTPC gating for trial playback).
#define M61_EVENT_ID        1633704605u   // CAkEvent[10035]
#define M61_ACTION_ID       1052467820u   // CAkActionPlay[10034]
#define M61_MUSICRSC_ID     740262603u    // CAkMusicRanSeqCntr[4066]
#define M61_MUSICSEG_ID     161087351u    // CAkMusicSegment[4065]
#define M61_MUSICTRACK_ID   861017726u    // CAkMusicTrack[4064]
// (The M61 FULL chain is 3056202008 / 709017358 / 580326404 / 650936270 /
//  289765561 for when we also want the "play full track" behavior.)

// set by DecodeWorker once all WEMs are loaded into g_tracks[i].wemBytes.
// template rebuilder waits on this before its bank-load + SetMedia, so we
// never push an empty media table to Wwise.
static volatile bool g_wemsReady = false;

// template item bytes captured from a real audio bank
static uint8_t g_realSoundBody[256] = {};
static uint32_t g_realSoundSize = 0;
static uint8_t g_realActionBody[256] = {};
static uint32_t g_realActionSize = 0;
static uint8_t g_realEventBody[64] = {};
static uint32_t g_realEventSize = 0;
// music-engine templates (HIRC types 0x0A=Segment, 0x0B=Track, 0x0D=RanSeqCntr)
static uint8_t g_realMusicTrackBody[4096] = {};
static uint32_t g_realMusicTrackSize = 0;
static uint32_t g_realMusicTrackSourceBankId = 0;
static uint8_t g_realMusicSegmentBody[4096] = {};
static uint32_t g_realMusicSegmentSize = 0;
static uint32_t g_realMusicSegmentSourceBankId = 0;
static uint8_t g_realMusicRanSeqBody[8192] = {};
static uint32_t g_realMusicRanSeqSize = 0;
static uint32_t g_realMusicRanSeqSourceBankId = 0;
// real WEM data extracted from a bank's DATA chunk for testing
static uint8_t* g_realWem = nullptr;
static uint32_t g_realWemSize = 0;
static uint32_t g_realWemSourceId = 0;

// SetMedia forward decl
struct AkSourceSettings {
    uint32_t sourceID;
    uint8_t* pMediaMemory;
    uint32_t uMediaSize;
    uint32_t pad;
};
typedef int32_t (__cdecl* SetMediaFn2)(AkSourceSettings* settings, uint32_t numSettings);
static SetMediaFn2 g_setMedia = nullptr;

// ============================================================
// Music folder scanner
// ============================================================

static uint16_t GetWavDuration(const char* path) {
    FILE* f = fopen(path, "rb");
    if (!f) return 0;

    uint8_t hdr[44];
    if (fread(hdr, 1, 44, f) < 44) { fclose(f); return 0; }
    if (memcmp(hdr, "RIFF", 4) != 0 || memcmp(hdr + 8, "WAVE", 4) != 0) {
        fclose(f);
        return 0;
    }

    uint32_t byteRate = *(uint32_t*)(hdr + 28);
    if (byteRate == 0) { fclose(f); return 0; }

    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    fclose(f);

    return (uint16_t)((fileSize - 44) / byteRate);
}

// forward decls
static std::string lower_ext(const char* fname);
static bool FindFFprobe();
static void ReadAudioTags(CustomTrack& t);
// state for post-wake custom-event resume (definitions near Hook_Suspend)
// pointer to the DSMusicPlayerSystemResource captured at OnFinishLoadGroup.
// declared early so MusicEventListener can write it before the resolver hook
// (defined later in the file) reads it.
static void* g_pSysResource = nullptr;
// forward decl - actual definition is later in the file
static void* SafeReadPtr(void* base, size_t off);
static volatile uint32_t g_lastCustomEventId;
static volatile uint64_t g_lastCustomGameObj;
static void*             g_lastCustomCallback;
static uint32_t          g_lastCustomFlags;
static volatile uint32_t g_lastCustomPlayingId;
static volatile bool     g_engineSuspended;
// wallclock-based playback position tracking for alt-tab resume.
// Wwise's GetSourcePlayPosition returns 0 for our custom voices, so we
// approximate by counting wall time since the PostEvent fired.
static LARGE_INTEGER     g_lastCustomPostTick = {};
static volatile int32_t  g_lastCustomPositionMs = 0;
typedef int32_t (__cdecl* SeekOnEventFn)(uint32_t eventId, uint64_t gameObjId,
    int32_t positionMs, bool seekToNearestMarker, uint32_t playingId);
static SeekOnEventFn g_seekOnEvent = nullptr;

// check if file extension is supported
static bool IsSupportedAudio(const char* fname) {
    auto lower = std::string(fname);
    for (auto& c : lower) c = (char)tolower(c);
    auto dot = lower.rfind('.');
    if (dot == std::string::npos) return false;
    std::string ext = lower.substr(dot);
    return ext == ".wav" || ext == ".mp3" || ext == ".ogg" ||
           ext == ".flac" || ext == ".m4a" || ext == ".opus";
}

// UTF-16 -> UTF-8 conversion (Windows FindFirstFileW gives us wide chars)
static std::string WideToUtf8(const wchar_t* w) {
    if (!w || !*w) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string s((size_t)(n - 1), 0);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}

// UTF-16 -> current ANSI code page (CP_ACP). used for paths that get handed
// to CreateProcessA (ffmpeg) since CreateProcessA interprets path bytes as
// ANSI when spawning. unmappable chars become '?' but the common case
// (CP1252 for western locales) roundtrips fine for U+2019 etc.
static std::string WideToAcp(const wchar_t* w) {
    if (!w || !*w) return {};
    int n = WideCharToMultiByte(CP_ACP, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string s((size_t)(n - 1), 0);
    WideCharToMultiByte(CP_ACP, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}

// slugify for cache-file paths: keep ASCII alnum + safe punctuation, replace
// everything else with '_'. non-ASCII bytes (UTF-8 multibyte sequences, or
// CP1252 accented chars) would otherwise poison WSOURCES UTF-8 parsing and
// confuse CreateFile lookups. source paths are left alone (ffmpeg handles them
// via Windows' CP_ACP conversion), only our own intermediate files get slugged.
static std::string SlugifyCacheName(const std::string& name) {
    std::string out;
    out.reserve(name.size());
    for (unsigned char c : name) {
        bool keep = c < 0x80 &&
                    (isalnum(c) || c == '-' || c == '_' || c == ' ' ||
                     c == '.' || c == '(' || c == ')' || c == ',');
        out.push_back(keep ? (char)c : '_');
    }
    return out;
}

// 32-bit FNV-1a hash, case-folded. used to derive a stable per-file track ID
// so the music-player UI's saved playlists/favorites continue to point at the
// same logical song across mod restarts and file reorderings. high byte 0xAD
// keeps our IDs in our reserved 0xAD?????? range so they don't collide with
// game-defined track IDs (which are typically lower 32-bit values).
static uint32_t StableTrackIdFromName(const std::string& name) {
    uint32_t h = 2166136261u;  // FNV offset basis
    for (unsigned char c : name) {
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + 32);  // case-fold
        h ^= c;
        h *= 16777619u;        // FNV prime
    }
    // pack into 0xAD?????? (high byte 0xAD = our marker, 24 bits of hash)
    return 0xAD000000u | (h & 0x00FFFFFFu);
}

// strip a leading track-number prefix from a stem: "1-03 Artist - Title" ->
// "Artist - Title", "05 Title" -> "Title", "05. Title" -> "Title". only strips
// if the prefix is followed by a space.
static std::string StripTrackNumberPrefix(const std::string& s) {
    size_t i = 0;
    while (i < s.size() && isdigit((unsigned char)s[i])) i++;
    if (i == 0) return s;
    if (i < s.size() && s[i] == '-') {
        size_t j = i + 1;
        while (j < s.size() && isdigit((unsigned char)s[j])) j++;
        if (j > i + 1) i = j;
    }
    if (i < s.size() && s[i] == '.') i++;
    size_t preSpace = i;
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) i++;
    if (i == preSpace) return s;
    return s.substr(i);
}

static void ScanMusicFolder() {
    wchar_t searchPath[MAX_PATH];
    swprintf(searchPath, MAX_PATH, L"%hs\\sd_music\\*.*", g_gameDir);

    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(searchPath, &fd);
    if (hFind == INVALID_HANDLE_VALUE) {
        Log("[MUSICMOD] sd_music/ folder not found or empty\n");
        return;
    }

    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::string nameUtf8 = WideToUtf8(fd.cFileName);
        std::string nameAcp  = WideToAcp(fd.cFileName);
        if (!IsSupportedAudio(nameUtf8.c_str())) continue;

        CustomTrack t;
        // source path stored in ANSI code page so CreateProcessA (ffmpeg /
        // ffprobe spawn) reads the filename back as the right UTF-16 path
        // when it converts via CP_ACP. Using UTF-8 here would misdecode
        // multibyte sequences as CP1252 and fail to open the source.
        char fullpath[MAX_PATH];
        snprintf(fullpath, sizeof(fullpath), "%s\\sd_music\\%s",
                 g_gameDir, nameAcp.c_str());
        t.filepath = fullpath;

        // cache filename is an ASCII-safe slug so CreateFile lookups behave
        // predictably regardless of unicode in the source name.
        std::string slug = SlugifyCacheName(nameUtf8);
        char wemCache[MAX_PATH];
        snprintf(wemCache, sizeof(wemCache),
                 "%s\\sd_music\\.cache\\wem\\Windows\\%s.wem",
                 g_gameDir, slug.c_str());
        t.wemPath = wemCache;

        std::string stem = nameUtf8;
        auto dot = stem.rfind('.');
        if (dot != std::string::npos) stem = stem.substr(0, dot);
        std::string noPrefix = StripTrackNumberPrefix(stem);

        auto dash = noPrefix.find(" - ");
        if (dash != std::string::npos) {
            t.artist = noPrefix.substr(0, dash);
            t.title = noPrefix.substr(dash + 3);
        } else {
            t.artist = "Custom";
            t.title = noPrefix;
        }
        t.album = "Custom Music";
        t.durationSec = 0; // resolved later after decode

        // stable track id derived from the source filename so the music-player
        // playlist/favorites continue to point at the same logical song after
        // the user adds, removes, or reorders files in sd_music/.
        t.stableId = StableTrackIdFromName(nameUtf8);

        // for WAV files, we can read duration directly
        if (lower_ext(nameUtf8.c_str()) == ".wav") {
            t.durationSec = GetWavDuration(fullpath);
        }

        Log("[MUSICMOD] track: \"%s\" by \"%s\" id=0x%08X -> %s\n",
            t.title.c_str(), t.artist.c_str(), t.stableId, nameUtf8.c_str());
        g_tracks.push_back(std::move(t));

    } while (FindNextFileW(hFind, &fd));
    FindClose(hFind);

    // tag read is deferred to a background thread (kicked off later in init).
    // Doing it synchronously here blocks startup for 7+ seconds while
    // ffprobe spawns once per tag per file, and the music player resource
    // can load and miss our OnFinishLoadGroup listener.

    // sort by stableId so g_tracks order is deterministic across runs
    // (FindFirstFileW order is filesystem-dependent and not guaranteed stable).
    // a stable order also keeps internal indices (event/media IDs) consistent
    // for a given file set across boots.
    std::sort(g_tracks.begin(), g_tracks.end(),
              [](const CustomTrack& a, const CustomTrack& b) {
                  return a.stableId < b.stableId;
              });

    Log("[MUSICMOD] found %zu audio file(s)\n", g_tracks.size());
}

// ============================================================
// ffmpeg integration - decode mp3/ogg/flac/etc to PCM
// ============================================================

static char g_ffmpegPath[MAX_PATH] = {};
static char g_ffprobePath[MAX_PATH] = {};


// Decode source audio to int16 stereo PCM via native single-header libs.
// Returns interleaved samples in `outSamples`, channels=2 always (mono is
// duplicated), sample rate preserved from the source.
//
// Supported: MP3 (dr_mp3), FLAC (dr_flac), OGG Vorbis (stb_vorbis), WAV
// (dr_wav). Unrecognised extensions return false so the caller can fall
// back to ffmpeg for OPUS/M4A/etc.
static bool DecodeAudioNative(const char* path,
                               std::vector<int16_t>& outSamples,
                               uint32_t* outSampleRate) {
    const char* dot = strrchr(path, '.');
    if (!dot) return false;
    char ext[16]; size_t i = 0;
    for (const char* p = dot + 1; *p && i < sizeof(ext) - 1; p++, i++) {
        ext[i] = (char)tolower((unsigned char)*p);
    }
    ext[i] = 0;

    if (strcmp(ext, "mp3") == 0) {
        drmp3 mp3 = {};
        if (!drmp3_init_file(&mp3, path, nullptr)) return false;
        uint64_t totalFrames = drmp3_get_pcm_frame_count(&mp3);
        uint32_t srcCh = mp3.channels, srcRate = mp3.sampleRate;
        std::vector<int16_t> tmp((size_t)totalFrames * srcCh);
        drmp3_uint64 got = drmp3_read_pcm_frames_s16(&mp3, totalFrames, tmp.data());
        drmp3_uninit(&mp3);
        if (got == 0) return false;
        // duplicate mono -> stereo if needed
        if (srcCh == 1) {
            outSamples.resize((size_t)got * 2);
            for (size_t k = 0; k < (size_t)got; k++) {
                outSamples[k*2] = outSamples[k*2 + 1] = tmp[k];
            }
        } else if (srcCh == 2) {
            outSamples = std::move(tmp);
            outSamples.resize((size_t)got * 2);
        } else {
            // mix down: average first 2 channels (lazy but works for most)
            outSamples.resize((size_t)got * 2);
            for (size_t k = 0; k < (size_t)got; k++) {
                outSamples[k*2]     = tmp[k*srcCh];
                outSamples[k*2 + 1] = tmp[k*srcCh + 1];
            }
        }
        *outSampleRate = srcRate;
        return true;
    }
    if (strcmp(ext, "flac") == 0) {
        drflac* fl = drflac_open_file(path, nullptr);
        if (!fl) return false;
        uint64_t totalFrames = fl->totalPCMFrameCount;
        uint32_t srcCh = fl->channels, srcRate = fl->sampleRate;
        std::vector<int16_t> tmp((size_t)totalFrames * srcCh);
        drflac_uint64 got = drflac_read_pcm_frames_s16(fl, totalFrames, tmp.data());
        drflac_close(fl);
        if (got == 0) return false;
        if (srcCh == 1) {
            outSamples.resize((size_t)got * 2);
            for (size_t k = 0; k < (size_t)got; k++) {
                outSamples[k*2] = outSamples[k*2 + 1] = tmp[k];
            }
        } else {
            outSamples.resize((size_t)got * 2);
            for (size_t k = 0; k < (size_t)got; k++) {
                outSamples[k*2]     = tmp[k*srcCh];
                outSamples[k*2 + 1] = tmp[k*srcCh + 1];
            }
        }
        *outSampleRate = srcRate;
        return true;
    }
    if (strcmp(ext, "wav") == 0) {
        drwav wv = {};
        if (!drwav_init_file(&wv, path, nullptr)) return false;
        uint64_t totalFrames = wv.totalPCMFrameCount;
        uint32_t srcCh = wv.channels, srcRate = wv.sampleRate;
        std::vector<int16_t> tmp((size_t)totalFrames * srcCh);
        drwav_uint64 got = drwav_read_pcm_frames_s16(&wv, totalFrames, tmp.data());
        drwav_uninit(&wv);
        if (got == 0) return false;
        if (srcCh == 1) {
            outSamples.resize((size_t)got * 2);
            for (size_t k = 0; k < (size_t)got; k++) {
                outSamples[k*2] = outSamples[k*2 + 1] = tmp[k];
            }
        } else {
            outSamples.resize((size_t)got * 2);
            for (size_t k = 0; k < (size_t)got; k++) {
                outSamples[k*2]     = tmp[k*srcCh];
                outSamples[k*2 + 1] = tmp[k*srcCh + 1];
            }
        }
        *outSampleRate = srcRate;
        return true;
    }
    if (strcmp(ext, "ogg") == 0) {
        int err = 0;
        stb_vorbis* vb = stb_vorbis_open_filename(path, &err, nullptr);
        if (!vb) return false;
        stb_vorbis_info info = stb_vorbis_get_info(vb);
        uint32_t srcCh = (uint32_t)info.channels, srcRate = info.sample_rate;
        // stream samples in batches
        std::vector<int16_t> stream;
        const int CH = 2;
        int16_t buf[4096 * 2];
        for (;;) {
            int got = stb_vorbis_get_samples_short_interleaved(
                vb, CH, buf, sizeof(buf) / sizeof(buf[0]));
            if (got <= 0) break;
            stream.insert(stream.end(), buf, buf + got * CH);
        }
        stb_vorbis_close(vb);
        if (stream.empty()) return false;
        outSamples = std::move(stream);
        *outSampleRate = srcRate;
        (void)srcCh;
        return true;
    }
    return false; // unknown extension
}

// Apply linear gain to int16 samples with saturation.
static void ApplyGainDb(std::vector<int16_t>& samples, double db) {
    double gain = pow(10.0, db / 20.0);
    for (auto& s : samples) {
        double v = (double)s * gain;
        if (v > 32767.0) v = 32767.0;
        if (v < -32768.0) v = -32768.0;
        s = (int16_t)v;
    }
}

// mkdir -p for a single Windows path. Walks each separator and creates each
// intermediate. Returns true if the target dir exists by the end.
static bool EnsureDirTree(const char* path) {
    char buf[MAX_PATH];
    strncpy_s(buf, path, MAX_PATH - 1);
    for (char* p = buf; *p; p++) {
        if ((*p == '\\' || *p == '/') && p != buf && *(p-1) != ':') {
            char saved = *p;
            *p = 0;
            CreateDirectoryA(buf, nullptr);
            *p = saved;
        }
    }
    CreateDirectoryA(buf, nullptr);
    DWORD a = GetFileAttributesA(buf);
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
}

// Write a Wwise PCM WEM. A Wwise PCM WEM is a standard Microsoft RIFF/WAVE
// file using WAVE_FORMAT_EXTENSIBLE (formatTag 0xFFFE) with the PCM
// SubFormat GUID. Wwise's PCM source plugin reads this directly, the same
// way it reads any conversion tool's PCM WEM output. See
// https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ksmedia/ns-ksmedia-waveformatextensible
//
// Layout (68-byte header for stereo 16-bit, then PCM samples):
//   00  4   "RIFF"
//   04  4   RIFF size = 60 + dataBytes
//   08  4   "WAVE"
//   0C  4   "fmt "
//   10  4   fmt chunk size = 40
//   14  2   wFormatTag = 0xFFFE
//   16  2   nChannels
//   18  4   nSamplesPerSec
//   1C  4   nAvgBytesPerSec
//   20  2   nBlockAlign
//   22  2   wBitsPerSample
//   24  2   cbSize = 22
//   26  2   wValidBitsPerSample
//   28  4   dwChannelMask
//   2C 16   SubFormat GUID = KSDATAFORMAT_SUBTYPE_PCM
//   3C  4   "data"
//   40  4   data size
//   44 ..   PCM samples (little-endian int16 interleaved)
static bool WritePcmWemFile(const char* path, const int16_t* samples,
                             uint64_t numFrames, uint16_t channels,
                             uint32_t sampleRate) {
    static const uint8_t SUBTYPE_PCM[16] = {
        0x01,0x00,0x00,0x00, 0x00,0x00, 0x10,0x00,
        0x80,0x00, 0x00,0xAA,0x00,0x38,0x9B,0x71,
    };
    const uint16_t bitsPerSample = 16;
    const uint16_t blockAlign    = (uint16_t)(channels * (bitsPerSample / 8));
    const uint32_t byteRate      = sampleRate * blockAlign;
    const uint64_t dataBytes64   = numFrames * blockAlign;
    if (dataBytes64 > 0xFFFFFFF0ULL) return false; // RIFF 4GB cap
    const uint32_t dataBytes     = (uint32_t)dataBytes64;
    const uint32_t riffSize      = 60 + dataBytes;
    uint32_t channelMask = 0;
    if (channels == 1)      channelMask = 0x4;            // FRONT_CENTER
    else if (channels == 2) channelMask = 0x3;            // FRONT_LEFT|RIGHT
    else if (channels == 4) channelMask = 0x33;           // L|R|BL|BR
    else if (channels == 6) channelMask = 0x3F;           // 5.1
    else                    channelMask = (1u << channels) - 1u;

    FILE* f = fopen(path, "wb");
    if (!f) return false;
    auto w  = [&](const void* p, size_t n) { fwrite(p, 1, n, f); };
    auto u16 = [&](uint16_t v) { fwrite(&v, 2, 1, f); };
    auto u32 = [&](uint32_t v) { fwrite(&v, 4, 1, f); };

    w("RIFF", 4); u32(riffSize); w("WAVE", 4);
    w("fmt ", 4); u32(40);
    u16(0xFFFE);            // WAVE_FORMAT_EXTENSIBLE
    u16(channels);
    u32(sampleRate);
    u32(byteRate);
    u16(blockAlign);
    u16(bitsPerSample);
    u16(22);                // cbSize
    u16(bitsPerSample);     // wValidBitsPerSample
    u32(channelMask);
    w(SUBTYPE_PCM, 16);
    w("data", 4); u32(dataBytes);
    size_t wrote = fwrite(samples, 1, dataBytes, f);
    fclose(f);
    return wrote == dataBytes;
}

// Read an existing PCM WEM (or any RIFF/WAVE) just enough to compute its
// playback duration in seconds. Returns 0 on failure.
static uint16_t ReadWavOrWemDurationSec(const char* path) {
    drwav wv = {};
    if (!drwav_init_file(&wv, path, nullptr)) return 0;
    uint32_t rate = wv.sampleRate;
    uint64_t frames = wv.totalPCMFrameCount;
    drwav_uninit(&wv);
    if (rate == 0) return 0;
    return (uint16_t)(frames / rate);
}

// Read a PCM WAV file (e.g. ffmpeg output) into int16 stereo samples and emit
// the equivalent PCM WEM at destPath. The intermediate WAV is left to the
// caller to delete.
static bool ConvertWavToPcmWem(const char* srcWav, const char* destWem) {
    drwav wv = {};
    if (!drwav_init_file(&wv, srcWav, nullptr)) return false;
    uint32_t rate = wv.sampleRate;
    uint16_t ch   = wv.channels < 1 ? 2 : wv.channels;
    uint64_t totalFrames = wv.totalPCMFrameCount;
    std::vector<int16_t> samples((size_t)totalFrames * ch);
    drwav_uint64 got = drwav_read_pcm_frames_s16(&wv, totalFrames, samples.data());
    drwav_uninit(&wv);
    if (got == 0) return false;
    // Force stereo if we somehow got mono back from ffmpeg: duplicate L into R.
    if (ch == 1) {
        std::vector<int16_t> stereo((size_t)got * 2);
        for (size_t k = 0; k < (size_t)got; k++) {
            stereo[k*2] = stereo[k*2 + 1] = samples[k];
        }
        return WritePcmWemFile(destWem, stereo.data(), got, 2, rate);
    }
    return WritePcmWemFile(destWem, samples.data(), got, ch, rate);
}

// SEH-wrapped memcpy used when copying from foreign memory that might span a
// page boundary into garbage. Returns true on full copy, false on partial fault.
static bool SafeMemcpy(void* dst, const void* src, size_t n) {
    __try { memcpy(dst, src, n); return true; }
    __except(1) { return false; }
}

// Read up to `n` bytes from `src` into `dst`. SEH-protected so it's callable
// from contexts that have C++ object unwinding (where __try inline is illegal).
static bool SafeReadBytes(void* dst, const void* src, size_t n) {
    if (!src || !dst) return false;
    __try { memcpy(dst, src, n); return true; }
    __except(1) { return false; }
}


// Walk the cache directory and delete stale BC7 / WAV / WEM files for tracks
// whose source media is no longer in sd_music/. This means removing an MP3
// also removes its cached BC7 blobs and decoded audio.
static void PruneStaleCache() {
    char cacheDir[MAX_PATH];
    snprintf(cacheDir, MAX_PATH, "%s\\sd_music\\.cache", g_gameDir);
    char pattern[MAX_PATH];
    snprintf(pattern, MAX_PATH, "%s\\*", cacheDir);
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    int removed = 0;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        // expected naming: <originalfile>.<ext>.<suffix> e.g.
        // "Anything You Need.mp3.wav", ".bc7small", ".bc7large", ".wem"
        const char* sfx[] = { ".wav", ".wem", ".bc7small", ".bc7large", nullptr };
        const char* matched = nullptr;
        for (int i = 0; sfx[i]; i++) {
            size_t flen = strlen(fd.cFileName);
            size_t slen = strlen(sfx[i]);
            if (flen > slen && _stricmp(fd.cFileName + flen - slen, sfx[i]) == 0) {
                matched = sfx[i]; break;
            }
        }
        if (!matched) continue;
        // strip suffix to get the source filename (e.g. "Anything You Need.mp3")
        char src[MAX_PATH];
        snprintf(src, MAX_PATH, "%s", fd.cFileName);
        src[strlen(src) - strlen(matched)] = 0;
        char srcPath[MAX_PATH];
        snprintf(srcPath, MAX_PATH, "%s\\sd_music\\%s", g_gameDir, src);
        if (GetFileAttributesA(srcPath) == INVALID_FILE_ATTRIBUTES) {
            char victim[MAX_PATH];
            snprintf(victim, MAX_PATH, "%s\\%s", cacheDir, fd.cFileName);
            if (DeleteFileA(victim)) removed++;
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    if (removed > 0) {
        Log("[MUSICMOD] pruned %d stale cache files\n", removed);
    }
}

static bool FindFFmpeg() {
    Log("[MUSICMOD] looking for ffmpeg...\n");

    // try sd_music/ffmpeg.exe first
    snprintf(g_ffmpegPath, MAX_PATH, "%s\\sd_music\\ffmpeg.exe", g_gameDir);
    if (GetFileAttributesA(g_ffmpegPath) != INVALID_FILE_ATTRIBUTES) {
        Log("[MUSICMOD] ffmpeg found in sd_music/: %s\n", g_ffmpegPath);
        return true;
    }
    Log("[MUSICMOD] not in sd_music/\n");

    // try system PATH
    char buf[MAX_PATH];
    if (SearchPathA(nullptr, "ffmpeg.exe", nullptr, MAX_PATH, buf, nullptr) > 0) {
        strcpy_s(g_ffmpegPath, MAX_PATH, buf);
        Log("[MUSICMOD] ffmpeg found on PATH: %s\n", g_ffmpegPath);
        return true;
    }
    Log("[MUSICMOD] not on system PATH\n");

    g_ffmpegPath[0] = '\0';
    return false;
}

// locate ffprobe.exe: next to ffmpeg first, then PATH
static bool FindFFprobe() {
    if (g_ffmpegPath[0]) {
        std::string p = g_ffmpegPath;
        size_t sl = p.find_last_of('\\');
        if (sl != std::string::npos) {
            p = p.substr(0, sl + 1) + "ffprobe.exe";
            if (GetFileAttributesA(p.c_str()) != INVALID_FILE_ATTRIBUTES) {
                strcpy_s(g_ffprobePath, MAX_PATH, p.c_str());
                Log("[MUSICMOD] ffprobe: %s\n", g_ffprobePath);
                return true;
            }
        }
    }
    char buf[MAX_PATH];
    if (SearchPathA(nullptr, "ffprobe.exe", nullptr, MAX_PATH, buf, nullptr) > 0) {
        strcpy_s(g_ffprobePath, MAX_PATH, buf);
        Log("[MUSICMOD] ffprobe on PATH: %s\n", g_ffprobePath);
        return true;
    }
    g_ffprobePath[0] = 0;
    Log("[MUSICMOD] ffprobe not found (tag extraction disabled)\n");
    return false;
}

// read one format_tag (e.g. "title", "artist", "album") via ffprobe
// returns true if tag is found and non-empty; out is NUL-terminated
static bool ReadTag(const char* filepath, const char* tagName,
                    char* out, size_t outSz) {
    if (!g_ffprobePath[0] || outSz < 2) return false;
    out[0] = 0;

    char cmd[MAX_PATH * 3];
    snprintf(cmd, sizeof(cmd),
             "\"%s\" -v error -show_entries format_tags=%s "
             "-of default=nw=1:nk=1 \"%s\"",
             g_ffprobePath, tagName, filepath);

    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE rh = nullptr, wh = nullptr;
    if (!CreatePipe(&rh, &wh, &sa, 0)) return false;
    SetHandleInformation(rh, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wh;
    si.hStdError  = wh;
    PROCESS_INFORMATION pi = {};

    char mcmd[MAX_PATH * 3];
    strncpy_s(mcmd, sizeof(mcmd), cmd, _TRUNCATE);

    if (!CreateProcessA(nullptr, mcmd, nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(rh); CloseHandle(wh);
        return false;
    }
    CloseHandle(wh);

    DWORD got = 0;
    ReadFile(rh, out, (DWORD)(outSz - 1), &got, nullptr);
    out[got] = 0;
    while (got > 0 && (out[got - 1] == '\n' || out[got - 1] == '\r' ||
                       out[got - 1] == ' '  || out[got - 1] == '\t')) {
        out[--got] = 0;
    }
    CloseHandle(rh);

    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return out[0] != 0;
}

// single ffprobe call returns title+artist+album as TAG:key=value lines.
// 3x faster than spawning ffprobe once per tag.
static void ReadAudioTags(CustomTrack& t) {
    if (!g_ffprobePath[0]) return;

    char cmd[MAX_PATH * 3];
    snprintf(cmd, sizeof(cmd),
             "\"%s\" -v error -show_entries format_tags=title,artist,album "
             "-of default=nw=1 \"%s\"",
             g_ffprobePath, t.filepath.c_str());

    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    HANDLE rh = nullptr, wh = nullptr;
    if (!CreatePipe(&rh, &wh, &sa, 0)) return;
    SetHandleInformation(rh, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wh;
    si.hStdError  = wh;
    PROCESS_INFORMATION pi = {};

    char mcmd[MAX_PATH * 3];
    strncpy_s(mcmd, sizeof(mcmd), cmd, _TRUNCATE);

    if (!CreateProcessA(nullptr, mcmd, nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(rh); CloseHandle(wh);
        return;
    }
    CloseHandle(wh);

    char buf[2048] = {};
    DWORD got = 0;
    ReadFile(rh, buf, sizeof(buf) - 1, &got, nullptr);
    buf[got] = 0;
    CloseHandle(rh);
    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    // ffprobe output looks like:
    //   TAG:title=Easy Way Out
    //   TAG:artist=Low Roar
    //   TAG:album=Death Stranding (Songs from the Video Game)
    char* p = buf;
    while (p && *p) {
        char* eol = strpbrk(p, "\r\n");
        if (eol) *eol = 0;
        if (strncmp(p, "TAG:", 4) == 0) {
            char* eq = strchr(p + 4, '=');
            if (eq) {
                *eq = 0;
                const char* key = p + 4;
                const char* val = eq + 1;
                if (*val) {
                    if      (_stricmp(key, "title")  == 0) t.title  = val;
                    else if (_stricmp(key, "artist") == 0) t.artist = val;
                    else if (_stricmp(key, "album")  == 0) t.album  = val;
                }
            }
        }
        p = eol ? eol + 1 : nullptr;
        while (p && (*p == '\r' || *p == '\n')) p++;
    }
}

// silently download ffmpeg from BtbN's GitHub releases (LGPL essentials build)
static bool DownloadFFmpeg() {
    Log("[MUSICMOD] === ffmpeg auto-download ===\n");
    Log("[MUSICMOD] source: github.com/BtbN/FFmpeg-Builds (LGPL essentials)\n");
    Log("[MUSICMOD] license: LGPL 2.1+\n");

    char destZip[MAX_PATH];
    snprintf(destZip, MAX_PATH, "%s\\sd_music\\ffmpeg-temp.zip", g_gameDir);

    // ensure sd_music exists
    char musicDir[MAX_PATH];
    snprintf(musicDir, MAX_PATH, "%s\\sd_music", g_gameDir);
    CreateDirectoryA(musicDir, nullptr);

    Log("[MUSICMOD] downloading ~80MB to %s\n", destZip);
    Log("[MUSICMOD] this is silent and may take 1-3 minutes depending on connection...\n");

    DWORD startTime = GetTickCount();
    HRESULT hr = URLDownloadToFileA(nullptr,
        "https://github.com/BtbN/FFmpeg-Builds/releases/latest/download/ffmpeg-master-latest-win64-lgpl.zip",
        destZip, 0, nullptr);
    DWORD elapsed = GetTickCount() - startTime;

    if (FAILED(hr)) {
        Log("[MUSICMOD] download failed: 0x%X (took %lums)\n", hr, elapsed);
        return false;
    }

    // get file size for confirmation
    HANDLE h = CreateFileA(destZip, GENERIC_READ, FILE_SHARE_READ, nullptr,
                          OPEN_EXISTING, 0, nullptr);
    LARGE_INTEGER fsize = {};
    if (h != INVALID_HANDLE_VALUE) { GetFileSizeEx(h, &fsize); CloseHandle(h); }
    Log("[MUSICMOD] download complete: %lld bytes in %lums (%.1f MB/s)\n",
        fsize.QuadPart, elapsed,
        (double)fsize.QuadPart / 1024.0 / 1024.0 / (elapsed / 1000.0));

    // extract using Windows tar.exe (built-in on Win10 1803+)
    char extractDir[MAX_PATH];
    snprintf(extractDir, MAX_PATH, "%s\\sd_music\\.ffmpeg", g_gameDir);
    CreateDirectoryA(extractDir, nullptr);
    Log("[MUSICMOD] extracting to %s\n", extractDir);

    char cmd[MAX_PATH * 3];
    snprintf(cmd, sizeof(cmd), "tar.exe -xf \"%s\" -C \"%s\"", destZip, extractDir);

    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};

    if (!CreateProcessA(nullptr, cmd, nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        Log("[MUSICMOD] tar.exe failed to start: %lu (need Windows 10 1803+)\n", GetLastError());
        return false;
    }
    WaitForSingleObject(pi.hProcess, 120000);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (exitCode != 0) {
        Log("[MUSICMOD] tar extraction failed: exit=%lu\n", exitCode);
        return false;
    }
    Log("[MUSICMOD] extraction complete\n");

    // find the extracted ffmpeg.exe (in subfolder like ffmpeg-master-latest-win64-lgpl/bin/)
    char searchPath[MAX_PATH];
    snprintf(searchPath, MAX_PATH, "%s\\*", extractDir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(searchPath, &fd);
    char ffmpegSrc[MAX_PATH] = {};
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                fd.cFileName[0] != '.') {
                snprintf(ffmpegSrc, MAX_PATH, "%s\\%s\\bin\\ffmpeg.exe", extractDir, fd.cFileName);
                if (GetFileAttributesA(ffmpegSrc) != INVALID_FILE_ATTRIBUTES) {
                    Log("[MUSICMOD] found ffmpeg.exe in: %s\n", fd.cFileName);
                    break;
                }
                ffmpegSrc[0] = '\0';
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }

    if (!ffmpegSrc[0] || GetFileAttributesA(ffmpegSrc) == INVALID_FILE_ATTRIBUTES) {
        Log("[MUSICMOD] couldn't find ffmpeg.exe in extracted archive\n");
        return false;
    }

    // copy to sd_music/ffmpeg.exe
    char dest[MAX_PATH];
    snprintf(dest, MAX_PATH, "%s\\sd_music\\ffmpeg.exe", g_gameDir);
    if (!CopyFileA(ffmpegSrc, dest, FALSE)) {
        Log("[MUSICMOD] copy to sd_music/ffmpeg.exe failed: %lu\n", GetLastError());
        return false;
    }

    // also copy ffprobe.exe if present (used for tag extraction)
    char probeSrc[MAX_PATH];
    strcpy_s(probeSrc, MAX_PATH, ffmpegSrc);
    char* slash = strrchr(probeSrc, '\\');
    if (slash) { strcpy_s(slash + 1, MAX_PATH - (slash + 1 - probeSrc), "ffprobe.exe"); }
    if (GetFileAttributesA(probeSrc) != INVALID_FILE_ATTRIBUTES) {
        char probeDest[MAX_PATH];
        snprintf(probeDest, MAX_PATH, "%s\\sd_music\\ffprobe.exe", g_gameDir);
        if (CopyFileA(probeSrc, probeDest, FALSE)) {
            Log("[MUSICMOD] ffprobe installed at: %s\n", probeDest);
        }
    }

    // cleanup zip and extract dir (best effort)
    DeleteFileA(destZip);
    // leave extract dir - cleanup is fragile, not worth crashing over

    strcpy_s(g_ffmpegPath, MAX_PATH, dest);
    Log("[MUSICMOD] ffmpeg installed at: %s\n", g_ffmpegPath);
    Log("[MUSICMOD] === ffmpeg auto-download complete ===\n");
    return true;
}

// Decode source audio to a Wwise-ready PCM WEM at t.wemPath. Native decoder
// for mp3/flac/ogg/wav, ffmpeg fallback for everything else.
static bool DecodeToPcm(CustomTrack& t) {
    // cache hit: WEM newer than source -> skip decode/encode entirely.
    WIN32_FILE_ATTRIBUTE_DATA srcAttr, cacheAttr;
    if (!GetFileAttributesExA(t.filepath.c_str(), GetFileExInfoStandard, &srcAttr)) return false;
    if (GetFileAttributesExA(t.wemPath.c_str(), GetFileExInfoStandard, &cacheAttr) &&
        CompareFileTime(&cacheAttr.ftLastWriteTime, &srcAttr.ftLastWriteTime) >= 0) {
        uint16_t dur = ReadWavOrWemDurationSec(t.wemPath.c_str());
        if (dur > 0) {
            t.channels = 2;
            t.sampleRate = 48000;
            t.bitsPerSample = 16;
            t.durationSec = dur;
            return true;
        }
        // header read failed - fall through and re-encode
    }

    // ensure cache dirs (.cache, .cache/wem, .cache/wem/Windows)
    char wemDir[MAX_PATH];
    snprintf(wemDir, MAX_PATH, "%s\\sd_music\\.cache\\wem\\Windows", g_gameDir);
    EnsureDirTree(wemDir);

    // Don't loudness-normalize: integrated-LUFS targeting flattens dynamics
    // across tracks (a quiet acoustic piece gets boosted to match a fight
    // theme), which is the opposite of what an artist intends. Keep each
    // track's native mix. Apply a conservative fixed gain reduction so we
    // sit at roughly the attenuation level the game's music bus expects.
    // env var DS2_MUSIC_GAIN_DB sets the dB reduction (default -6).
    double gainDb = -6.0;
    char envGain[32] = {};
    if (GetEnvironmentVariableA("DS2_MUSIC_GAIN_DB", envGain, sizeof(envGain)) > 0) {
        double v = atof(envGain);
        if (v >= -40.0 && v <= 6.0) gainDb = v;
    }

    // native decoders (mp3/flac/ogg/wav). Falls through to ffmpeg for
    // unrecognised formats (m4a/opus/etc).
    std::vector<int16_t> samples;
    uint32_t srcRate = 0;
    if (DecodeAudioNative(t.filepath.c_str(), samples, &srcRate)) {
        ApplyGainDb(samples, gainDb);
        uint64_t frames = samples.size() / 2;
        if (!WritePcmWemFile(t.wemPath.c_str(), samples.data(), frames, 2, srcRate)) {
            Log("[MUSICMOD] WritePcmWemFile failed for %s\n", t.filepath.c_str());
            return false;
        }
        t.channels = 2;
        t.sampleRate = srcRate;
        t.bitsPerSample = 16;
        t.durationSec = srcRate ? (uint16_t)(frames / srcRate) : 0;
        Log("[MUSICMOD] decoded (native): %s @ %uHz, %us\n",
            t.filepath.c_str(), srcRate, t.durationSec);
        return t.durationSec > 0;
    }

    // ffmpeg fallback: write a temp .wav at 48kHz/16/stereo, then convert
    // it to a PCM WEM and remove the temp.
    if (!g_ffmpegPath[0]) {
        Log("[MUSICMOD] no native decoder for %s and no ffmpeg available\n",
            t.filepath.c_str());
        return false;
    }
    char tmpWav[MAX_PATH];
    snprintf(tmpWav, MAX_PATH, "%s.tmp.wav", t.wemPath.c_str());
    char cmd[MAX_PATH * 3];
    snprintf(cmd, sizeof(cmd),
        "\"%s\" -hide_banner -loglevel error -i \"%s\" "
        "-af volume=%.2fdB "
        "-ar 48000 -ac 2 -sample_fmt s16 -y \"%s\"",
        g_ffmpegPath, t.filepath.c_str(), gainDb, tmpWav);
    Log("[MUSICMOD] decoding (ffmpeg fallback): %s\n", t.filepath.c_str());
    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi = {};
    if (!CreateProcessA(nullptr, cmd, nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        Log("[MUSICMOD] CreateProcess failed for ffmpeg: %lu\n", GetLastError());
        return false;
    }
    DWORD waitResult = WaitForSingleObject(pi.hProcess, 180000);
    if (waitResult == WAIT_TIMEOUT) {
        Log("[MUSICMOD] ffmpeg TIMEOUT for %s, killing\n", t.filepath.c_str());
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
    }
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    if (exitCode != 0) {
        Log("[MUSICMOD] ffmpeg failed for %s (exit=%lu)\n",
            t.filepath.c_str(), exitCode);
        DeleteFileA(tmpWav);
        return false;
    }
    if (!ConvertWavToPcmWem(tmpWav, t.wemPath.c_str())) {
        Log("[MUSICMOD] ConvertWavToPcmWem failed for %s\n", t.filepath.c_str());
        DeleteFileA(tmpWav);
        return false;
    }
    DeleteFileA(tmpWav);

    // duration: read it back from the WEM we just wrote.
    {
        uint16_t dur = ReadWavOrWemDurationSec(t.wemPath.c_str());
        t.channels = 2;
        t.sampleRate = 48000;
        t.bitsPerSample = 16;
        t.durationSec = dur;
        if (dur == 0) {
            Log("[MUSICMOD] dur-read returned 0 for %s\n", t.wemPath.c_str());
        }
    }
    Log("[MUSICMOD] decoded: %s (%us) -> %s\n",
        t.filepath.c_str(), t.durationSec, t.wemPath.c_str());
    return t.durationSec > 0;
}

// load WEM file bytes into t.wemBytes; marks t.isReady on success
static bool LoadTrackWemBytes(CustomTrack& t) {
    if (t.wemPath.empty()) return false;
    HANDLE h = INVALID_HANDLE_VALUE;
    for (int retry = 0; retry < 20; retry++) {
        h = CreateFileA(t.wemPath.c_str(), GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        nullptr, OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) break;
        DWORD e = GetLastError();
        if (e != ERROR_SHARING_VIOLATION) break;
        Sleep(100);
    }
    if (h == INVALID_HANDLE_VALUE) {
        Log("[MUSICMOD] WEM not found (err=%lu): %s\n",
            GetLastError(), t.wemPath.c_str());
        return false;
    }
    LARGE_INTEGER sz;
    if (!GetFileSizeEx(h, &sz) || sz.QuadPart <= 12) {
        CloseHandle(h);
        return false;
    }
    t.wemBytes.resize((size_t)sz.QuadPart);
    DWORD got = 0;
    ReadFile(h, t.wemBytes.data(), (DWORD)sz.QuadPart, &got, nullptr);
    CloseHandle(h);
    if (got != (DWORD)sz.QuadPart) {
        t.wemBytes.clear();
        return false;
    }
    // sanity check: RIFF/WAVE
    if (memcmp(t.wemBytes.data(), "RIFF", 4) != 0 ||
        memcmp(t.wemBytes.data() + 8, "WAVE", 4) != 0) {
        Log("[MUSICMOD] WEM bad header: %s\n", t.wemPath.c_str());
        t.wemBytes.clear();
        return false;
    }
    t.isReady = true;

    // parse + log fmt chunk so we can spot per-track format differences
    // between working and silent tracks (sample rate, channels, format tag,
    // any oddity in the fmt body that might trip Wwise's source plugin).
    uint32_t fmtTag = 0, sampleRate = 0, byteRate = 0, dataSize = 0;
    uint16_t channels = 0, bps = 0, blockAlign = 0;
    bool foundFmt = false, foundData = false;
    {
        const uint8_t* d = t.wemBytes.data();
        size_t n = t.wemBytes.size();
        size_t off = 12; // after RIFF + size + WAVE
        while (off + 8 <= n) {
            uint32_t cid = *(const uint32_t*)(d + off);
            uint32_t cSz = *(const uint32_t*)(d + off + 4);
            if (off + 8 + cSz > n) break;
            if (cid == 0x20746d66) { // "fmt "
                if (cSz >= 16) {
                    fmtTag     = *(const uint16_t*)(d + off + 8);
                    channels   = *(const uint16_t*)(d + off + 10);
                    sampleRate = *(const uint32_t*)(d + off + 12);
                    byteRate   = *(const uint32_t*)(d + off + 16);
                    blockAlign = *(const uint16_t*)(d + off + 20);
                    bps        = *(const uint16_t*)(d + off + 22);
                    foundFmt = true;
                }
            } else if (cid == 0x61746164) { // "data"
                dataSize = cSz;
                foundData = true;
            }
            off += 8 + cSz;
        }
    }
    Log("[MUSICMOD] WEM loaded: \"%s\" %lld bytes  fmt=0x%04X ch=%u rate=%u bps=%u block=%u byteRate=%u dataSz=%u%s%s\n",
        t.title.c_str(), sz.QuadPart,
        fmtTag, channels, sampleRate, bps, blockAlign, byteRate, dataSize,
        foundFmt ? "" : " NO_FMT", foundData ? "" : " NO_DATA");
    return true;
}

// wipe .cache/*.wav + WEMs when the decode pipeline changes (bump CACHE_VERSION
// when ffmpeg filters / wwise conversion settings change so stale caches from
// older mod versions get re-encoded)
static void InvalidateStaleCache() {
    static const char* CACHE_VERSION = "nativedyn-1";
    char markerPath[MAX_PATH];
    snprintf(markerPath, MAX_PATH, "%s\\sd_music\\.cache\\_version", g_gameDir);
    char cur[64] = {};
    HANDLE h = CreateFileA(markerPath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD got = 0;
        ReadFile(h, cur, sizeof(cur) - 1, &got, nullptr);
        cur[got] = 0;
        CloseHandle(h);
    }
    if (strcmp(cur, CACHE_VERSION) == 0) return;

    Log("[MUSICMOD] cache version %s -> %s, wiping stale outputs...\n",
        cur[0] ? cur : "<none>", CACHE_VERSION);
    auto wipeDirGlob = [&](const char* dirAbs, const char* glob) {
        char search[MAX_PATH];
        snprintf(search, MAX_PATH, "%s\\%s", dirAbs, glob);
        WIN32_FIND_DATAA fd;
        HANDLE hf = FindFirstFileA(search, &fd);
        if (hf == INVALID_HANDLE_VALUE) return;
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            char full[MAX_PATH];
            snprintf(full, MAX_PATH, "%s\\%s", dirAbs, fd.cFileName);
            DeleteFileA(full);
        } while (FindNextFileA(hf, &fd));
        FindClose(hf);
    };
    char wavDir[MAX_PATH], wemDir[MAX_PATH];
    snprintf(wavDir, MAX_PATH, "%s\\sd_music\\.cache", g_gameDir);
    snprintf(wemDir, MAX_PATH, "%s\\sd_music\\.cache\\wem\\Windows", g_gameDir);
    wipeDirGlob(wavDir, "*.wav");
    wipeDirGlob(wemDir, "*.wem");

    h = CreateFileA(markerPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD got = 0;
        WriteFile(h, CACHE_VERSION, (DWORD)strlen(CACHE_VERSION), &got, nullptr);
        CloseHandle(h);
    }
}

// worker thread: download ffmpeg if needed, decode all tracks in background
static DWORD WINAPI DecodeWorker(LPVOID) {
    Log("[MUSICMOD] decode worker started\n");

    InvalidateStaleCache();

    // ffmpeg might already be set (from FindFFmpeg in init); if not, download
    if (!g_ffmpegPath[0]) {
        Log("[MUSICMOD] no ffmpeg found, attempting auto-download...\n");
        if (!DownloadFFmpeg()) {
            Log("[MUSICMOD] ffmpeg unavailable - mp3/ogg/flac decoding disabled\n");
            Log("[MUSICMOD] only .wav files will work without ffmpeg\n");
        }
    }

    Log("[MUSICMOD] decoding %zu tracks (ffmpeg=%s)\n",
        g_tracks.size(), g_ffmpegPath[0] ? g_ffmpegPath : "<none>");

    // read tags FIRST (before ffmpeg) so they're populated by the time
    // injection happens (~6s in). single ffprobe call per file ~150ms each =
    // ~2.5s for 18 files - fast enough that ScanMusicFolder doesn't block
    // long enough to miss the music-player resource load. tag results inform
    // the cloned album/artist text built during InjectCustomTracks.
    FindFFprobe();
    for (auto& t : g_tracks) {
        std::string oldArtist = t.artist, oldTitle = t.title;
        ReadAudioTags(t);
        if (t.title != oldTitle || t.artist != oldArtist) {
            Log("[MUSICMOD] tags: \"%s\" by \"%s\" album=\"%s\"\n",
                t.title.c_str(), t.artist.c_str(), t.album.c_str());
        }
    }

    int done = 0, failed = 0;
    for (size_t i = 0; i < g_tracks.size(); i++) {
        if (DecodeToPcm(g_tracks[i])) done++;
        else failed++;
    }
    Log("[MUSICMOD] decode step: %d ok, %d failed\n", done, failed);

    int ready = 0;
    for (auto& t : g_tracks) {
        if (LoadTrackWemBytes(t)) ready++;
    }
    Log("[MUSICMOD] decode worker complete: %d/%zu tracks ready for Wwise\n",
        ready, g_tracks.size());

    // signal the template rebuilder: WEMs are loaded, bank load + SetMedia
    // can now proceed with valid media data.
    g_wemsReady = true;
    return 0;
}

// helper for extension extraction
static std::string lower_ext(const char* fname) {
    std::string s = fname;
    for (auto& c : s) c = (char)tolower(c);
    auto d = s.rfind('.');
    return d == std::string::npos ? "" : s.substr(d);
}

// ============================================================
// Object creation helpers
// ============================================================

static void* AllocObj(size_t size) {
    // use the process default heap so objects live alongside game objects
    void* mem = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    return mem;
}

static char* AllocString(const char* text) {
    size_t len = strlen(text);
    auto buf = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len + 1);
    if (buf) memcpy(buf, text, len);
    return buf;
}

static void SetObjBase(void* obj, void* vtableSrc) {
    // copy vtable pointer from source object of same type
    *(void**)obj = *(void**)vtableSrc;
    // refcount = 1
    *(uint32_t*)((uint8_t*)obj + 0x08) = 1;
    // random UUID so the streaming system doesn't conflict
    auto uuid = (uint8_t*)obj + 0x10;
    for (int i = 0; i < 16; i++) uuid[i] = (uint8_t)(rand() & 0xFF);
}

static void* CreateLocalizedText(const char* text, void* vtabSrc) {
    auto obj = (uint8_t*)AllocObj(0x40); // 0x38 needed, round up
    if (!obj) return nullptr;
    SetObjBase(obj, vtabSrc);

    *(const char**)(obj + 0x20) = AllocString(text);   // mText
    *(uint16_t*)(obj + 0x28) = (uint16_t)strlen(text); // mTextLength
    // mSubtitleMode at +0x2A is an enum stored as int32 but writing
    // uint32 here would bleed into padding. Use int16 to be safe.
    *(int16_t*)(obj + 0x2A) = 0;                       // SubtitleMode::DEFAULT
    *(void**)(obj + 0x30) = nullptr;                    // mEntry
    return obj;
}

static void* CreateArtist(uint32_t id, const char* name,
                           void* artistVtab, void* textVtab) {
    auto obj = (uint8_t*)AllocObj(0x40);
    if (!obj) return nullptr;
    SetObjBase(obj, artistVtab);

    *(uint32_t*)(obj + 0x20) = id;                          // ArtistId
    *(int16_t*)(obj + 0x24)  = (int16_t)9999;               // MenuDisplayPriority
    *(void**)(obj + 0x28) = CreateLocalizedText(name, textVtab); // ArtistNameText
    return obj;
}

static void* CreateAlbum(const char* title, const char* artistName, void* artistRes,
                          void* albumVtab, void* textVtab) {
    auto obj = (uint8_t*)AllocObj(0x60);
    if (!obj) return nullptr;
    SetObjBase(obj, albumVtab);

    *(int16_t*)(obj + 0x20) = (int16_t)9999;
    *(void**)(obj + 0x28) = CreateLocalizedText(title, textVtab);       // TitleText
    *(void**)(obj + 0x30) = CreateLocalizedText(artistName, textVtab);  // ArtistNameText
    *(void**)(obj + 0x38) = CreateLocalizedText(artistName, textVtab);  // CreditNameText
    *(void**)(obj + 0x40) = CreateLocalizedText(artistName, textVtab);  // ArtistNameTextForTelop
    *(void**)(obj + 0x48) = CreateLocalizedText(artistName, textVtab);  // CreditNameTextForTelop
    *(void**)(obj + 0x50) = artistRes;                                  // ArtistResource
    return obj;
}

// Clone a real track and override specific fields.
// This inherits all unknown fields (streaming group ID, type pointers, etc.)
// that the UI checks for visibility.
static void* CloneTrack(void* sourceTrack, uint32_t trackId, uint16_t seconds,
                         const char* title, void* albumRes, void* textVtab) {
    // type registry says objSize=768 (0x300) - clone the FULL object
    size_t cloneSize = 0x300;
    auto obj = (uint8_t*)AllocObj(cloneSize);
    if (!obj) return nullptr;

    // copy ALL bytes from the source track (inherits vtable, group ID, unk60, unk68, etc.)
    memcpy(obj, sourceTrack, cloneSize);

    // override the fields we want to customize
    *(uint32_t*)(obj + 0x08) = 1;              // RefCount = 1
    // generate new UUID so the object is unique
    for (int i = 0; i < 16; i++) obj[0x10 + i] = (uint8_t)(rand() & 0xFF);

    *(uint32_t*)(obj + 0x20) = trackId;
    *(uint16_t*)(obj + 0x24) = seconds;
    // priority is filled in by the caller (InjectCustomTracks) once the
    // index in the music-player ordering is known. seed with a sane
    // default that pushes us past vanilla tracks (max around 500).
    *(int16_t*)(obj + 0x26)  = (int16_t)20000;
    *(uint8_t*)(obj + 0x28)  = 1;              // Flag (1 = always available)
    // keep AlbumResource from source - custom albums get filtered (unregistered)
    *(void**)(obj + 0x38) = CreateLocalizedText(title, textVtab); // new title
    // keep SoundResource from source (+0x40)
    // keep TrialSoundResource from source (+0x48)
    // keep JacketUITexture from source (+0x50)
    *(void**)(obj + 0x58) = nullptr;           // OpenConditionFact = null (always unlocked)

    return obj;
}

// ============================================================
// Track injection into DSMusicPlayerSystemResource
// ============================================================


// SEH-safe walker that patches the WwiseID field at
// Track+0xB0 -> +0x1D0 -> +0x218 -> +0x48 -> +0x308
static bool PatchCustomWwiseId(void* tr, uint32_t newId, uint32_t* outOldId) {
    __try {
        void* p1 = *(void**)((uint8_t*)tr + 0xB0);    if (!p1) return false;
        void* p2 = *(void**)((uint8_t*)p1 + 0x1D0);   if (!p2) return false;
        void* p3 = *(void**)((uint8_t*)p2 + 0x218);   if (!p3) return false;
        void* p4 = *(void**)((uint8_t*)p3 + 0x48);    if (!p4) return false;
        uint32_t* fld = (uint32_t*)((uint8_t*)p4 + 0x308);
        if (outOldId) *outOldId = *fld;
        *fld = newId;
        return true;
    } __except(1) { return false; }
}

// Decima schema offsets (from types.json - authoritative).
// Used for the deep-clone path so our custom tracks don't share any pointer
// with an OG track's audio chain.
#define GSR_GRAPHPROGRAM_OFS     0x288   // GraphSoundResource.GraphProgram (Ref)
#define GPR_EXPOSEDDATA_OFS      0x0B8   // GraphProgramResource.ExposedDataResource
#define NCR_PARAMS_OFS           0x020   // NodeConstantsResource.Parameters (embedded PPL)
#define PPL_DSLO_OFS             0x020   // ProgramParameterList.DefaultSoftLinkedObjects
#define NCR_DSLO_OFS             (NCR_PARAMS_OFS + PPL_DSLO_OFS)   // 0x40 absolute
#define WWISEID_ID_OFS           0x020   // WwiseID.Id (uint32)

// Allocation sizes: padded a bit past static schema sizes to be safe against
// any runtime-state bytes we haven't characterized.
#define CLONE_WWISEID_SIZE       0x030   // schema 0x28
#define CLONE_NCR_SIZE           0x0C0   // schema ~0xA8
#define CLONE_GPR_SIZE           0x100   // schema 0xF0
#define CLONE_GSR_SIZE           0x300   // schema ~0x2B0

struct ClonedChain {
    void* gsr;
    void* gpr;
    void* ncr;
    void* wwiseId;
    void** newDsloEntries;  // our own entries array (count slots)
    uint32_t dsloCount;
    uint32_t origEventId;
    uint32_t newEventId;
};

// Walk srcGSR and return its current WwiseID.Id (event short id).
// SEH-safe. Returns 0 on any failure.
static uint32_t ReadEventIdFromGSR(void* srcGSR) {
    if (!srcGSR) return 0;
    __try {
        void* gpr = *(void**)((uint8_t*)srcGSR + GSR_GRAPHPROGRAM_OFS);
        if (!gpr) return 0;
        void* ncr = *(void**)((uint8_t*)gpr + GPR_EXPOSEDDATA_OFS);
        if (!ncr) return 0;
        auto* dslo = (RawArray*)((uint8_t*)ncr + NCR_DSLO_OFS);
        if (!dslo->entries || dslo->count == 0) return 0;
        void* wwiseId = dslo->entries[0];
        if (!wwiseId) return 0;
        return *(uint32_t*)((uint8_t*)wwiseId + WWISEID_ID_OFS);
    } __except(1) { return 0; }
}

// Build a fresh Decima chain that behaves like srcGSR's, but with WwiseID.Id
// replaced by customEventId. Nothing from srcGSR's chain is mutated; this
// satisfies the additive-only HARD RULE.
// Returns true on success and fills `out`.
// cache of a KNOWN-GOOD WwiseID object's bytes, captured from the first
// source track whose DSLO[0] is clearly a WwiseID (non-sentinel Id). We use
// this as the template for tracks where DSLO[0] isn't a real WwiseID - those
// tracks' DSLO[0] holds a non-WwiseID object (hence garbage Id like 82),
// copying its bytes produces a clone with the wrong vtable which the dispatch
// path silently ignores, so the source event fires instead of our cloned one.
static uint8_t g_wwiseIdTemplate[CLONE_WWISEID_SIZE] = {};
static bool    g_haveWwiseIdTemplate = false;

static const uint32_t WWISEID_SENTINEL = 82;

static bool BuildClonedChain(void* srcGSR, uint32_t customEventId,
                              ClonedChain* out) {
    if (!srcGSR || !out) return false;
    memset(out, 0, sizeof(*out));

    void* srcGPR = nullptr;
    void* srcNCR = nullptr;
    RawArray srcDsloCopy{};
    void* srcWwiseID = nullptr;
    uint32_t srcOrigId = 0;
    __try {
        srcGPR = *(void**)((uint8_t*)srcGSR + GSR_GRAPHPROGRAM_OFS);
        if (!srcGPR) return false;
        srcNCR = *(void**)((uint8_t*)srcGPR + GPR_EXPOSEDDATA_OFS);
        if (!srcNCR) return false;
        auto* srcDslo = (RawArray*)((uint8_t*)srcNCR + NCR_DSLO_OFS);
        srcDsloCopy = *srcDslo;
        if (!srcDsloCopy.entries || srcDsloCopy.count == 0) return false;
        srcWwiseID = srcDsloCopy.entries[0];
        if (!srcWwiseID) return false;
        srcOrigId = *(uint32_t*)((uint8_t*)srcWwiseID + WWISEID_ID_OFS);
    } __except(1) { return false; }

    // if source has a real WwiseID, cache it for later fallback use.
    if (!g_haveWwiseIdTemplate && srcOrigId != WWISEID_SENTINEL) {
        __try {
            memcpy(g_wwiseIdTemplate, srcWwiseID, CLONE_WWISEID_SIZE);
            g_haveWwiseIdTemplate = true;
            Log("[MUSICMOD] cached WwiseID template from srcId=%u\n", srcOrigId);
        } __except(1) {}
    }

    auto newWwiseID = AllocObj(CLONE_WWISEID_SIZE);
    auto newNCR     = AllocObj(CLONE_NCR_SIZE);
    auto newGPR     = AllocObj(CLONE_GPR_SIZE);
    auto newGSR     = AllocObj(CLONE_GSR_SIZE);
    if (!newWwiseID || !newNCR || !newGPR || !newGSR) return false;

    uint32_t origEventId = 0;
    void** newEntries = nullptr;
    bool   usedTemplate = false;

    __try {
        // if source's DSLO[0] isn't a real WwiseID, seed our clone from the
        // cached template (a proven WwiseID). this gives us the right vtable
        // and object layout so the dispatch path recognizes it, instead of
        // silently falling back to the source's own resolution path.
        if (srcOrigId == WWISEID_SENTINEL && g_haveWwiseIdTemplate) {
            memcpy(newWwiseID, g_wwiseIdTemplate, CLONE_WWISEID_SIZE);
            usedTemplate = true;
        } else {
            memcpy(newWwiseID, srcWwiseID, CLONE_WWISEID_SIZE);
        }
        memcpy(newNCR, srcNCR, CLONE_NCR_SIZE);
        memcpy(newGPR, srcGPR, CLONE_GPR_SIZE);
        memcpy(newGSR, srcGSR, CLONE_GSR_SIZE);

        // reset RefCount + fresh UUIDs so clones look unique
        uint8_t* hdrs[4] = { (uint8_t*)newGSR, (uint8_t*)newGPR,
                             (uint8_t*)newNCR, (uint8_t*)newWwiseID };
        for (uint8_t* o : hdrs) {
            *(uint32_t*)(o + 0x08) = 1;
            for (int i = 0; i < 16; i++) o[0x10 + i] = (uint8_t)(rand() & 0xFF);
        }

        origEventId = *(uint32_t*)((uint8_t*)newWwiseID + WWISEID_ID_OFS);
        *(uint32_t*)((uint8_t*)newWwiseID + WWISEID_ID_OFS) = customEventId;
        (void)usedTemplate;  // informational; caller logs via origEventId context

        // fresh DSLO entries array so we don't share the source's pointer
        size_t entriesBytes = (size_t)srcDsloCopy.count * sizeof(void*);
        newEntries = (void**)HeapAlloc(GetProcessHeap(), 0, entriesBytes);
        if (!newEntries) return false;
        for (uint32_t i = 0; i < srcDsloCopy.count; i++)
            newEntries[i] = srcDsloCopy.entries[i];
        newEntries[0] = newWwiseID;  // swap slot 0 to our clone, keep [1]=SoundGroup

        auto* newDslo = (RawArray*)((uint8_t*)newNCR + NCR_DSLO_OFS);
        newDslo->count = srcDsloCopy.count;
        newDslo->capacity = srcDsloCopy.count;
        newDslo->entries = newEntries;

        *(void**)((uint8_t*)newGPR + GPR_EXPOSEDDATA_OFS) = newNCR;
        *(void**)((uint8_t*)newGSR + GSR_GRAPHPROGRAM_OFS) = newGPR;
    } __except(1) { return false; }

    out->gsr = newGSR;
    out->gpr = newGPR;
    out->ncr = newNCR;
    out->wwiseId = newWwiseID;
    out->newDsloEntries = newEntries;
    out->dsloCount = srcDsloCopy.count;
    out->origEventId = origEventId;
    out->newEventId = customEventId;
    return true;
}

// helper: SEH-safe pointer dump (can't __try inside InjectCustomTracks - uses std::vector)
static void SafeDumpQwords(void* p, char* outBuf, size_t outSz, int n = 8) {
    outBuf[0] = 0;
    if (!p) return;
    for (int q = 0; q < n; q++) {
        uint64_t v = 0;
        __try { v = *((uint64_t*)p + q); } __except(1) { return; }
        char tmp[32]; snprintf(tmp, sizeof(tmp), "%016llX ", (unsigned long long)v);
        strncat_s(outBuf, outSz, tmp, _TRUNCATE);
    }
}

static void InjectCustomTracks(void* sysRes) {
    if (g_injected || g_tracks.empty()) return;

    Log("[MUSICMOD] injecting %zu tracks into DSMusicPlayerSystemResource @ %p\n",
        g_tracks.size(), sysRes);

    auto* artistArr = (RawArray*)((uint8_t*)sysRes + 0x20);
    auto* trackArr = (RawArray*)((uint8_t*)sysRes + 0x30);
    g_musicTrackArr = trackArr;  // expose for per-track jacket polling
    Log("[MUSICMOD] existing: %u artists, %u tracks (g_musicTrackArr=%p)\n",
        artistArr->count, trackArr->count, g_musicTrackArr);

    if (trackArr->count == 0 || artistArr->count == 0) {
        Log("[MUSICMOD] no existing data to reference, aborting injection\n");
        return;
    }

    // grab vtable sources from existing objects
    void* srcTrack  = trackArr->entries[0];
    void* srcArtist = artistArr->entries[0];
    void* srcAlbum  = *(void**)((uint8_t*)srcTrack + 0x30);  // first track's album
    void* srcText   = *(void**)((uint8_t*)srcTrack + 0x38);  // first track's title text
    void* srcSound  = *(void**)((uint8_t*)srcTrack + 0x40);  // first track's sound resource
    void* srcFact   = *(void**)((uint8_t*)srcTrack + 0x58);  // first track's unlock condition

    Log("[MUSICMOD] vtable sources:\n");
    Log("[MUSICMOD]   track  = %p (%s)\n", srcTrack, ObjTypeName(srcTrack));
    Log("[MUSICMOD]   artist = %p (%s)\n", srcArtist, ObjTypeName(srcArtist));
    Log("[MUSICMOD]   album  = %p (%s)\n", srcAlbum, srcAlbum ? ObjTypeName(srcAlbum) : "null");
    Log("[MUSICMOD]   text   = %p (%s)\n", srcText, srcText ? ObjTypeName(srcText) : "null");
    Log("[MUSICMOD]   sound  = %p (%s)\n", srcSound, srcSound ? ObjTypeName(srcSound) : "null");
    Log("[MUSICMOD]   fact   = %p (unlock condition from track 0)\n", srcFact);

    if (!srcAlbum || !srcText || !srcSound) {
        Log("[MUSICMOD] missing vtable source, aborting\n");
        return;
    }


    srand(GetTickCount());

    // pre-scan OG tracks: find indices whose TrialSoundResource is a real
    // music chain (DSLO[0] = WwiseID with non-sentinel Id). only custom rows
    // borrowed from such "music" sources successfully dispatch our cloned
    // custom event; sources backed by non-music rows (jingles/ambient with
    // sentinel 82) cause the game to silently use its own playback path.
    auto safeReadTrialRes = [](void* ogTrack) -> void* {
        void* res = nullptr;
        __try { res = *(void**)((uint8_t*)ogTrack + 0x48); } __except(1) {}
        return res;
    };
    auto safeReadDur = [](void* ogTrack) -> uint16_t {
        uint16_t d = 0;
        __try { d = *(uint16_t*)((uint8_t*)ogTrack + 0x24); } __except(1) {}
        return d;
    };

    // music-capable sources. We restrict to ONLY the bb_theme_Preview source
    // (Wwise event id 3993410792 for the trial). Frida-tracked GSP per-pid
    // confirmed: tracks borrowing this source advance position cleanly, while
    // tracks borrowing other sources freeze at ~1.5s and resume sporadically.
    // The OG source's internal music-segment configuration bleeds through
    // our cloned chain in ways our bank patches don't reach. Using one
    // known-good source for every custom = consistent ticker behaviour.
    struct MusicSrc { size_t idx; uint16_t dur; };
    std::vector<MusicSrc> musicSrcs;
    musicSrcs.reserve(32);
    const uint32_t kPreferredSrcEvent = 3993410792u; // bb_theme_Preview trial
    for (uint32_t si = 0; si < trackArr->count; si++) {
        void* ogTrack = trackArr->entries[si];
        if (!ogTrack) continue;
        void* ogTrialRes = safeReadTrialRes(ogTrack);
        if (!ogTrialRes) continue;
        uint32_t eid = ReadEventIdFromGSR(ogTrialRes);
        if (eid == kPreferredSrcEvent) {
            musicSrcs.push_back({(size_t)si, safeReadDur(ogTrack)});
        }
    }
    if (musicSrcs.empty()) {
        // bb_theme not present in this build's bank - fall back to any
        // music-capable source so we still produce something usable.
        Log("[MUSICMOD] preferred src (bb_theme) not found, falling back to any music source\n");
        for (uint32_t si = 0; si < trackArr->count; si++) {
            void* ogTrack = trackArr->entries[si];
            if (!ogTrack) continue;
            void* ogTrialRes = safeReadTrialRes(ogTrack);
            if (!ogTrialRes) continue;
            uint32_t eid = ReadEventIdFromGSR(ogTrialRes);
            if (eid != 0 && eid != WWISEID_SENTINEL) {
                musicSrcs.push_back({(size_t)si, safeReadDur(ogTrack)});
            }
        }
    }
    std::sort(musicSrcs.begin(), musicSrcs.end(),
              [](const MusicSrc& a, const MusicSrc& b) { return a.dur > b.dur; });
    Log("[MUSICMOD] pre-scan: %zu music-capable OG tracks (longest dur=%us)\n",
        musicSrcs.size(), musicSrcs.empty() ? 0 : musicSrcs[0].dur);
    for (size_t k = 0; k < musicSrcs.size() && k < 8; k++) {
        Log("[MUSICMOD]   src[%zu] dur=%us\n", musicSrcs[k].idx, musicSrcs[k].dur);
    }
    if (musicSrcs.empty()) {
        Log("[MUSICMOD] no music-capable sources; falling back to all tracks\n");
        for (uint32_t si = 0; si < trackArr->count; si++) {
            musicSrcs.push_back({(size_t)si, 0});
        }
    }

    // clone tracks borrowing from a duration-compatible source so the cloned
    // MusicSegment can hold the full WEM. for each custom track we walk the
    // sorted source list and pick the first source whose preview duration
    // >= our track's duration (cycling within the eligible subset for variety
    // in album art). if no source is long enough, fall back to the longest.
    std::vector<void*> newTracks;
    g_borrowedWwiseIds.clear();

    // per-source rotation counter so multiple custom tracks don't all hit
    // the exact same source when many are eligible
    size_t rotation = 0;

    // build one AlbumResource PER UNIQUE ARTIST among the custom tracks. The
    // music-player UI groups rows by AlbumResource pointer, so sharing a
    // pointer per artist makes tracks from the same artist cluster while
    // still showing correct artist labels. All custom albums use a borrowed
    // registered album as their template (copy + override title/artist text).
    void* templateAlbumSrc = nullptr;
    if (!musicSrcs.empty()) {
        void* ogTrack = trackArr->entries[musicSrcs[0].idx];
        if (ogTrack) templateAlbumSrc = *(void**)((uint8_t*)ogTrack + 0x30);
    }

    // capture an OG UITexture (jacket) byte template - we'll use it to clone
    // a per-custom-track UITexture with our own BC7 album art bytes patched in.
    // Layout (per types schema): 16B GGUUID + 1B bool + SmallTextureInfo +
    // LargeTextureInfo + 8B SmallFramesRef + 8B LargeFramesRef + 8B Frames.Size
    // + 1B bool. Each TextureInfo = 16B header + 16B hash + 16B data hdr +
    // EmbeddedSize bytes. So full UITexture = ~16 + 1 + (32+16+65536) + (32+16+262144)
    // + 8+8+8+1 = 327818 bytes (256x256 small + 512x512 large, both BC7).
    // first, scan all OG tracks and log their id + +0x50 ptr so we can see
    // which entries are real music tracks vs sentinels/placeholders.
    Log("[MUSICMOD] OG track scan (count=%u):\n", trackArr->count);
    for (uint32_t i = 0; i < trackArr->count; i++) {
        void* og = trackArr->entries[i];
        if (!og) { Log("  [%u] NULL\n", i); continue; }
        uint32_t trId = 0;
        void* ui = nullptr;
        void* sound = nullptr;
        SafeReadBytes(&trId, (uint8_t*)og + 0x20, 4);
        ui = SafeReadPtr(og, 0x50);
        sound = SafeReadPtr(og, 0x40);
        Log("  [%u] og=%p id=0x%08X sound=%p ui=%p\n", i, og, trId, sound, ui);
    }

    // dump og[45]'s ENTIRE first 0x100 bytes so we can find the actual
    // JacketUITexture field offset (0x50 is wrong - all tracks share that ptr
    // into a small lookup table region).
    if (trackArr->count > 45 && trackArr->entries[45]) {
        uint8_t* og45 = (uint8_t*)trackArr->entries[45];
        uint8_t buf[0x100] = {0};
        if (SafeReadBytes(buf, og45, sizeof(buf))) {
            Log("[MUSICMOD] og[45] @ %p full dump:\n", og45);
            for (int row = 0; row < (int)sizeof(buf); row += 16) {
                char line[128] = {0};
                int wo = 0;
                for (int b = 0; b < 16; b++) {
                    wo += snprintf(line + wo, sizeof(line) - wo,
                                   "%02X ", buf[row+b]);
                }
                Log("[MUSICMOD] og[45] +%03X: %s\n", row, line);
            }
            // also dump as 8-byte ptrs with annotation
            for (int q = 0; q < 32; q++) {
                uint64_t v = *(uint64_t*)(buf + q*8);
                const char* tag = "data";
                if (v >= 0x140000000ull && v < 0x800000000000ull) tag = "ptr";
                Log("[MUSICMOD] og[45] +%03X: 0x%016llX  %s\n",
                    q*8, (unsigned long long)v, tag);
            }
        }
    }

    // capture an OG UITexture to use as a template. Skip track[0] which is
    // a sentinel (id=0x00000001, ui points to cargo registry not a UITexture).
    // Prefer track[45] (bb_theme) which is a known-real music track.
    void* templateUITexture = nullptr;
    void* templateUITextureSrcTrack = nullptr;
    uint32_t preferIdx[] = { 45, 1, 2, 3 };
    for (uint32_t pi = 0; pi < 4 && !templateUITexture; pi++) {
        if (preferIdx[pi] >= trackArr->count) continue;
        void* og = trackArr->entries[preferIdx[pi]];
        if (!og) continue;
        void* ui = SafeReadPtr(og, 0x50);
        if (ui) {
            templateUITexture = ui;
            templateUITextureSrcTrack = og;
            uint32_t trId = 0;
            SafeReadBytes(&trId, (uint8_t*)og + 0x20, 4);
            Log("[MUSICMOD] UITexture template captured from OG track[%u] id=0x%08X UI=%p (preferred)\n",
                preferIdx[pi], trId, ui);
            // dump the first 256 bytes
            uint8_t* p = (uint8_t*)ui;
            uint8_t outerBuf[256] = {0};
            if (SafeReadBytes(outerBuf, p, sizeof(outerBuf))) {
                for (int row = 0; row < 256; row += 16) {
                    char line[128] = {0};
                    int wo = 0;
                    for (int b = 0; b < 16; b++) {
                        wo += snprintf(line + wo, sizeof(line) - wo, "%02X ", outerBuf[row+b]);
                    }
                    Log("[MUSICMOD] UITex(%u) +%03X: %s\n", preferIdx[pi], row, line);
                }
            }
            break;
        }
    }
    for (uint32_t i = 0; !templateUITexture && i < trackArr->count; i++) {
        void* og = trackArr->entries[i];
        if (!og) continue;
        void* ui = SafeReadPtr(og, 0x50);
        if (ui) {
            templateUITexture = ui;
            templateUITextureSrcTrack = og;
            uint32_t trId = *(uint32_t*)((uint8_t*)og + 0x20);
            Log("[MUSICMOD] UITexture template captured from OG track[%u] id=0x%08X UI=%p\n",
                i, trId, ui);
            // dump first 256 bytes so we can derive the actual UITexture layout
            uint8_t* p = (uint8_t*)ui;
            for (int row = 0; row < 256; row += 16) {
                char line[128] = {0};
                int off = 0;
                for (int b = 0; b < 16; b++) {
                    off += snprintf(line + off, sizeof(line) - off,
                                    "%02X ", p[row + b]);
                }
                Log("[MUSICMOD] UITex +%03X: %s\n", row, line);
            }
            // walk every "varying" pointer in the first 256 bytes (offsets
            // 0x00, 0x10, 0x30, 0x40, ... - the ones at +0x08 within each
            // pair are the repeating typeinfo). For each, dump 80 bytes from
            // the target so we can find which sub-object holds BC7 bytes
            // (look for size markers 0x10000 / 0x40000 = 65536 / 262144).
            const int probeOffs[] = { 0x00, 0x10, 0x30, 0x40, 0x50, 0x60,
                                       0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0,
                                       0xD0, 0xE0, 0xF0 };
            for (int pi = 0; pi < (int)(sizeof(probeOffs)/sizeof(probeOffs[0])); pi++) {
                int o = probeOffs[pi];
                uint8_t* sub = (uint8_t*)SafeReadPtr(p, o);
                if (!sub) continue;
                uint8_t buf[64] = {0};
                if (!SafeReadBytes(buf, sub, sizeof(buf))) {
                    Log("[MUSICMOD] UITex[+%03X]->%p: <unreadable>\n", o, sub);
                    continue;
                }
                char line[256] = {0};
                int wo = 0;
                for (int b = 0; b < 64; b++) {
                    wo += snprintf(line + wo, sizeof(line) - wo,
                                   "%02X ", buf[b]);
                }
                Log("[MUSICMOD] UITex[+%03X]->%p: %s\n", o, sub, line);
            }
            break;
        }
    }
    if (!templateUITexture) {
        Log("[MUSICMOD] no OG track has UITexture; album art will fall back to source\n");
    }
    std::vector<std::pair<std::string, void*>> artistAlbums;  // artist (UPPER) -> album
    auto getOrMakeAlbumForArtist = [&](const std::string& artistRaw,
                                       const std::string& albumTitle) -> void* {
        // music player UI convention: artist names are displayed in ALL CAPS
        std::string artist = artistRaw;
        for (auto& c : artist) c = (char)toupper((unsigned char)c);
        for (auto& kv : artistAlbums) if (kv.first == artist) return kv.second;
        if (!templateAlbumSrc) return nullptr;
        auto albumClone = (uint8_t*)AllocObj(0x300);
        if (!albumClone) return nullptr;
        memcpy(albumClone, templateAlbumSrc, 0x300);
        void* artistTxt = CreateLocalizedText(artist.c_str(), srcText);
        if (artistTxt) {
            *(void**)(albumClone + 0x30) = artistTxt;  // ArtistNameText
            *(void**)(albumClone + 0x40) = artistTxt;  // ArtistNameTextForTelop
        }
        void* titleTxt = CreateLocalizedText(albumTitle.c_str(), srcText);
        if (titleTxt) *(void**)(albumClone + 0x28) = titleTxt;  // TitleText
        artistAlbums.push_back({artist, (void*)albumClone});
        Log("[MUSICMOD] AlbumResource for artist \"%s\" @ %p\n",
            artist.c_str(), (void*)albumClone);
        return albumClone;
    };

    for (size_t i = 0; i < g_tracks.size(); i++) {
        uint16_t needDur = g_tracks[i].durationSec;
        size_t srcIdx = musicSrcs[0].idx;  // default = longest
        // count eligible sources
        size_t nEligible = 0;
        for (auto& m : musicSrcs) if (m.dur >= needDur) nEligible++;
        if (nEligible > 0) {
            size_t pick = rotation++ % nEligible;
            size_t seen = 0;
            for (auto& m : musicSrcs) {
                if (m.dur >= needDur) {
                    if (seen == pick) { srcIdx = m.idx; break; }
                    seen++;
                }
            }
        } else {
            Log("[MUSICMOD] INJECT \"%s\" dur=%us has NO eligible source (longest=%us); using longest anyway\n",
                g_tracks[i].title.c_str(), needDur, musicSrcs[0].dur);
        }
        auto srcTrackForClone = (uint8_t*)trackArr->entries[srcIdx];
        if (!srcTrackForClone) {
            Log("[MUSICMOD] INJECT i=%zu: trackArr->entries[%zu] is null, skipping custom track \"%s\"\n",
                i, srcIdx, g_tracks[i].title.c_str());
            continue;
        }

        void* tr = CloneTrack(
            srcTrackForClone,
            g_tracks[i].stableId,        // FNV-derived id, stable across boots
            g_tracks[i].durationSec,
            g_tracks[i].title.c_str(),
            nullptr,                     // keep source album (registered)
            srcText
        );
        if (!tr) {
            Log("[MUSICMOD] INJECT i=%zu: CloneTrack returned null for \"%s\" (srcIdx=%zu src=%p)\n",
                i, g_tracks[i].title.c_str(), srcIdx, srcTrackForClone);
            continue;
        }

        // point this track at the per-artist album so rows from the same
        // artist cluster. Different artists get different albums (still in
        // the same bottom section thanks to high priority).
        void* albumForTrack = getOrMakeAlbumForArtist(g_tracks[i].artist,
                                                      g_tracks[i].album);
        if (albumForTrack) {
            *(void**)((uint8_t*)tr + 0x30) = albumForTrack;
        }

        // ALBUM ART (diagnostic): the previous in-memory clone+byte-patch
        // approach failed because the runtime UITexture is a small
        // pointer-pair struct that points to GPU-side sub-resources, not an
        // inline serialized blob. Instead, borrow a DIFFERENT OG track's
        // JacketUITexture pointer per custom so we can verify (a) that
        // tr+0x50 actually drives the jacket the UI displays and (b) the
        // pipeline is sound. If varied jackets appear, the next step is to
        // construct a real UITexture object with our BC7 bytes.
        //
        // Pick a different OG track per custom (skip track[0] sentinel and
        // skip the borrow source bb_theme so jackets are visibly different).
        // Use the track's stableId hash so the same MP3 always gets the same
        // borrowed jacket across launches.
        // VALIDATION TEST: borrow OG UITexture as before, but ALSO
        // swap the C+0x08 dst pointer to a freshly-created BC7 dst with
        // this track's custom art. If this works (custom row shows
        // custom art), we know our dst creation path is sound. If it
        // doesn't, dst creation has issues (state, format, descriptor
        // mismatch) we need to fix before any cloning attempt.
        if (trackArr->count > 1) {
            uint32_t pick = (uint32_t)(g_tracks[i].stableId % trackArr->count);
            if (pick == 0) pick = 1;
            if (pick == 45) pick = 46 < trackArr->count ? 46 : 1;
            void* og = trackArr->entries[pick];
            if (og) {
                void* otherUI = SafeReadPtr(og, 0x50);
                if (otherUI) {
                    *(void**)((uint8_t*)tr + 0x50) = otherUI;
                    if (i < 3) {
                        Log("[MUSICMOD] borrowed jacket from OG[%u] -> %p for \"%s\"\n",
                            pick, otherUI, g_tracks[i].title.c_str());
                    }
                    // [REMOVED] DST-swap test confirmed engine doesn't use
                    // chain pointers for sampling -- pre-baked SRVs in
                    // descriptor heap reference the original dsts. Direct
                    // GPU upload to the OG dsts is the path (handled by
                    // the direct uploader thread).
                }
            }
        }

        // push to bottom of menu - existing tracks max around prio 500
        *(int16_t*)((uint8_t*)tr + 0x26) = (int16_t)(30000 + (int)i);

        g_tracks[i].pTrackResource = tr;
        newTracks.push_back(tr);
        uint32_t trVerifyId  = *(uint32_t*)((uint8_t*)tr + 0x20);
        int16_t  trVerifyPri = *(int16_t*) ((uint8_t*)tr + 0x26);
        uint16_t trVerifyDur = *(uint16_t*)((uint8_t*)tr + 0x24);
        void*    trSoundRes  = *(void**)   ((uint8_t*)tr + 0x40);
        void*    trTrialRes  = *(void**)   ((uint8_t*)tr + 0x48);
        void*    trAlbum     = *(void**)   ((uint8_t*)tr + 0x30);
        Log("[MUSICMOD] created track 0x%08X: \"%s\" (borrowed sound from track[%zu]) verify: id=%u prio=%d dur=%u\n",
            g_tracks[i].stableId, g_tracks[i].title.c_str(), srcIdx,
            trVerifyId, trVerifyPri, trVerifyDur);
        Log("[MUSICMOD]   IDENTIFIERS: TrackResource=%p SoundResource=%p TrialSound=%p Album=%p\n",
            tr, trSoundRes, trTrialRes, trAlbum);

        // DEEP CLONE experiment: build a fresh GSR/GPR/NCR/WwiseID chain and
        // route the custom row's TRIAL (+0x48) through it. For first test,
        // point the cloned WwiseID.Id at ANOTHER source track's trial event
        // so we can tell audibly whether the clone is being consulted or the
        // source chain is still in play.
        //
        // Target selection: read src[(srcIdx+1) % count]'s trial event id. If
        // the clone is wired right, custom row i will play that other track's
        // sample when Y is pressed. If not, it'll still play srcTrack's sample.
        //
        // HARD RULE check: we only read from source objects, never write. All
        // writes go to freshly-allocated heap memory.
        uint32_t origTrialId = ReadEventIdFromGSR(trTrialRes);
        // Iteration 1: route at CUSTOM_EVENT_BASE+i, which is our own Event item
        // appended to the extended bank with M61's playback chain (same WEM,
        // different IDs). If this works, we hear M61 audio through OUR chain,
        // proving the appended music-engine items are functional.
        uint32_t redirectTrialId = CUSTOM_EVENT_BASE + (uint32_t)i;

        Log("[MUSICMOD]   trial-chain: src=%p origEventId=%u, redirecting to custom event %u (0x%08X)\n",
            trTrialRes, origTrialId, redirectTrialId, redirectTrialId);

        if (redirectTrialId != 0 && trTrialRes != nullptr) {
            ClonedChain cc{};
            if (BuildClonedChain(trTrialRes, redirectTrialId, &cc)) {
                Log("[MUSICMOD]   clone OK: GSR=%p GPR=%p NCR=%p WwiseID=%p (orig id=%u -> new id=%u, %u DSLO slots)\n",
                    cc.gsr, cc.gpr, cc.ncr, cc.wwiseId,
                    cc.origEventId, cc.newEventId, cc.dsloCount);
                // install clone as the custom row's trial (+0x48) AND full play (+0x40)
                // chains. Track+0x48 = TrialSoundResource (Y-press sample);
                // Track+0x40 = SoundResource (full-track play). Both are
                // Ref<SoundResource> so they accept the same cloned GSR.
                // Without +0x40 install, the music-player play dispatcher
                // (sub_14269b3d0) resolves the audioNode from the source's
                // un-cloned chain and plays the source track.
                *(void**)((uint8_t*)tr + 0x48) = cc.gsr;
                *(void**)((uint8_t*)tr + 0x40) = cc.gsr;
                Log("[MUSICMOD]   Track+0x40 and +0x48 now -> %p (our cloned GSR)\n", cc.gsr);
            } else {
                Log("[MUSICMOD]   clone FAILED - leaving shared chain in place\n");
            }
        } else {
            Log("[MUSICMOD]   skipping clone: missing redirectTrialId or trTrialRes\n");
        }
    }

    if (newTracks.empty()) {
        Log("[MUSICMOD] no tracks created, aborting\n");
        return;
    }

    // DON'T extend AllArtists in-place - the artist buffer may be adjacent
    // to the track buffer, and writing past it would corrupt track data.
    // Custom tracks link to the artist through album refs, so AllArtists
    // extension isn't strictly needed for display.
    Log("[MUSICMOD] AllArtists: %u (not extending - linked via album refs)\n", artistArr->count);

    // extend AllTracks. If capacity is too small we MUST allocate a fresh
    // buffer - writing past the original allocation corrupts whatever heap
    // block follows it, which causes async crashes 6-22s later when Wwise's
    // mixer thread or the heap scavenger walks the trampled region.
    {
        uint32_t oldCount = trackArr->count;
        uint32_t oldCap = trackArr->capacity;
        uint32_t newCount = oldCount + (uint32_t)newTracks.size();
        Log("[MUSICMOD] AllTracks: count=%u cap=%u entries=%p, extending to %u\n",
            oldCount, oldCap, trackArr->entries, newCount);

        if (oldCap >= newCount) {
            for (size_t i = 0; i < newTracks.size(); i++)
                trackArr->entries[oldCount + i] = newTracks[i];
            trackArr->count = newCount;
            Log("[MUSICMOD] AllTracks: %u -> %u (in existing capacity)\n", oldCount, newCount);
        } else {
            // grow with headroom so future re-inject (after unload/load cycle)
            // doesn't need another reallocation
            uint32_t newCap = newCount + 32;
            void** newEntries = (void**)VirtualAlloc(nullptr, newCap * sizeof(void*),
                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!newEntries) {
                Log("[MUSICMOD] AllTracks: VirtualAlloc failed, ABORTING extension\n");
                return;
            }
            memcpy(newEntries, trackArr->entries, oldCount * sizeof(void*));
            for (size_t i = 0; i < newTracks.size(); i++)
                newEntries[oldCount + i] = newTracks[i];
            trackArr->entries = newEntries;
            trackArr->count = newCount;
            trackArr->capacity = newCap;
            Log("[MUSICMOD] AllTracks: %u -> %u (reallocated, new entries=%p cap=%u)\n",
                oldCount, newCount, newEntries, newCap);
        }
    }

    g_injected = true;
    Log("[MUSICMOD] injection complete\n");


    // first test: try reloading the captured bank with a modified bank ID
    // if THIS works, the parsing/load mechanism is fine and our HIRC is the problem
    // if this fails too, our load approach is wrong
    if (g_loadBankMemoryCopy && g_capturedBank && g_capturedBankSize > 0) {
        // make a copy with modified bankId
        auto testBank = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, g_capturedBankSize);
        if (testBank) {
            memcpy(testBank, g_capturedBank, g_capturedBankSize);
            // change bankId at BKHD body offset +0x04 (BKHD starts at 0, body starts at +8)
            *(uint32_t*)(testBank + 8 + 4) = 0xCAFE0001;
            uint32_t testBankId = 0;
            int32_t testResult = g_loadBankMemoryCopy(testBank, g_capturedBankSize, &testBankId);
            Log("[MUSICMOD] reload test (captured bank, modified id): result=%d bankId=%u\n",
                testResult, testBankId);
        }
    }

    // test: build a minimal bank (BKHD + empty HIRC) to verify our format is correct
    if (g_loadBankMemoryCopy && g_capturedBank && g_capturedBankSize >= 56) {
        uint32_t bkhdBodySize = *(uint32_t*)(g_capturedBank + 4);
        // total: BKHD(8 + bodySize) + HIRC(8 + 4) = bodySize + 20
        uint32_t emptyBankSize = 8 + bkhdBodySize + 8 + 4;
        auto emptyBank = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, emptyBankSize);
        if (emptyBank) {
            // BKHD: copy header from captured, modify bank ID
            memcpy(emptyBank, g_capturedBank, 8 + bkhdBodySize);
            *(uint32_t*)(emptyBank + 8 + 4) = 0xCAFE0002; // unique bank ID
            // HIRC: tag + size + numItems(0)
            uint8_t* hp = emptyBank + 8 + bkhdBodySize;
            memcpy(hp, "HIRC", 4); hp += 4;
            *(uint32_t*)hp = 4; hp += 4;        // chunk size = 4 (just numItems)
            *(uint32_t*)hp = 0;                 // numItems = 0

            uint32_t emptyBankId = 0;
            int32_t emptyResult = g_loadBankMemoryCopy(emptyBank, emptyBankSize, &emptyBankId);
            Log("[MUSICMOD] EMPTY bank test (BKHD+empty HIRC): result=%d bankId=%u size=%u\n",
                emptyResult, emptyBankId, emptyBankSize);
        }
    }

    // try loading our custom Wwise bank
    // DISABLED: this early BuildCustomBank load registered Action 0xAD300000
    // with target 0xAD200000 (CUSTOM_SOUND_BASE) BEFORE BuildMinimalMusicBank
    // could register the same Action ID with target 0xAD500000 (our cloned MRSC).
    // Wwise dedups by ulID and keeps the first registration, so our music chain
    // action's target was being shadowed by a stale plain-Sound action target.
    if (false && g_loadBankMemoryCopy && !g_tracks.empty()) {
        uint32_t bankSize = 0;
        uint8_t* bankData = BuildCustomBank((int)g_tracks.size(), &bankSize);
        if (bankData) {
            // dump our custom bank to disk for comparison
            char customPath[MAX_PATH];
            snprintf(customPath, MAX_PATH, "%s\\sd_music\\.cache\\custom.bnk", g_gameDir);
            FILE* cf = fopen(customPath, "wb");
            if (cf) { fwrite(bankData, 1, bankSize, cf); fclose(cf); }
            Log("[MUSICMOD] custom bank dumped to %s\n", customPath);

            uint32_t bankId = 0;
            int32_t result = g_loadBankMemoryCopy(bankData, bankSize, &bankId);
            Log("[MUSICMOD] custom bank load: result=%d bankId=%u (size=%u)\n",
                result, bankId, bankSize);
            if (result == 1) {
                Log("[MUSICMOD] CUSTOM BANK LOADED SUCCESSFULLY\n");

                // try walking the captured bank's HIRC for a Sound (type 2) we can study
                if (g_capturedBank && g_capturedBankSize > 56) {
                    // find HIRC chunk
                    auto bp = g_capturedBank;
                    size_t pos = 0;
                    while (pos + 8 <= g_capturedBankSize) {
                        if (memcmp(bp + pos, "HIRC", 4) == 0) {
                            uint32_t hircSize = *(uint32_t*)(bp + pos + 4);
                            uint32_t numItems = *(uint32_t*)(bp + pos + 8);
                            size_t ip = pos + 12;
                            int searched = 0;
                            for (uint32_t i = 0; i < numItems && ip + 5 <= pos + 8 + hircSize; i++) {
                                uint8_t itemType = bp[ip];
                                uint32_t itemSize = *(uint32_t*)(bp + ip + 1);
                                if (itemType == 2 && searched++ < 1) {
                                    Log("[MUSICMOD] real Sound item @ HIRC[%u] size=%u:\n", i, itemSize);
                                    auto pp = bp + ip;
                                    for (uint32_t b = 0; b < 5 + itemSize && b < 200; b += 16) {
                                        Log("[MUSICMOD]   +%02X: ", b);
                                        for (uint32_t k = 0; k < 16 && b+k < 5 + itemSize; k++)
                                            Log("%02X ", pp[b+k]);
                                        Log("\n");
                                    }
                                    break;
                                }
                                ip += 5 + itemSize;
                            }
                            if (searched == 0) Log("[MUSICMOD] no Sound (type 2) items in captured HIRC\n");
                            break;
                        }
                        uint32_t cs = *(uint32_t*)(bp + pos + 4);
                        pos += 8 + cs;
                    }
                }

                // SetMedia with the Wwise-native WEM bytes for each custom Sound
                if (g_setMedia) {
                    for (size_t i = 0; i < g_tracks.size(); i++) {
                        if (!g_tracks[i].isReady || g_tracks[i].wemBytes.empty()) {
                            Log("[MUSICMOD]   track %zu not ready (no WEM)\n", i);
                            continue;
                        }
                        AkSourceSettings ss = {};
                        ss.sourceID = 0xAD400000u + (uint32_t)i;
                        ss.pMediaMemory = g_tracks[i].wemBytes.data();
                        ss.uMediaSize = (uint32_t)g_tracks[i].wemBytes.size();
                        int32_t mr = g_setMedia(&ss, 1);
                        Log("[MUSICMOD]   SetMedia(media=%u, WEM size=%u): result=%d\n",
                            ss.sourceID, ss.uMediaSize, mr);
                    }
                }

                // test PostEvent on our custom event IDs
                if (g_origPostEvent) {
                    for (size_t i = 0; i < g_tracks.size(); i++) {
                        uint32_t evId = CUSTOM_EVENT_BASE + (uint32_t)i;
                        uint32_t pid = g_origPostEvent(evId, 1, 0, nullptr, nullptr, 0, nullptr, 0);
                        Log("[MUSICMOD]   PostEvent(custom %u) -> playingId=%u %s\n",
                            evId, pid, pid != 0 ? "RECOGNIZED" : "rejected");
                    }
                }
            }
        }
    }

    // resolve borrowed Wwise event IDs for audio redirection
    // ResourceName is a Decima String at SoundResource + 0xB0
    if (g_getIDFromString) {
        Log("[MUSICMOD] resolving Wwise event IDs from SoundResource names...\n");
        g_borrowedWwiseIds.clear();
        for (size_t i = 0; i < g_tracks.size(); i++) {
            if (!g_tracks[i].pTrackResource) { g_borrowedWwiseIds.push_back(0); continue; }
            auto trackObj = (uint8_t*)g_tracks[i].pTrackResource;
            auto soundRes = *(void**)(trackObj + 0x40);
            if (!soundRes) { g_borrowedWwiseIds.push_back(0); continue; }

            auto strData = *(const char**)((uint8_t*)soundRes + 0xB0);
            if (strData) {
                uint32_t strLen = *(uint32_t*)(strData - 8);
                if (strLen > 0 && strLen < 100) {
                    uint32_t wwiseId = g_getIDFromString(strData);
                    g_borrowedWwiseIds.push_back(wwiseId);
                    Log("[MUSICMOD]   custom[%zu] borrows \"%.*s\" -> WwiseID %u\n",
                        i, (int)strLen, strData, wwiseId);
                } else {
                    g_borrowedWwiseIds.push_back(0);
                }
            } else {
                g_borrowedWwiseIds.push_back(0);
            }
        }
    }
}

// ============================================================
// IStreamingSystem::Events listener
// ============================================================
// vtable must match game's Events layout:
//   [0] OnFinishLoadGroup(const Array<Ref<RTTIRefObject>>&)
//   [1] OnBeforeUnloadGroup(const Array<Ref<RTTIRefObject>>&)
//   [2] OnLoadAssetGroup(const Array<Ref<RTTIRefObject>>&)
// No virtual destructor (game's Events has protected non-virtual dtor)

class MusicEventListener {
public:
    virtual void OnFinishLoadGroup(const RawArray* objects) {
        if (!objects || objects->count == 0) return;

        for (uint32_t i = 0; i < objects->count; i++) {
            void* obj = objects->entries[i];
            if (!obj) continue;

            const char* name = ObjTypeName(obj);
            if (!name) continue;

            if (strcmp(name, "DSMusicPlayerSystemResource") == 0) {
                Log("[MUSICMOD] OnFinishLoadGroup: found DSMusicPlayerSystemResource @ %p\n", obj);
                g_pSysResource = obj;
                InjectCustomTracks(obj);
            }
        }
    }

    virtual void OnBeforeUnloadGroup(const RawArray* objects) {
        if (!objects || objects->count == 0) return;
        for (uint32_t i = 0; i < objects->count; i++) {
            void* obj = objects->entries[i];
            if (!obj) continue;
            const char* name = ObjTypeName(obj);
            if (name && strcmp(name, "DSMusicPlayerSystemResource") == 0) {
                Log("[MUSICMOD] DSMusicPlayerSystemResource unloading, will re-inject next load\n");
                g_injected = false;
            }
        }
    }

    virtual void OnLoadAssetGroup(const RawArray* objects) {
        // unused
    }
};

static MusicEventListener g_listener;

// ============================================================
// StreamingManager hooks
// ============================================================

// IStreamingSystem vtable:
//   [0] destructor
//   [1] unk1
//   [2] unk2
//   [3] AddEventListener(Events*)
//   [4] RemoveEventListener(Events*)
// StreamingManager.mStreamingSystem at offset 0x578

static void RegisterListener(void* streamingManager) {
    auto* pStreamSys = (void**)((uint8_t*)streamingManager + 0x578);
    void* streamSys = *pStreamSys;
    if (!streamSys) {
        Log("[MUSICMOD] mStreamingSystem is null\n");
        return;
    }
    Log("[MUSICMOD] IStreamingSystem @ %p\n", streamSys);

    auto vtable = *(void***)streamSys;
    typedef void (__fastcall* AddListenerFn)(void*, void*);
    auto addListener = (AddListenerFn)vtable[3];
    addListener(streamSys, &g_listener);
    Log("[MUSICMOD] registered event listener\n");
}

// StreamingManager::StreamingManager constructor
// Prologue (28 bytes, all position-independent):
//   48 89 5C 24 08    mov [rsp+8], rbx
//   48 89 6C 24 10    mov [rsp+10h], rbp
//   48 89 74 24 18    mov [rsp+18h], rsi
//   48 89 7C 24 20    mov [rsp+20h], rdi
//   41 56             push r14
//   48 83 EC 20       sub rsp, 20h
//   33 ED             xor ebp, ebp
// (next instr is lea rax,[rip+X] which is RIP-relative, don't touch)

static const char* SIG_STREAMING_CTOR =
    "48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 "
    "48 89 7C 24 20 41 56 48 83 EC 20 33 ED 48 8D 05";
static const int CTOR_STOLEN_BYTES = 28;

static const char* SIG_STREAMING_INSTANCE =
    "48 89 05 ?? ?? ?? ?? E8 ?? ?? ?? ?? 33 D2 "
    "41 B8 F8 0A 00 00 48 8B C8 48 8B D8 E8";

typedef void* (__fastcall* StreamingCtorFn)(void* thisPtr);
static StreamingCtorFn g_origStreamingCtor = nullptr;

static void* __fastcall Hook_StreamingCtor(void* manager) {
    Log("[MUSICMOD] StreamingManager::ctor this=%p\n", manager);
    void* result = g_origStreamingCtor(manager);
    RegisterListener(manager);
    return result;
}

// ============================================================
// Wwise exports
// ============================================================

// All Wwise functions are exported from DS2.exe (the main module).

static const char* WWISE_POSTEVENT_MANGLED =
    "?PostEvent@SoundEngine@AK@@YAII_KIP6AXW4AkCallbackType@@"
    "PEAUAkCallbackInfo@@@ZPEAXIPEAUAkExternalSourceInfo@@I@Z";

static const char* WWISE_GETID_MANGLED =
    "?GetIDFromString@SoundEngine@AK@@YAIPEBD@Z";

static const char* WWISE_POSTEVENT_NAME_MANGLED =
    "?PostEvent@SoundEngine@AK@@YAIPEBD_KIP6AXW4AkCallbackType@@"
    "PEAUAkCallbackInfo@@@ZPEAXIPEAUAkExternalSourceInfo@@I@Z";

static const char* WWISE_STOPPLAYINGID_MANGLED =
    "?StopPlayingID@SoundEngine@AK@@YAXIHW4AkCurveInterpolation@@@Z";

// AKRESULT SeekOnEvent(AkUniqueID, AkGameObjectID, AkTimeMs, bool, AkPlayingID)
static const char* WWISE_SEEKONEVENT_MANGLED =
    "?SeekOnEvent@SoundEngine@AK@@YA?AW4AKRESULT@@I_KH_NI@Z";

// AK::SoundEngine::ExecuteActionOnEvent (ID variant) - likely how music player
// triggers sample play/stop (Y press uses this, not PostEvent)
static const char* WWISE_EXECUTEACTIONONEVENT_ID_MANGLED =
    "?ExecuteActionOnEvent@SoundEngine@AK@@YA?AW4AKRESULT@@IW4AkActionOnEventType@12@_KHW4AkCurveInterpolation@@I@Z";

// Extra APIs that the music player may actually use for track playback.
// Sound_Of_Nature mod hooks these - theory: PostTrigger drives Music Switch Containers
// which is how music samples play (not standard PostEvent).
static const char* WWISE_POSTTRIGGER_ID_MANGLED =
    "?PostTrigger@SoundEngine@AK@@YA?AW4AKRESULT@@I_K@Z";
static const char* WWISE_POSTTRIGGER_A_MANGLED =
    "?PostTrigger@SoundEngine@AK@@YA?AW4AKRESULT@@PEBD_K@Z";
static const char* WWISE_POSTTRIGGER_W_MANGLED =
    "?PostTrigger@SoundEngine@AK@@YA?AW4AKRESULT@@PEB_W_K@Z";
static const char* WWISE_SETSWITCH_ID_MANGLED =
    "?SetSwitch@SoundEngine@AK@@YA?AW4AKRESULT@@II_K@Z";
static const char* WWISE_SETSTATE_ID_MANGLED =
    "?SetState@SoundEngine@AK@@YA?AW4AKRESULT@@II@Z";
// app focus pathway (DS2's state manager sub_1406784f0 fires these when
// the game window gains/loses focus). Alt-tab triggers Suspend, return to
// game triggers WakeupFromSuspend. Hooking both to diagnose custom track
// voice death on tab-back.
static const char* WWISE_SUSPEND_MANGLED =
    "?Suspend@SoundEngine@AK@@YA?AW4AKRESULT@@_N0@Z";
static const char* WWISE_WAKEUP_MANGLED =
    "?WakeupFromSuspend@SoundEngine@AK@@YA?AW4AKRESULT@@I@Z";

// PostEventByIdFn declared earlier (forward decl)
// GetIDFromString declared earlier
typedef void (__cdecl* StopPlayingIDFn)(uint32_t playingId, int32_t transMs, int32_t curve);
typedef uint32_t (__cdecl* PostEventByNameFn)(
    const char* eventName, uint64_t gameObjId, uint32_t flags,
    void* callback, void* cookie,
    uint32_t numExtSrc, void* extSrc, uint32_t playingId);
// g_origPostEvent declared earlier
static PostEventByNameFn g_origPostEventName = nullptr;
// g_getIDFromString declared earlier
static StopPlayingIDFn g_stopPlayingID = nullptr;
static void* g_postEventAddr = nullptr;
static void* g_postEventNameAddr = nullptr;

static volatile int g_pendingCustomTrack = -1; // set when HW breakpoint detects custom track access

// ============================================================
// Hardware breakpoint - detect when music player accesses custom tracks
// ============================================================

// (g_watchAddrs and g_watchCount declared earlier as forward decl)

// Dump registers + shallow stack trace on any unhandled crash we can catch
// first-chance. Registered as the FIRST vectored handler so we get called
// before the game's own SEH. We continue-search after logging so the game's
// normal handler still runs and process exits naturally.
// RATE LIMITED: game/DRM uses SEH-based exception-driven control flow and
// can fire the same AV thousands of times/sec which the game's own handler
// recovers from. Logging every one flooded our log (217K lines) and stalled
// the game via fflush. Log distinct RIPs only, cap at 10 total dumps.
static LONG CALLBACK CrashDumpVEH(PEXCEPTION_POINTERS ep) {
    DWORD code = ep->ExceptionRecord->ExceptionCode;
    // only log hard faults - skip C++ throws, SIGINT, single-step, etc.
    if (code != EXCEPTION_ACCESS_VIOLATION &&
        code != EXCEPTION_STACK_OVERFLOW &&
        code != EXCEPTION_ILLEGAL_INSTRUCTION &&
        code != EXCEPTION_PRIV_INSTRUCTION &&
        code != EXCEPTION_INT_DIVIDE_BY_ZERO) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    // dedupe: only log first occurrence of each unique RIP, cap at 50
    static std::mutex s_crashMtx;
    static uintptr_t s_seenRips[50] = {};
    static int       s_seenCount = 0;
    {
        std::lock_guard<std::mutex> lock(s_crashMtx);
        uintptr_t rip = (uintptr_t)ep->ContextRecord->Rip;
        for (int i = 0; i < s_seenCount; i++) {
            if (s_seenRips[i] == rip) return EXCEPTION_CONTINUE_SEARCH;
        }
        if (s_seenCount >= 50) return EXCEPTION_CONTINUE_SEARCH;
        s_seenRips[s_seenCount++] = rip;
    }
    auto r = ep->ContextRecord;
    Log("[MUSICMOD] *** CRASH code=0x%08X rip=%p rsp=%p\n",
        code, (void*)r->Rip, (void*)r->Rsp);
    Log("[MUSICMOD]   rax=%016llx rcx=%016llx rdx=%016llx rbx=%016llx\n",
        r->Rax, r->Rcx, r->Rdx, r->Rbx);
    Log("[MUSICMOD]   rbp=%016llx rsi=%016llx rdi=%016llx r8=%016llx\n",
        r->Rbp, r->Rsi, r->Rdi, r->R8);
    Log("[MUSICMOD]   r9=%016llx r10=%016llx r11=%016llx r12=%016llx\n",
        r->R9, r->R10, r->R11, r->R12);
    if (code == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2) {
        Log("[MUSICMOD]   AV op=%llu addr=%p\n",
            (unsigned long long)ep->ExceptionRecord->ExceptionInformation[0],
            (void*)ep->ExceptionRecord->ExceptionInformation[1]);
    }
    // stack backtrace
    void* frames[24] = {};
    USHORT n = RtlCaptureStackBackTrace(0, 24, frames, nullptr);
    HMODULE hExeMod = GetModuleHandleA(nullptr);
    uintptr_t gameBase = (uintptr_t)hExeMod, gameSize = 0;
    MODULEINFO mi = {};
    if (GetModuleInformation(GetCurrentProcess(), hExeMod, &mi, sizeof(mi))) {
        gameSize = mi.SizeOfImage;
    }
    // also find the large game module (post-DRM)
    HMODULE hMods[512]; DWORD cb = 0;
    if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cb)) {
        for (int m = 0; m < (int)(cb / sizeof(HMODULE)); m++) {
            MODULEINFO mi2 = {};
            if (GetModuleInformation(GetCurrentProcess(), hMods[m], &mi2, sizeof(mi2))) {
                if (mi2.SizeOfImage > 0x5000000) {
                    gameBase = (uintptr_t)hMods[m];
                    gameSize = mi2.SizeOfImage;
                    break;
                }
            }
        }
    }
    for (USHORT i = 0; i < n; i++) {
        uintptr_t a = (uintptr_t)frames[i];
        if (gameBase && a >= gameBase && a < gameBase + gameSize) {
            Log("[MUSICMOD]   frame[%u] game+0x%llX\n", i,
                (unsigned long long)(a - gameBase));
        } else {
            Log("[MUSICMOD]   frame[%u] %p\n", i, (void*)a);
        }
    }
    // force flush
    if (g_log) fflush(g_log);
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG CALLBACK MusicVEH(PEXCEPTION_POINTERS ep) {
    if (ep->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // check DR6 to see which breakpoint fired
    uintptr_t dr6 = ep->ContextRecord->Dr6;
    int hitBp = -1;
    if (dr6 & 1) hitBp = 0;
    else if (dr6 & 2) hitBp = 1;
    else if (dr6 & 4) hitBp = 2;
    else if (dr6 & 8) hitBp = 3;

    if (hitBp >= 0 && hitBp < g_watchCount) {
        // hit our breakpoint! Track index = hitBp
        g_pendingCustomTrack = hitBp;
        Log("[MUSICMOD] HW BP hit: custom track %d accessed (RIP=%p)\n",
            hitBp, (void*)ep->ContextRecord->Rip);
    }

    // clear DR6 and set RF flag to skip the instruction restart issue
    ep->ContextRecord->Dr6 = 0;
    ep->ContextRecord->EFlags |= 0x10000; // RF flag

    return EXCEPTION_CONTINUE_EXECUTION;
}

static void InstallHwBreakpoints() {
    // set DR0-DR3 on all game threads to watch our custom tracks' TrackId fields
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;

    THREADENTRY32 te;
    te.dwSize = sizeof(te);
    DWORD pid = GetCurrentProcessId();
    DWORD myTid = GetCurrentThreadId();
    int threadsSet = 0;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            if (te.th32ThreadID == myTid) continue;

            HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
                                        FALSE, te.th32ThreadID);
            if (!hThread) continue;

            SuspendThread(hThread);
            CONTEXT ctx = {};
            ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(hThread, &ctx)) {
                // set up to 4 hardware breakpoints on TrackId fields (offset +0x20)
                if (g_watchCount > 0) ctx.Dr0 = g_watchAddrs[0];
                if (g_watchCount > 1) ctx.Dr1 = g_watchAddrs[1];
                if (g_watchCount > 2) ctx.Dr2 = g_watchAddrs[2];
                if (g_watchCount > 3) ctx.Dr3 = g_watchAddrs[3];

                // DR7: enable each BP, condition=read/write (11), length=4 bytes (11)
                uint64_t dr7 = 0;
                for (int i = 0; i < g_watchCount && i < 4; i++) {
                    dr7 |= (uint64_t)1 << (i * 2); // local enable
                    dr7 |= (uint64_t)0x3 << (16 + i * 4); // RW = read/write
                    dr7 |= (uint64_t)0x3 << (18 + i * 4); // LEN = 4 bytes
                }
                ctx.Dr7 = dr7;
                SetThreadContext(hThread, &ctx);
                threadsSet++;
            }
            ResumeThread(hThread);
            CloseHandle(hThread);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    Log("[MUSICMOD] HW breakpoints set on %d threads (%d watch addrs)\n", threadsSet, g_watchCount);
}

// ============================================================
// Wwise native audio - bank building + loading
// ============================================================

// Wwise bank loading exports - the game uses one of these
static const char* WWISE_LOADBANKMEMCOPY_MANGLED =
    "?LoadBankMemoryCopy@SoundEngine@AK@@YA?AW4AKRESULT@@PEBXIAEAI@Z";
static const char* WWISE_SETMEDIA_MANGLED =
    "?SetMedia@SoundEngine@AK@@YA?AW4AKRESULT@@PEAUAkSourceSettings@@I@Z";

// AkSourceSettings, SetMediaFn2, g_setMedia declared earlier
static const char* WWISE_LOADBANKMEMVIEW_MANGLED =
    "?LoadBankMemoryView@SoundEngine@AK@@YA?AW4AKRESULT@@PEBXIAEAI@Z";
static const char* WWISE_LOADBANK_ID_MANGLED =
    "?LoadBank@SoundEngine@AK@@YA?AW4AKRESULT@@II@Z";

// LoadBankMemoryFn typedef'd earlier (forward decl)
typedef int32_t (__cdecl* LoadBankByIdFn)(uint32_t bankId, uint32_t memPoolId);
typedef int32_t (__cdecl* SetMediaFn)(void* sourceSettings, uint32_t numSources);

// g_loadBankMemoryCopy declared earlier (forward decl)
static LoadBankMemoryFn g_origLoadBankMemoryCopy = nullptr;
static LoadBankMemoryFn g_loadBankMemoryView = nullptr;
static LoadBankMemoryFn g_origLoadBankMemoryView = nullptr;
static LoadBankByIdFn g_loadBankById = nullptr;
static LoadBankByIdFn g_origLoadBankById = nullptr;
static PostEventByIdFn g_postEventDirect = nullptr;

// captured template bank globals declared earlier (forward decl)

static void CaptureBank(const void* bankData, uint32_t bankSize, const char* source) {
    g_capturedBankCount++;

    // dump bank info for debugging - look for chunks
    bool hasHIRC = false;
    bool hasDIDX = false;
    bool hasDATA = false;
    if (bankSize >= 16 && memcmp(bankData, "BKHD", 4) == 0) {
        // walk chunks looking for HIRC/DIDX/DATA
        auto p = (const uint8_t*)bankData;
        size_t pos = 0;
        while (pos + 8 <= bankSize) {
            const char* tag = (const char*)(p + pos);
            uint32_t chunkSize = *(uint32_t*)(p + pos + 4);
            if (chunkSize > bankSize) break;
            if (memcmp(tag, "HIRC", 4) == 0) hasHIRC = true;
            else if (memcmp(tag, "DIDX", 4) == 0) hasDIDX = true;
            else if (memcmp(tag, "DATA", 4) == 0) hasDATA = true;
            pos += 8 + chunkSize;
        }
    }

    // passive scan: any HIRC bank can yield missing Action/Event templates.
    // This way even pure-audio banks (Sound only) and pure-event banks (no DATA)
    // both contribute their first-of-type to the template pool.
    // Always scan HIRC banks: Sound/Action/Event stop once captured (first-of-type),
    // but music-container templates keep looking for LARGER items (the first music
    // item in the music-player bank is often an empty stub; the real tracks with
    // AkBankSourceData + AkTrackSrcInfo come later in the HIRC).
    if (hasHIRC) {
        auto bp = (const uint8_t*)bankData;
        size_t pos = 0;
        while (pos + 8 <= bankSize) {
            if (memcmp(bp + pos, "HIRC", 4) == 0) {
                uint32_t hircSize = *(uint32_t*)(bp + pos + 4);
                uint32_t numItems = *(uint32_t*)(bp + pos + 8);
                size_t ip = pos + 12;
                for (uint32_t i = 0; i < numItems && ip + 5 <= pos + 8 + hircSize; i++) {
                    uint8_t itemType = bp[ip];
                    uint32_t itemSize = *(uint32_t*)(bp + ip + 1);
                    if (itemType == 2 && g_realSoundSize == 0 && itemSize > 0 && itemSize <= 256) {
                        memcpy(g_realSoundBody, bp + ip + 5, itemSize);
                        g_realSoundSize = itemSize;
                        Log("[MUSICMOD] passive-captured Sound template (size=%u) from bank #%u\n",
                            itemSize, g_capturedBankCount);
                    } else if (itemType == 3 && g_realActionSize == 0 && itemSize > 0 && itemSize <= 256) {
                        memcpy(g_realActionBody, bp + ip + 5, itemSize);
                        g_realActionSize = itemSize;
                        Log("[MUSICMOD] passive-captured Action template (size=%u) from bank #%u\n",
                            itemSize, g_capturedBankCount);
                    } else if (itemType == 4 && g_realEventSize == 0 && itemSize > 0 && itemSize <= 64) {
                        memcpy(g_realEventBody, bp + ip + 5, itemSize);
                        g_realEventSize = itemSize;
                        Log("[MUSICMOD] passive-captured Event template (size=%u) from bank #%u\n",
                            itemSize, g_capturedBankCount);
                    } else if (itemType == 0x0B && itemSize >= 150 && itemSize <= 400 &&
                               g_realMusicTrackSize == 0 &&
                               itemSize <= sizeof(g_realMusicTrackBody)) {
                        // target the SIMPLEST functional MusicTrack: 150-400 bytes is the
                        // typical range for 1-source / 1-playlist / 1-subtrack. Smaller =
                        // empty stub, larger = multi-source complex track.
                        memcpy(g_realMusicTrackBody, bp + ip + 5, itemSize);
                        g_realMusicTrackSize = itemSize;
                        g_realMusicTrackSourceBankId = g_capturedBankCount;
                        uint32_t itemId = *(uint32_t*)(bp + ip + 5);
                        Log("[MUSICMOD] captured CAkMusicTrack template (size=%u id=%u) from bank #%u\n",
                            itemSize, itemId, g_capturedBankCount);
                        for (uint32_t b = 0; b < itemSize; b += 16) {
                            char line[128] = "";
                            for (uint32_t k = 0; k < 16 && b+k < itemSize; k++) {
                                char tmp[6]; snprintf(tmp, sizeof(tmp), "%02X ", g_realMusicTrackBody[b+k]);
                                strncat_s(line, tmp, _TRUNCATE);
                            }
                            Log("[MUSICMOD]   MT +%03X: %s\n", b, line);
                        }
                    } else if (itemType == 0x0A && itemSize >= 80 && itemSize <= 200 &&
                               g_realMusicSegmentSize == 0 &&
                               itemSize <= sizeof(g_realMusicSegmentBody)) {
                        memcpy(g_realMusicSegmentBody, bp + ip + 5, itemSize);
                        g_realMusicSegmentSize = itemSize;
                        g_realMusicSegmentSourceBankId = g_capturedBankCount;
                        uint32_t itemId = *(uint32_t*)(bp + ip + 5);
                        Log("[MUSICMOD] captured CAkMusicSegment template (size=%u id=%u) from bank #%u\n",
                            itemSize, itemId, g_capturedBankCount);
                        for (uint32_t b = 0; b < itemSize; b += 16) {
                            char line[128] = "";
                            for (uint32_t k = 0; k < 16 && b+k < itemSize; k++) {
                                char tmp[6]; snprintf(tmp, sizeof(tmp), "%02X ", g_realMusicSegmentBody[b+k]);
                                strncat_s(line, tmp, _TRUNCATE);
                            }
                            Log("[MUSICMOD]   MS +%03X: %s\n", b, line);
                        }
                    } else if (itemType == 0x0D && itemSize >= 150 && itemSize <= 700 &&
                               g_realMusicRanSeqSize == 0 &&
                               itemSize <= sizeof(g_realMusicRanSeqBody)) {
                        memcpy(g_realMusicRanSeqBody, bp + ip + 5, itemSize);
                        g_realMusicRanSeqSize = itemSize;
                        g_realMusicRanSeqSourceBankId = g_capturedBankCount;
                        uint32_t itemId = *(uint32_t*)(bp + ip + 5);
                        Log("[MUSICMOD] captured CAkMusicRanSeqCntr template (size=%u id=%u) from bank #%u\n",
                            itemSize, itemId, g_capturedBankCount);
                        for (uint32_t b = 0; b < itemSize; b += 16) {
                            char line[128] = "";
                            for (uint32_t k = 0; k < 16 && b+k < itemSize; k++) {
                                char tmp[6]; snprintf(tmp, sizeof(tmp), "%02X ", g_realMusicRanSeqBody[b+k]);
                                strncat_s(line, tmp, _TRUNCATE);
                            }
                            Log("[MUSICMOD]   MR +%03X: %s\n", b, line);
                        }
                    }
                    ip += 5 + itemSize;
                }
                break;
            }
            uint32_t cs = *(uint32_t*)(bp + pos + 4);
            pos += 8 + cs;
        }
    }

    // Prefer the music-player bank (contains event 3056202008 = M61 full) for
    // g_audioBank, replacing any earlier capture that didn't. The music player
    // bank is ~14MB so we need a higher size cap than the 2MB we started with.
    bool candidateHasM61 = false;
    if (hasHIRC && bankSize >= 64 && bankSize < 0x2000000) {
        uint32_t sz = 0;
        if (FindHircItemById((const uint8_t*)bankData, bankSize, 4, 3056202008u, &sz)) {
            candidateHasM61 = true;
        }
    }
    bool wantReplace = candidateHasM61 && (!g_audioBank || !FindHircItemById(g_audioBank, g_audioBankSize, 4, 3056202008u, nullptr));
    if (wantReplace && g_audioBank) {
        Log("[MUSICMOD] replacing g_audioBank (%u bytes, no M61) with music-player bank (%u bytes)\n",
            g_audioBankSize, bankSize);
        HeapFree(GetProcessHeap(), 0, g_audioBank);
        g_audioBank = nullptr;
        g_audioBankSize = 0;
    }
    // also capture a SECOND bank: any audio bank (HIRC+DIDX+DATA) - prefer the
    // music player bank (M61-containing), but fall back to any if we can't find it yet.
    if (!g_audioBank && hasHIRC && hasDATA && bankSize >= 64 && bankSize < 0x2000000 &&
        (candidateHasM61 || bankSize < 0x200000)) {
        g_audioBank = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, bankSize);
        if (g_audioBank) {
            memcpy(g_audioBank, bankData, bankSize);
            g_audioBankSize = bankSize;
            Log("[MUSICMOD] captured audio bank #%u: %u bytes (HIRC+DIDX+DATA)\n",
                g_capturedBankCount, bankSize);

            // walk DIDX (data index) to find the first WEM and extract it
            // DIDX entries are 12 bytes each: { sourceID(4), offset(4), size(4) }
            // entries reference offsets in the DATA chunk
            auto dp = (const uint8_t*)bankData;
            size_t dpos = 0;
            uint32_t didxOffset = 0, didxSize = 0;
            uint32_t dataOffset = 0;
            while (dpos + 8 <= bankSize) {
                if (memcmp(dp + dpos, "DIDX", 4) == 0) {
                    didxSize = *(uint32_t*)(dp + dpos + 4);
                    didxOffset = (uint32_t)(dpos + 8);
                } else if (memcmp(dp + dpos, "DATA", 4) == 0) {
                    dataOffset = (uint32_t)(dpos + 8);
                }
                uint32_t cs = *(uint32_t*)(dp + dpos + 4);
                dpos += 8 + cs;
            }
            if (didxSize >= 12 && dataOffset > 0) {
                // first DIDX entry
                uint32_t firstSourceID = *(uint32_t*)(dp + didxOffset + 0);
                uint32_t firstWemOffset = *(uint32_t*)(dp + didxOffset + 4);
                uint32_t firstWemSize = *(uint32_t*)(dp + didxOffset + 8);
                Log("[MUSICMOD]   DIDX[0]: sourceID=%u offset=%u size=%u\n",
                    firstSourceID, firstWemOffset, firstWemSize);
                if (firstWemSize > 0 && firstWemSize < 0x100000 &&
                    dataOffset + firstWemOffset + firstWemSize <= bankSize) {
                    g_realWem = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, firstWemSize);
                    if (g_realWem) {
                        memcpy(g_realWem, dp + dataOffset + firstWemOffset, firstWemSize);
                        g_realWemSize = firstWemSize;
                        g_realWemSourceId = firstSourceID;
                        Log("[MUSICMOD]   extracted WEM: %u bytes for sourceID %u\n",
                            firstWemSize, firstSourceID);
                    }
                }
            }

            // walk HIRC for Sound items
            auto bp = g_audioBank;
            size_t pos = 0;
            while (pos + 8 <= g_audioBankSize) {
                if (memcmp(bp + pos, "HIRC", 4) == 0) {
                    uint32_t hircSize = *(uint32_t*)(bp + pos + 4);
                    uint32_t numItems = *(uint32_t*)(bp + pos + 8);
                    size_t ip = pos + 12;
                    int dumped = 0;
                    for (uint32_t i = 0; i < numItems && ip + 5 <= pos + 8 + hircSize; i++) {
                        uint8_t itemType = bp[ip];
                        uint32_t itemSize = *(uint32_t*)(bp + ip + 1);
                        // also log Bus items (type 7) and AuxBus (14) for reference
                        if (itemType == 7 || itemType == 14) {
                            Log("[MUSICMOD] BUS item @ HIRC[%u] type=%u size=%u id=%u\n",
                                i, itemType, itemSize, *(uint32_t*)(bp + ip + 5));
                        }
                        // log Sound items with their codec
                        if (itemType == 2 && itemSize >= 13) {
                            uint32_t codec = *(uint32_t*)(bp + ip + 5 + 4); // body+4 is pluginID
                            uint8_t streamType = bp[ip + 5 + 8];
                            Log("[MUSICMOD] Sound HIRC[%u] size=%u codec=0x%08X stream=%u\n",
                                i, itemSize, codec, streamType);
                        }
                        if (itemType == 2 || itemType == 3 || itemType == 4) {
                            const char* tname = itemType == 2 ? "Sound" : itemType == 3 ? "Action" : "Event";
                            bool firstOfType =
                                (itemType == 2 && g_realSoundSize == 0) ||
                                (itemType == 3 && g_realActionSize == 0) ||
                                (itemType == 4 && g_realEventSize == 0);
                            if (firstOfType && dumped < 6) {
                                Log("[MUSICMOD] real %s item @ HIRC[%u] size=%u:\n", tname, i, itemSize);
                                for (uint32_t b = 0; b < 5 + itemSize && b < 200; b += 16) {
                                    Log("[MUSICMOD]   +%02X: ", b);
                                    for (uint32_t k = 0; k < 16 && b+k < 5 + itemSize; k++)
                                        Log("%02X ", (bp + ip)[b+k]);
                                    Log("\n");
                                }
                                dumped++;
                            }
                            // save body bytes for use as template
                            if (itemType == 2 && g_realSoundSize == 0 && itemSize <= 256) {
                                memcpy(g_realSoundBody, bp + ip + 5, itemSize);
                                g_realSoundSize = itemSize;
                            } else if (itemType == 3 && g_realActionSize == 0 && itemSize <= 256) {
                                memcpy(g_realActionBody, bp + ip + 5, itemSize);
                                g_realActionSize = itemSize;
                            } else if (itemType == 4 && g_realEventSize == 0 && itemSize <= 64) {
                                memcpy(g_realEventBody, bp + ip + 5, itemSize);
                                g_realEventSize = itemSize;
                            }
                        }
                        ip += 5 + itemSize;
                    }
                    break;
                }
                uint32_t cs = *(uint32_t*)(bp + pos + 4);
                pos += 8 + cs;
            }
        }
    }

    // capture the FIRST small bank with HIRC (sound hierarchy template)
    bool shouldCapture = !g_capturedBank && bankSize >= 64 && bankSize < 0x100000 && hasHIRC;
    if (shouldCapture) {
        g_capturedBank = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, bankSize);
        if (g_capturedBank) {
            memcpy(g_capturedBank, bankData, bankSize);
            g_capturedBankSize = bankSize;
            Log("[MUSICMOD] captured template bank #%u via %s: %u bytes\n",
                g_capturedBankCount, source, bankSize);
            Log("[MUSICMOD]   chunks: HIRC=%d DIDX=%d DATA=%d\n", hasHIRC, hasDIDX, hasDATA);

            // dump entire bank to disk for inspection
            char bankPath[MAX_PATH];
            snprintf(bankPath, MAX_PATH, "%s\\sd_music\\.cache\\template.bnk", g_gameDir);
            FILE* bf = fopen(bankPath, "wb");
            if (bf) {
                fwrite(bankData, 1, bankSize, bf);
                fclose(bf);
                Log("[MUSICMOD]   dumped to %s\n", bankPath);
            }

            uint32_t bkhdSize = *(uint32_t*)((uint8_t*)bankData + 4);
            Log("[MUSICMOD]   BKHD body (%u bytes)\n", bkhdSize);

            // walk and log all chunks
            auto p = (const uint8_t*)bankData;
            size_t pos = 0;
            while (pos + 8 <= bankSize) {
                char tag[5] = {};
                memcpy(tag, p + pos, 4);
                uint32_t cs = *(uint32_t*)(p + pos + 4);
                if (cs > bankSize - pos - 8) break;
                Log("[MUSICMOD]   chunk \"%s\" @ %zu: %u bytes\n", tag, pos, cs);

                // for HIRC, log the first few items
                if (memcmp(tag, "HIRC", 4) == 0 && cs >= 4) {
                    uint32_t numItems = *(uint32_t*)(p + pos + 8);
                    Log("[MUSICMOD]     HIRC: %u items\n", numItems);

                    // dump first 3 items
                    size_t ip = pos + 12;
                    for (uint32_t i = 0; i < numItems && i < 3 && ip + 5 <= pos + 8 + cs; i++) {
                        uint8_t itemType = p[ip];
                        uint32_t itemSize = *(uint32_t*)(p + ip + 1);
                        uint32_t itemId = *(uint32_t*)(p + ip + 5);
                        Log("[MUSICMOD]     item[%u]: type=%u size=%u id=%u\n",
                            i, itemType, itemSize, itemId);
                        ip += 5 + itemSize;
                    }
                }
                pos += 8 + cs;
            }
        }
    } else if (g_capturedBankCount <= 100) {
        // log all banks with their structure info
        uint32_t version = 0, bankId = 0, bkhdSize = 0;
        if (bankSize >= 16) {
            bkhdSize = *(uint32_t*)((uint8_t*)bankData + 4);
            version = *(uint32_t*)((uint8_t*)bankData + 8);
            bankId = *(uint32_t*)((uint8_t*)bankData + 12);
        }
        Log("[MUSICMOD] %s #%u: %u bytes BKHD=%u v=%u bankId=%u%s%s%s\n",
            source, g_capturedBankCount, bankSize, bkhdSize, version, bankId,
            hasHIRC ? " HIRC" : "", hasDIDX ? " DIDX" : "", hasDATA ? " DATA" : "");
    }
}

static int32_t __cdecl Hook_LoadBankMemoryCopy(const void* bankData, uint32_t bankSize, uint32_t* outBankId) {
    CaptureBank(bankData, bankSize, "LoadBankMemoryCopy");
    return g_origLoadBankMemoryCopy(bankData, bankSize, outBankId);
}

static int32_t __cdecl Hook_LoadBankMemoryView(const void* bankData, uint32_t bankSize, uint32_t* outBankId) {
    CaptureBank(bankData, bankSize, "LoadBankMemoryView");
    return g_origLoadBankMemoryView(bankData, bankSize, outBankId);
}

static int32_t __cdecl Hook_LoadBankById(uint32_t bankId, uint32_t memPoolId) {
    if (g_capturedBankCount < 30) {
        Log("[MUSICMOD] LoadBank by ID: %u (pool=%u)\n", bankId, memPoolId);
    }
    g_capturedBankCount++;
    return g_origLoadBankById(bankId, memPoolId);
}

// Wwise AKRESULT codes
#define AK_Success 1
#define AK_Fail 0

// custom bank/event IDs - unique high values
// CUSTOM_EVENT_BASE declared earlier
#define CUSTOM_BANK_ID     0xAD000001u
#define CUSTOM_SOUND_BASE  0xAD200000u
#define CUSTOM_ACTION_BASE 0xAD300000u
#define CUSTOM_MEDIA_BASE  0xAD400000u

// Build an "extended" bank by copying the captured audio bank
// and APPENDING custom Sound/Action/Event items to its HIRC chunk.
// This way our items inherit the bank's working bus routing.
// Locate an HIRC item of a specific type + ulID inside a bank buffer.
// Returns pointer to the item's BODY (after the 5-byte type+size header) and
// its body size. Returns nullptr if not found.
static const uint8_t* FindHircItemById(const uint8_t* bank, uint32_t bankSize,
                                        uint8_t wantType, uint32_t wantUlId,
                                        uint32_t* outBodySize) {
    if (!bank || bankSize < 12) return nullptr;
    size_t pos = 0;
    while (pos + 8 <= bankSize) {
        if (memcmp(bank + pos, "HIRC", 4) == 0) {
            uint32_t hircSize = *(uint32_t*)(bank + pos + 4);
            uint32_t numItems = *(uint32_t*)(bank + pos + 8);
            size_t ip = pos + 12;
            size_t end = pos + 8 + hircSize;
            for (uint32_t i = 0; i < numItems && ip + 5 <= end; i++) {
                uint8_t type = bank[ip];
                uint32_t size = *(uint32_t*)(bank + ip + 1);
                if (ip + 5 + size > end) break;
                if (type == wantType && size >= 4) {
                    uint32_t itemId = *(uint32_t*)(bank + ip + 5);
                    if (itemId == wantUlId) {
                        if (outBodySize) *outBodySize = size;
                        return bank + ip + 5;
                    }
                }
                ip += 5 + size;
            }
            return nullptr;
        }
        uint32_t cs = *(uint32_t*)(bank + pos + 4);
        pos += 8 + cs;
    }
    return nullptr;
}

// Build a MINIMAL music bank containing only our new HIRC items (no copy of
// bank #15's contents). This avoids the duplicate-ID issue where Wwise's music
// engine appears to skip music-node registration when loading a duplicate bank.
// The source WEM is resolved from the separately-loaded bank #15.
static uint8_t* BuildMinimalMusicBank(int numTracks, uint32_t* outSize, uint32_t newBankId);

// Replace every 4-byte little-endian occurrence of `oldId` with `newId` in
// buf[0..size). Used to surgically rewrite references inside copied HIRC item
// bodies (ulID, DirectParentID, child arrays, etc.). Safe because Wwise IDs
// are 32-bit unique values so false matches are astronomically unlikely.
static uint32_t ReplaceU32(uint8_t* buf, uint32_t size, uint32_t oldId, uint32_t newId) {
    uint32_t hits = 0;
    for (uint32_t i = 0; i + 4 <= size; i++) {
        if (*(uint32_t*)(buf + i) == oldId) {
            *(uint32_t*)(buf + i) = newId;
            hits++;
        }
    }
    return hits;
}

static uint8_t* BuildExtendedBank(int numTracks, uint32_t* outSize, uint32_t newBankId) {
    if (!g_audioBank || g_audioBankSize == 0) return nullptr;

    // Prefer the music-engine chain from M61 if we can find it in g_audioBank.
    // Falls back to the old plain Sound/Action/Event append if any item is
    // missing (we'd lose audio but at least wouldn't crash the bank).
    uint32_t m61EventSz=0, m61ActSz=0, m61MRSCSz=0, m61MSegSz=0, m61MTrkSz=0;
    auto m61Event = FindHircItemById(g_audioBank, g_audioBankSize, 4,    M61_EVENT_ID,       &m61EventSz);
    auto m61Act   = FindHircItemById(g_audioBank, g_audioBankSize, 3,    M61_ACTION_ID,      &m61ActSz);
    auto m61MRSC  = FindHircItemById(g_audioBank, g_audioBankSize, 0x0D, M61_MUSICRSC_ID,    &m61MRSCSz);
    auto m61MSeg  = FindHircItemById(g_audioBank, g_audioBankSize, 0x0A, M61_MUSICSEG_ID,    &m61MSegSz);
    auto m61MTrk  = FindHircItemById(g_audioBank, g_audioBankSize, 0x0B, M61_MUSICTRACK_ID,  &m61MTrkSz);
    bool useMusicChain = (m61Event && m61Act && m61MRSC && m61MSeg && m61MTrk);
    Log("[MUSICMOD] BuildExtendedBank: useMusicChain=%d (E=%u A=%u MR=%u MS=%u MT=%u)\n",
        useMusicChain?1:0, m61EventSz, m61ActSz, m61MRSCSz, m61MSegSz, m61MTrkSz);

    // find HIRC chunk in original bank
    auto src = g_audioBank;
    size_t pos = 0;
    size_t hircChunkOffset = 0;
    uint32_t hircChunkSize = 0;
    while (pos + 8 <= g_audioBankSize) {
        if (memcmp(src + pos, "HIRC", 4) == 0) {
            hircChunkOffset = pos;
            hircChunkSize = *(uint32_t*)(src + pos + 4);
            break;
        }
        uint32_t cs = *(uint32_t*)(src + pos + 4);
        pos += 8 + cs;
    }
    if (!hircChunkOffset) return nullptr;

    // calculate space for new items
    uint32_t newItemsSize = 0;
    uint32_t newItemsPerTrack = 0;
    if (useMusicChain) {
        // 5 items per track: MusicTrack + MusicSegment + MusicRanSeqCntr + Action + Event
        // PLUS one diagnostic "piggyback" Event (9-byte body) that targets OG action
        // so we can isolate: our cloned music is broken vs our bank-load doesn't register NEW items
        newItemsSize = numTracks * (5*5 + m61MTrkSz + m61MSegSz + m61MRSCSz + m61ActSz + m61EventSz
                                     + 5 + 9);
        newItemsPerTrack = 6;
    } else {
        if (g_realSoundSize > 0) newItemsSize += numTracks * (5 + g_realSoundSize);
        if (g_realActionSize > 0) newItemsSize += numTracks * (5 + g_realActionSize);
        newItemsSize += numTracks * (5 + 9);
        newItemsPerTrack = 3;
    }

    uint32_t newBankSize = (uint32_t)g_audioBankSize + newItemsSize;
    auto bank = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, newBankSize);
    if (!bank) return nullptr;

    size_t hircNumItemsOffset = hircChunkOffset + 8;
    size_t hircItemsEnd = hircChunkOffset + 8 + hircChunkSize;

    memcpy(bank, src, hircItemsEnd);
    if (hircItemsEnd < g_audioBankSize) {
        memcpy(bank + hircItemsEnd + newItemsSize, src + hircItemsEnd, g_audioBankSize - hircItemsEnd);
    }

    uint32_t origNumItems = *(uint32_t*)(bank + hircNumItemsOffset);
    *(uint32_t*)(bank + hircNumItemsOffset) = origNumItems + (uint32_t)numTracks * newItemsPerTrack;
    *(uint32_t*)(bank + hircChunkOffset + 4) = hircChunkSize + newItemsSize;
    *(uint32_t*)(bank + 8 + 4) = newBankId;

    uint8_t* p = bank + hircItemsEnd;
    auto w8  = [&](uint8_t v) { *p++ = v; };
    auto w32 = [&](uint32_t v){ *(uint32_t*)p = v; p += 4; };

    // Helper: append a single HIRC item by copying `bodySize` bytes from
    // `bodyTemplate`, writing the type+size header first.
    auto appendItem = [&](uint8_t type, const uint8_t* bodyTemplate, uint32_t bodySize,
                          uint8_t** outBodyStart) {
        w8(type);
        w32(bodySize);
        uint8_t* bodyStart = p;
        memcpy(bodyStart, bodyTemplate, bodySize);
        p += bodySize;
        if (outBodyStart) *outBodyStart = bodyStart;
    };

    for (int i = 0; i < numTracks; i++) {
        uint32_t newEventId     = CUSTOM_EVENT_BASE      + i;
        uint32_t newActionId    = CUSTOM_ACTION_BASE     + i;
        uint32_t newMRSCId      = CUSTOM_MUSICRSC_BASE   + i;
        uint32_t newMSegId      = CUSTOM_MUSICSEG_BASE   + i;
        uint32_t newMTrackId    = CUSTOM_MUSICTRACK_BASE + i;

        if (useMusicChain) {
            // 1. CAkMusicTrack (type 0x0B)
            uint8_t* mtBody = nullptr;
            appendItem(0x0B, m61MTrk, m61MTrkSz, &mtBody);
            ReplaceU32(mtBody, m61MTrkSz, M61_MUSICTRACK_ID, newMTrackId);
            // DirectParentID = parent MusicSegment
            ReplaceU32(mtBody, m61MTrkSz, M61_MUSICSEG_ID,   newMSegId);
            // Iteration 1: KEEP sourceID 676622012 so audio plays M61 through our own chain

            // 2. CAkMusicSegment (type 0x0A)
            uint8_t* msBody = nullptr;
            appendItem(0x0A, m61MSeg, m61MSegSz, &msBody);
            ReplaceU32(msBody, m61MSegSz, M61_MUSICSEG_ID,   newMSegId);
            ReplaceU32(msBody, m61MSegSz, M61_MUSICRSC_ID,   newMRSCId);
            ReplaceU32(msBody, m61MSegSz, M61_MUSICTRACK_ID, newMTrackId);

            // 3. CAkMusicRanSeqCntr (type 0x0D)
            uint8_t* mrBody = nullptr;
            appendItem(0x0D, m61MRSC, m61MRSCSz, &mrBody);
            ReplaceU32(mrBody, m61MRSCSz, M61_MUSICRSC_ID,   newMRSCId);
            ReplaceU32(mrBody, m61MRSCSz, M61_MUSICSEG_ID,   newMSegId);
            // OG MRSC's DirectParentID = 629350378 (0x25831FEA) lives in a bank
            // we don't control. The music engine may reject our MRSC if it can't
            // resolve the parent. Null it out so our MRSC stands as a root music
            // node. DirectParentID sits at body +0x0D in NodeBaseParams layout.
            ReplaceU32(mrBody, m61MRSCSz, 629350378u, 0u);

            // 4. CAkActionPlay (type 3)
            uint8_t* aBody = nullptr;
            appendItem(3, m61Act, m61ActSz, &aBody);
            ReplaceU32(aBody, m61ActSz, M61_ACTION_ID,     newActionId);
            ReplaceU32(aBody, m61ActSz, M61_MUSICRSC_ID,   newMRSCId);
            // ActionPlay has ulFileID = bankID-of-target (727071332 = bank #15)
            // at +0x0E. Set to 0 so Wwise resolves target from ANY loaded bank,
            // which will find our newMRSCId in OUR extended bank.
            ReplaceU32(aBody, m61ActSz, 727071332u,        0u);

            // 5. CAkEvent (type 4)
            uint8_t* eBody = nullptr;
            appendItem(4, m61Event, m61EventSz, &eBody);
            ReplaceU32(eBody, m61EventSz, M61_EVENT_ID,   newEventId);
            ReplaceU32(eBody, m61EventSz, M61_ACTION_ID,  newActionId);

            // DIAGNOSTIC "piggyback" Event: a new Event in our bank that references
            // the OG M61 trial Action directly (not our cloned Action). If posting
            // this Event plays OG audio, we've proven bank-loading DOES register our
            // new events. If silent too, our extended bank's NEW items never get
            // registered at all and we need a different bank strategy.
            uint32_t piggybackEventId = CUSTOM_EVENT_BASE + 0x100u + (uint32_t)i;
            w8(4);
            w32(9);
            w32(piggybackEventId);
            w8(1);
            w32(M61_ACTION_ID);
        } else {
            // fallback: plain Sound/Action/Event (won't produce music-engine audio
            // but keeps the bank valid)
            uint32_t soundId  = CUSTOM_SOUND_BASE + i;
            uint32_t mediaId  = CUSTOM_MEDIA_BASE + i;
            if (g_realSoundSize > 0) {
                w8(2);
                w32(g_realSoundSize);
                memcpy(p, g_realSoundBody, g_realSoundSize);
                *(uint32_t*)(p + 0) = soundId;
                *(uint32_t*)(p + 0x04) = 0x00010001u;
                *(uint32_t*)(p + 0x09) = mediaId;
                p[0x0D] = 0;
                p += g_realSoundSize;
            }
            if (g_realActionSize > 0) {
                w8(3);
                w32(g_realActionSize);
                memcpy(p, g_realActionBody, g_realActionSize);
                *(uint32_t*)(p + 0) = newActionId;
                *(uint32_t*)(p + 0x06) = soundId;
                p += g_realActionSize;
            }
            w8(4);
            w32(9);
            w32(newEventId);
            w8(1);
            w32(newActionId);
        }
    }

    *outSize = newBankSize;
    Log("[MUSICMOD] BuildExtendedBank: orig=%u new=%u items_added=%u (chain=%s)\n",
        (uint32_t)g_audioBankSize, newBankSize,
        (uint32_t)numTracks * newItemsPerTrack, useMusicChain ? "music" : "sound");

    // dump the extended bank to disk for offline wwiser analysis when we have
    // the music chain; only dump once to avoid filling disk
    static bool s_bankDumped = false;
    if (useMusicChain && !s_bankDumped) {
        char path[MAX_PATH];
        snprintf(path, MAX_PATH, "%s\\sd_music\\.cache\\extended_music.bnk", g_gameDir);
        FILE* f = fopen(path, "wb");
        if (f) {
            fwrite(bank, 1, newBankSize, f);
            fclose(f);
            Log("[MUSICMOD] dumped extended bank to %s (%u bytes)\n", path, newBankSize);
            s_bankDumped = true;
        }
    }
    return bank;
}

// Build a STANDALONE bank with only our 6 new HIRC items per track. No copy
// of bank #15's contents - just BKHD (cloned from bank #15 for format compat)
// + HIRC with our items. The source WEM 378574806 is resolved from bank #15
// which is loaded separately by the game.
static uint8_t* BuildMinimalMusicBank(int numTracks, uint32_t* outSize, uint32_t newBankId) {
    if (!g_audioBank || g_audioBankSize == 0) return nullptr;

    uint32_t m61EventSz=0, m61ActSz=0, m61MRSCSz=0, m61MSegSz=0, m61MTrkSz=0;
    auto m61Event = FindHircItemById(g_audioBank, g_audioBankSize, 4,    M61_EVENT_ID,       &m61EventSz);
    auto m61Act   = FindHircItemById(g_audioBank, g_audioBankSize, 3,    M61_ACTION_ID,      &m61ActSz);
    auto m61MRSC  = FindHircItemById(g_audioBank, g_audioBankSize, 0x0D, M61_MUSICRSC_ID,    &m61MRSCSz);
    auto m61MSeg  = FindHircItemById(g_audioBank, g_audioBankSize, 0x0A, M61_MUSICSEG_ID,    &m61MSegSz);
    auto m61MTrk  = FindHircItemById(g_audioBank, g_audioBankSize, 0x0B, M61_MUSICTRACK_ID,  &m61MTrkSz);
    if (!m61Event || !m61Act || !m61MRSC || !m61MSeg || !m61MTrk) {
        Log("[MUSICMOD] BuildMinimalMusicBank: missing M61 templates, bailing\n");
        return nullptr;
    }

    // locate BKHD in source bank to clone format-compatible header
    size_t bkhdOff = 0;
    uint32_t bkhdBodySize = 0;
    {
        size_t pos = 0;
        while (pos + 8 <= g_audioBankSize) {
            if (memcmp(g_audioBank + pos, "BKHD", 4) == 0) {
                bkhdOff = pos;
                bkhdBodySize = *(uint32_t*)(g_audioBank + pos + 4);
                break;
            }
            uint32_t cs = *(uint32_t*)(g_audioBank + pos + 4);
            pos += 8 + cs;
        }
    }
    if (bkhdBodySize == 0) {
        Log("[MUSICMOD] BuildMinimalMusicBank: no BKHD in source bank\n");
        return nullptr;
    }

    uint32_t bkhdTotalSize = 8 + bkhdBodySize;
    uint32_t itemsPerTrack = 6;  // 5 music chain + 1 piggyback
    uint32_t hircBodySize = 4;   // numItems u32
    hircBodySize += (uint32_t)numTracks * (5*5 + m61MTrkSz + m61MSegSz + m61MRSCSz + m61ActSz + m61EventSz + 5 + 9);
    uint32_t hircTotalSize = 8 + hircBodySize;
    uint32_t bankSize = bkhdTotalSize + hircTotalSize;

    auto bank = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, bankSize);
    if (!bank) return nullptr;

    memcpy(bank, g_audioBank + bkhdOff, bkhdTotalSize);
    *(uint32_t*)(bank + 8 + 4) = newBankId;  // set our bank ID

    uint8_t* p = bank + bkhdTotalSize;
    memcpy(p, "HIRC", 4); p += 4;
    *(uint32_t*)p = hircBodySize; p += 4;
    *(uint32_t*)p = (uint32_t)numTracks * itemsPerTrack; p += 4;

    auto w8  = [&](uint8_t v) { *p++ = v; };
    auto w32 = [&](uint32_t v){ *(uint32_t*)p = v; p += 4; };
    auto appendItem = [&](uint8_t type, const uint8_t* tmpl, uint32_t sz, uint8_t** outBody) {
        w8(type);
        w32(sz);
        uint8_t* bodyStart = p;
        memcpy(bodyStart, tmpl, sz);
        p += sz;
        if (outBody) *outBody = bodyStart;
    };

    for (int i = 0; i < numTracks; i++) {
        uint32_t newEventId  = CUSTOM_EVENT_BASE      + (uint32_t)i;
        uint32_t newActionId = CUSTOM_ACTION_BASE     + (uint32_t)i;
        uint32_t newMRSCId   = CUSTOM_MUSICRSC_BASE   + (uint32_t)i;
        uint32_t newMSegId   = CUSTOM_MUSICSEG_BASE   + (uint32_t)i;
        uint32_t newMTrackId = CUSTOM_MUSICTRACK_BASE + (uint32_t)i;

        uint8_t* mtBody = nullptr;
        appendItem(0x0B, m61MTrk, m61MTrkSz, &mtBody);
        ReplaceU32(mtBody, m61MTrkSz, M61_MUSICTRACK_ID, newMTrackId);
        ReplaceU32(mtBody, m61MTrkSz, M61_MUSICSEG_ID,   newMSegId);
        // WWISE-NATIVE custom audio: route the MusicTrack to OUR media id so
        // Wwise looks up our SetMedia data instead of bank #15's M61 WEM.
        // Source ID 378574806 (M61 trial WEM) appears 3 times in the track:
        // AkBankSourceData.sourceID + 2x AkTrackSrcInfo.sourceID.
        uint32_t newMediaId = CUSTOM_MEDIA_BASE + (uint32_t)i;
        ReplaceU32(mtBody, m61MTrkSz, 378574806u, newMediaId);
        // Codec PCM (0x00010001). Our WEMs are wFormatTag=0xFFFE EXTENSIBLE
        // which Wwise's PCM source plugin at sub_142866db0 / sub_142b46690
        // reads directly.
        // pluginID is at body +0x09 (after ulID(4), uFlags(1), numSrc(4)).
        if (m61MTrkSz >= 13) {
            *(uint32_t*)(mtBody + 0x09) = 0x00010001u;
        }
        // streamType in-memory (0) since SetMedia provides the full media buffer.
        if (m61MTrkSz > 0x0D) mtBody[0x0D] = 0;
        // uInMemoryMediaSize at body+0x12 - size of the WEM we SetMedia'd.
        if ((int)i < (int)g_tracks.size() && g_tracks[i].isReady &&
            m61MTrkSz >= 22 && !g_tracks[i].wemBytes.empty()) {
            *(uint32_t*)(mtBody + 0x12) = (uint32_t)g_tracks[i].wemBytes.size();
        }
        // uSourceBits at body+0x16 - was 0x08 (bNonCachable). Clear so SetMedia
        // can override / cache freely.
        if (m61MTrkSz > 0x16) mtBody[0x16] = 0;

        // MusicTrack clip duration patches. Previous approach scanned for any
        // double in 21.7-65.3ms range, which hit a false positive at the
        // mtBody includes the 4-byte ulID at offset 0. The Frida M61 MTrk
        // template hex confirmed the float fSrcDuration sits at body+0x67
        // (clip 0) and body+0x73 (clip 1). The earlier "off-by-4 fix" was
        // a misread - reverting to the original offsets.
        if (m61MTrkSz >= 0x77) {
            auto patchFloat = [&](uint32_t off, const char* lbl) {
                float f = *(float*)(mtBody + off);
                if (f > 20.0f && f < 100.0f) {
                    *(float*)(mtBody + off) = 36000.0f; // 10 hours in seconds
                    if (i == 0) {
                        Log("[MUSICMOD] MTrk %s @ 0x%X: %.3fs -> 36000.0s\n",
                            lbl, off, f);
                    }
                }
            };
            patchFloat(0x67, "clip0.fSrcDuration");
            patchFloat(0x73, "clip1.fSrcDuration");
        }

        uint8_t* msBody = nullptr;
        appendItem(0x0A, m61MSeg, m61MSegSz, &msBody);
        ReplaceU32(msBody, m61MSegSz, M61_MUSICSEG_ID,   newMSegId);
        ReplaceU32(msBody, m61MSegSz, M61_MUSICRSC_ID,   newMRSCId);
        ReplaceU32(msBody, m61MSegSz, M61_MUSICTRACK_ID, newMTrackId);

        // Patch the MusicSegment fDuration field (double, in ms). M61 template
        // hex confirms it's at body+0x4C as `AD AB 44 80 E1 45 E5 40` which
        // decodes to 43576 ms. Reverted from the 0x50 misfix that crashed.
        if (m61MSegSz >= 0x4C + 8) {
            double oldDur = *(double*)(msBody + 0x4C);
            double newDur = 36000000.0; // 10 hours
            *(double*)(msBody + 0x4C) = newDur;
            if (i == 0) {
                Log("[MUSICMOD] segment fDuration patch: %.1fms -> %.1fms (offset 0x4C)\n",
                    oldDur, newDur);
            }
        }

        // Also patch any marker fPositions that match the original fDuration
        // (or any marker position close to it). The "musicend" marker at the
        // end of the segment likely caps playback independently of fDuration,
        // which would explain the ~20s cutoff on playlist mode (Wwise hits
        // the exit marker and ends the segment). Sweep all aligned doubles
        // in the segment; any that falls near the original duration boundary
        // (~43s) gets bumped to match our new duration.
        if (m61MSegSz >= 16) {
            double origDur = 43576.0;
            for (uint32_t off = 0x54; off + 8 <= m61MSegSz; off++) {
                // skip the fDuration slot we already patched (at 0x4C)
                if (off == 0x4C) continue;
                double v = *(double*)(msBody + off);
                // only patch doubles that are plausibly marker positions
                // (finite, positive, within ~50% of original segment duration)
                if (v > origDur * 0.5 && v < origDur * 1.5) {
                    *(double*)(msBody + off) = 36000000.0;
                    if (i == 0) {
                        Log("[MUSICMOD] segment marker patch @ 0x%X: %.1fms -> 36000000.0ms\n",
                            off, v);
                    }
                    off += 7; // skip past this double
                }
            }
        }

        uint8_t* mrBody = nullptr;
        appendItem(0x0D, m61MRSC, m61MRSCSz, &mrBody);
        ReplaceU32(mrBody, m61MRSCSz, M61_MUSICRSC_ID,   newMRSCId);
        ReplaceU32(mrBody, m61MRSCSz, M61_MUSICSEG_ID,   newMSegId);
        // KEEP DirectParentID = 629350378 (CAkMusicSwitchCntr in bank #15) so
        // the music engine can inherit bus routing. Verified parent is registered
        // in the loaded HIRC table from bank #15. Without parent inheritance the
        // MRSC has no bus and audio is silently dropped by sub_1428a6600.

        uint8_t* aBody = nullptr;
        appendItem(3, m61Act, m61ActSz, &aBody);
        ReplaceU32(aBody, m61ActSz, M61_ACTION_ID,     newActionId);
        // FULL CHAIN: target our cloned MRSC, ulFileID = our bank ID.
        // The gate hook should make this work if the +0xc4 gate was the issue.
        ReplaceU32(aBody, m61ActSz, M61_MUSICRSC_ID,   newMRSCId);
        ReplaceU32(aBody, m61ActSz, 727071332u,        0xAD000003u);

        uint8_t* eBody = nullptr;
        appendItem(4, m61Event, m61EventSz, &eBody);
        ReplaceU32(eBody, m61EventSz, M61_EVENT_ID,   newEventId);
        ReplaceU32(eBody, m61EventSz, M61_ACTION_ID,  newActionId);

        uint32_t piggybackEventId = CUSTOM_EVENT_BASE + 0x100u + (uint32_t)i;
        w8(4);
        w32(9);
        w32(piggybackEventId);
        w8(1);
        w32(M61_ACTION_ID);
    }

    *outSize = bankSize;
    Log("[MUSICMOD] BuildMinimalMusicBank: %u bytes, %u items (chain+piggyback per track)\n",
        bankSize, (uint32_t)numTracks * itemsPerTrack);

    static bool s_minDumped = false;
    if (!s_minDumped) {
        char path[MAX_PATH];
        snprintf(path, MAX_PATH, "%s\\sd_music\\.cache\\minimal_music.bnk", g_gameDir);
        FILE* f = fopen(path, "wb");
        if (f) { fwrite(bank, 1, bankSize, f); fclose(f); s_minDumped = true;
            Log("[MUSICMOD] dumped minimal music bank to %s\n", path);
        }
    }
    return bank;
}

// build a minimal Wwise soundbank in memory
// BKHD + HIRC with Event->Action->Sound for each custom track
static uint8_t* BuildCustomBank(int numTracks, uint32_t* outSize) {
    // rough estimate: 256 bytes per track + 64 header
    size_t bufSize = 512 + numTracks * 256;
    auto bank = (uint8_t*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize);
    if (!bank) return nullptr;
    uint8_t* p = bank;

    // helper: write u8/u16/u32/tag
    auto w8  = [&](uint8_t v)  { *p++ = v; };
    auto w16 = [&](uint16_t v) { *(uint16_t*)p = v; p += 2; };
    auto w32 = [&](uint32_t v) { *(uint32_t*)p = v; p += 4; };
    auto wtag = [&](const char* tag) { memcpy(p, tag, 4); p += 4; };

    // BKHD chunk - copy from captured template
    wtag("BKHD");
    if (g_capturedBank && g_capturedBankSize >= 56 &&
        memcmp(g_capturedBank, "BKHD", 4) == 0) {
        uint32_t templBkhdSize = *(uint32_t*)(g_capturedBank + 4);
        w32(templBkhdSize);
        memcpy(p, g_capturedBank + 8, templBkhdSize);
        *(uint32_t*)(p + 4) = CUSTOM_BANK_ID;
        p += templBkhdSize;
    } else {
        w32(48); w32(150); w32(CUSTOM_BANK_ID);
        for (int z = 0; z < 10; z++) w32(0);
    }

    // HIRC chunk - Event -> Action -> Sound triplet for each track
    wtag("HIRC");
    auto hircSizePtr = (uint32_t*)p; p += 4;
    auto hircStart = p;
    w32(numTracks * 3); // 3 items per track

    Log("[MUSICMOD] BuildCustomBank: realSoundSize=%u realActionSize=%u realEventSize=%u\n",
        g_realSoundSize, g_realActionSize, g_realEventSize);

    for (int i = 0; i < numTracks; i++) {
        uint32_t soundId  = CUSTOM_SOUND_BASE + i;
        uint32_t actionId = CUSTOM_ACTION_BASE + i;
        uint32_t eventId  = CUSTOM_EVENT_BASE + i;
        uint32_t mediaId  = CUSTOM_MEDIA_BASE + i;

        // if we have a real Sound template, use it (preserves all the magic fields)
        if (g_realSoundSize > 0) {
            w8(2);
            w32(g_realSoundSize);
            memcpy(p, g_realSoundBody, g_realSoundSize);
            // overwrite ulID at +0x00 (4 bytes) - body offset 0
            *(uint32_t*)(p + 0) = soundId;
            // overwrite sourceID at body+0x0A (after pluginID +4 + streamType +1 = +5, but body starts after ulID so +9... wait)
            // template body layout (body+ offsets):
            //   +0x00: ulID
            //   +0x04: pluginID
            //   +0x08: streamType
            //   +0x09: sourceID
            //   +0x0D: uInMemoryMediaSize
            //   +0x11: uSourceBits
            //   +0x12-...: NodeBaseParams
            //   +0x1B: OverrideBusId or DirectParentID (the 0x332EF486 value)
            *(uint32_t*)(p + 0x09) = mediaId;
            // KEEP Vorbis codec from template (don't change to PCM)
            // ZERO OUT bus references - they reference items in OTHER banks we can't resolve
            *(uint32_t*)(p + 0x1B) = 0;
            // also try zeroing field at +0x17 (might also be a bus ref in some versions)
            // and +0x1F just in case
            p += g_realSoundSize;
        } else {

        // Sound (type 2) - minimal Wwise 2023 SoundSFX
        w8(2);
        auto sSize = (uint32_t*)p; p += 4;
        auto sStart = p;
        w32(soundId);
        // AkBankSourceData: pluginID, streamType, sourceID, mediaSize, sourceBits
        w32(0x00010001);  // PCM codec
        w8(2);            // streamType 2 = use SetMedia
        w32(mediaId);     // source/media ID
        w32(0);           // inMemoryMediaSize (0 since we use SetMedia)
        w8(0);            // uSourceBits
        // NodeBaseParams - all defaults
        w8(0);            // bIsOverrideParentFX
        w8(0);            // numFx
        w8(0);            // bOverrideAttachmentParams
        w32(0);           // OverrideBusId
        w32(0);           // DirectParentID
        w8(0);            // byBitVector (priority overrides)
        // NodeInitialParams: 2 prop bundles, both empty
        w8(0);            // initial props count
        w8(0);            // range mod props count
        // PositioningParams
        w8(0);            // bitVector
        // AuxParams
        w8(0);            // bitVector
        // AdvSettingsParams
        w8(0);            // byBitVector
        w8(0);            // virtualQueueBehavior
        w16(0);           // maxNumInstance
        w8(0);            // belowThresholdBehavior
        w8(0);            // byBitVector2
        // StateChunk
        w8(0);            // ulNumStateProps
        w8(0);            // ulNumStateGroups
        // InitialRTPC
        w16(0);           // count
        *sSize = (uint32_t)(p - sStart);
        } // end else (no Sound template)

        // Action (type 3) - use template if available
        if (g_realActionSize > 0) {
            w8(3);
            w32(g_realActionSize);
            memcpy(p, g_realActionBody, g_realActionSize);
            *(uint32_t*)(p + 0) = actionId;
            // Action target is at +0x06 (after ulID + actionType)
            *(uint32_t*)(p + 0x06) = soundId;
            p += g_realActionSize;
        } else {

        // Action (type 3) - Play
        w8(3);
        auto aSize = (uint32_t*)p; p += 4;
        auto aStart = p;
        w32(actionId);
        w16(0x0403);      // ActionType = Play (0x0403 in some versions, 0x0103 in others)
        w32(soundId);     // target = sound
        w8(0);            // padding/flags
        // ActionInitialValues: 2 empty prop bundles
        w8(0); w8(0); w8(0); w8(0);
        // ActionParams (Play has fade-in time + ID for fade?)
        w32(0);           // FadeInTime / various
        w32(0);           // FileID for play
        *aSize = (uint32_t)(p - aStart);
        } // end else (no Action template)

        // Event (type 4) - 1 action
        w8(4);
        auto eSize = (uint32_t*)p; p += 4;
        auto eStart = p;
        w32(eventId);
        w8(1);            // 1 action
        w32(actionId);    // action ID
        *eSize = (uint32_t)(p - eStart);
    }

    *hircSizePtr = (uint32_t)(p - hircStart);
    *outSize = (uint32_t)(p - bank);

    Log("[MUSICMOD] built Wwise bank: %u bytes, %d empty events\n", *outSize, numTracks);
    return bank;
}

// load WAV PCM data for SetMedia
struct WavPcmData {
    uint8_t* data;
    uint32_t size;
    uint16_t channels;
    uint32_t sampleRate;
    uint16_t bitsPerSample;
};

static WavPcmData LoadWavPcm(const char* path) {
    WavPcmData result = {};
    FILE* f = fopen(path, "rb");
    if (!f) return result;

    uint8_t hdr[44];
    if (fread(hdr, 1, 44, f) < 44 || memcmp(hdr, "RIFF", 4) != 0 || memcmp(hdr + 8, "WAVE", 4) != 0) {
        fclose(f); return result;
    }

    result.channels = *(uint16_t*)(hdr + 22);
    result.sampleRate = *(uint32_t*)(hdr + 24);
    result.bitsPerSample = *(uint16_t*)(hdr + 34);

    fseek(f, 0, SEEK_END);
    long fileSize = ftell(f);
    result.size = (uint32_t)(fileSize - 44);
    fseek(f, 44, SEEK_SET);

    result.data = (uint8_t*)HeapAlloc(GetProcessHeap(), 0, result.size);
    if (result.data) fread(result.data, 1, result.size, f);
    fclose(f);
    return result;
}

// ============================================================
// PostEvent hook - enhanced logging for Wwise debugging
// ============================================================

// SUBSTITUTION TEST: when the music player calls its sample-play event (2147876058),
// swap it out for our custom event ID 0xAD100000 so we can verify whether our
// custom bank's Sound -> WEM data actually produces audio at the speakers.
// If we hear SOMETHING (even garbage / silence), the bank chain works.
// If we hear NOTHING, the bank/SetMedia routing is broken.
static volatile bool g_substEnabled = false;
static volatile int  g_substCount = 0;
static uintptr_t     g_musicCallbackAddr = 0; // = g_gameBase + 0x26B5080 once known

static uint32_t __cdecl Hook_PostEvent(
    uint32_t eventId, uint64_t gameObjId, uint32_t flags,
    void* callback, void* cookie,
    uint32_t numExtSrc, void* extSrc, uint32_t playingId) {

    bool isMusic = (flags & 0x2000) != 0;

    uint32_t origEvent = eventId;

    // tag our custom events with the track name so the log is grep-friendly
    // for the "which samples work" question.
    const char* customLabel = nullptr;
    char labelBuf[128];
    if (eventId >= CUSTOM_EVENT_BASE && eventId < CUSTOM_EVENT_BASE + 0x200) {
        uint32_t slot = eventId - CUSTOM_EVENT_BASE;
        bool piggy = slot >= 0x100;
        if (piggy) slot -= 0x100;
        if (slot < g_tracks.size()) {
            snprintf(labelBuf, sizeof(labelBuf), "%scustom[%u] \"%s\"",
                     piggy ? "piggy " : "",
                     slot, g_tracks[slot].title.c_str());
            customLabel = labelBuf;
            // stash this event so we can replay it after a Wwise Suspend/Wake
            // cycle (alt-tab). Wwise's music engine doesn't restore our custom
            // voices on wake; re-posting the event in Hook_Wakeup does.
            g_lastCustomEventId  = eventId;
            g_lastCustomGameObj  = gameObjId;
            g_lastCustomFlags    = flags;
            g_lastCustomCallback = callback;
        }
    }

    // SUBST disabled - we now patch the TrackResource chain directly at inject time
    // instead of intercepting PostEvent calls. Leaving the infra here in case we need
    // it for a narrow targeted hijack later.
    bool isMusicPlay = false;
    if (isMusicPlay) {
        uint32_t idx = (uint32_t)(g_substCount++ % g_tracks.size());
        eventId = CUSTOM_EVENT_BASE + idx;
        Log("[MUSICMOD] *** SUBST: event %u -> %u (custom track %u, gameObj=%llu)\n",
            origEvent, eventId, idx, (unsigned long long)gameObjId);
    } else {
        Log("[MUSICMOD] PE id=%u (0x%08X)%s%s obj=%llu fl=0x%X cb=%p pid=%u\n",
            eventId, eventId,
            customLabel ? " " : "",
            customLabel ? customLabel : "",
            (unsigned long long)gameObjId, flags, callback, playingId);
        // for custom events, capture call stack so we can find the game
        // function that drives our music-player play path
        if (customLabel) {
            void* frames[16] = {};
            USHORT n = RtlCaptureStackBackTrace(0, 16, frames, nullptr);
            HMODULE hExe = GetModuleHandleA(nullptr);
            uintptr_t gameBase = (uintptr_t)hExe; size_t gameSize = 0;
            MODULEINFO mi = {};
            if (GetModuleInformation(GetCurrentProcess(), hExe, &mi, sizeof(mi))) {
                gameSize = mi.SizeOfImage;
            }
            HMODULE hMods[512]; DWORD cb = 0;
            if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cb)) {
                for (int m = 0; m < (int)(cb / sizeof(HMODULE)); m++) {
                    MODULEINFO mi2 = {};
                    if (GetModuleInformation(GetCurrentProcess(), hMods[m], &mi2, sizeof(mi2))) {
                        if (mi2.SizeOfImage > 0x5000000) {
                            gameBase = (uintptr_t)hMods[m];
                            gameSize = mi2.SizeOfImage;
                            break;
                        }
                    }
                }
            }
            for (int f = 0; f < n; f++) {
                uintptr_t a = (uintptr_t)frames[f];
                if (a >= gameBase && a < gameBase + gameSize) {
                    Log("[MUSICMOD]   stack[%d] game+0x%llX\n", f,
                        (unsigned long long)(a - gameBase));
                } else {
                    Log("[MUSICMOD]   stack[%d] %p\n", f, frames[f]);
                }
            }
        }
    }

    uint32_t result = g_origPostEvent(eventId, gameObjId, flags,
        callback, cookie, numExtSrc, extSrc, playingId);

    // stash the playingId for custom events so the focus watcher can stop
    // the previous voice before re-posting on alt-tab return.
    // also start a wallclock so we can SeekOnEvent back to position on resume.
    if (customLabel && result != 0) {
        g_lastCustomPlayingId = result;
        QueryPerformanceCounter(&g_lastCustomPostTick);
        g_lastCustomPositionMs = 0;
    }

    Log("[MUSICMOD]   -> playingId=%u%s%s\n",
        result, isMusic ? " (music)" : "", (result == 0) ? " REJECTED" : "");

    return result;
}

// PostEvent by name hook
static uint32_t __cdecl Hook_PostEventName(
    const char* eventName, uint64_t gameObjId, uint32_t flags,
    void* callback, void* cookie,
    uint32_t numExtSrc, void* extSrc, uint32_t playingId) {

    Log("[MUSICMOD] PostEventName: \"%s\" flags=0x%X\n",
        eventName ? eventName : "<null>", flags);

    return g_origPostEventName(eventName, gameObjId, flags,
        callback, cookie, numExtSrc, extSrc, playingId);
}

// ============================================================
// PostTrigger / SetSwitch / SetState hooks - Sound_Of_Nature theory:
// music player drives samples via PostTrigger, not PostEvent
// ============================================================
// AK::SoundEngine::ExecuteActionOnEvent(eventId, actionType, gameObj, transTimeMs, fadeCurve, playingId)
// actionType: 1=Stop, 2=Pause, 3=Resume, 4=Break, 5=ReleaseEnvelope, 6=Play
typedef int32_t (__cdecl* ExecuteActionOnEventFn)(
    uint32_t eventId, int32_t actionType, uint64_t gameObjId,
    int32_t transTimeMs, int32_t fadeCurve, uint32_t playingId);
typedef int32_t (__cdecl* PostTriggerIdFn)(uint32_t triggerId, uint64_t gameObjId);
typedef int32_t (__cdecl* PostTriggerNameAFn)(const char* triggerName, uint64_t gameObjId);
typedef int32_t (__cdecl* PostTriggerNameWFn)(const wchar_t* triggerName, uint64_t gameObjId);
typedef int32_t (__cdecl* SetSwitchIdFn)(uint32_t groupId, uint32_t switchId, uint64_t gameObjId);
typedef int32_t (__cdecl* SetStateIdFn)(uint32_t groupId, uint32_t stateId);

static ExecuteActionOnEventFn g_origExecActionOnEvent = nullptr;
static PostTriggerIdFn    g_origPostTriggerId    = nullptr;
static PostTriggerNameAFn g_origPostTriggerNameA = nullptr;
static PostTriggerNameWFn g_origPostTriggerNameW = nullptr;
static SetSwitchIdFn      g_origSetSwitchId      = nullptr;
static SetStateIdFn       g_origSetStateId       = nullptr;

// unique (trig, gameObj) logging so we don't spam
static uint32_t g_seenTrigs[256] = {};
static uint64_t g_seenTrigObjs[256] = {};
static int g_seenTrigCount = 0;

static int32_t __cdecl Hook_PostTriggerId(uint32_t triggerId, uint64_t gameObjId) {
    Log("[MUSICMOD] PostTriggerId: trig=%u (0x%08X) gameObj=%llu\n",
        triggerId, triggerId, (unsigned long long)gameObjId);
    return g_origPostTriggerId(triggerId, gameObjId);
}

static int32_t __cdecl Hook_ExecActionOnEvent(
    uint32_t eventId, int32_t actionType, uint64_t gameObjId,
    int32_t transTimeMs, int32_t fadeCurve, uint32_t playingId) {

    const char* actName = "?";
    switch (actionType) {
        case 1: actName = "STOP";    break;
        case 2: actName = "PAUSE";   break;
        case 3: actName = "RESUME";  break;
        case 4: actName = "BREAK";   break;
        case 5: actName = "RELEASE"; break;
        case 6: actName = "PLAY";    break;
    }

    Log("[MUSICMOD] ExecActionOnEvent: ev=%u (0x%08X) action=%s(%d) gameObj=%llu trans=%dms playId=%u\n",
        eventId, eventId, actName, actionType,
        (unsigned long long)gameObjId, transTimeMs, playingId);

    return g_origExecActionOnEvent(eventId, actionType, gameObjId, transTimeMs, fadeCurve, playingId);
}

static int32_t __cdecl Hook_SetStateId(uint32_t groupId, uint32_t stateId) {
    return g_origSetStateId(groupId, stateId);
}

// Track when StopPlayingID kills a custom playingId. Helps diagnose the
// playlist auto-skip ~20s after track start: if our event is explicitly
// stopped, we'll see the call here. If not, the player is likely just
// stopping at end-of-segment (markers/duration related).
static StopPlayingIDFn g_origStopPlayingID = nullptr;
static void __cdecl Hook_StopPlayingID(uint32_t playingId, int32_t transMs, int32_t curve) {
    Log("[MUSICMOD] StopPlayingID: playingId=%u trans=%dms curve=%d\n",
        playingId, transMs, curve);
    g_origStopPlayingID(playingId, transMs, curve);
}

// Track focus-change pathway. User reports custom music stops when they
// alt-tab. DS2's sub_1406784f0 watches app-state and calls
// Suspend(renderAnyway, fadeOut) on focus loss, WakeupFromSuspend on return.
// For OG music this fades + resumes transparently. For our cloned chain it
// seemingly kills the voice. These hooks tell us exactly when the suspend
// fires so we can correlate with track death.
typedef int32_t (__cdecl* SuspendFn)(bool bRenderAnyway, bool bFadeOut);
typedef int32_t (__cdecl* WakeupFromSuspendFn)(uint32_t delayMs);
static SuspendFn           g_origSuspend = nullptr;
static WakeupFromSuspendFn g_origWakeup  = nullptr;
static int32_t __cdecl Hook_Suspend(bool bRenderAnyway, bool bFadeOut) {
    Log("[MUSICMOD] *** AK::SoundEngine::Suspend(renderAnyway=%d, fadeOut=%d) lastCustom=0x%08X\n",
        (int)bRenderAnyway, (int)bFadeOut, g_lastCustomEventId);
    g_engineSuspended = true;
    int32_t r = g_origSuspend(bRenderAnyway, bFadeOut);
    Log("[MUSICMOD] *** Suspend returned %d\n", r);
    return r;
}
// Track the last-fired custom event so we can re-post it on Wakeup. Wwise's
// music engine doesn't auto-resume our custom events after alt-tab (unlike
// OG music which registers a music state machine), so we manually re-trigger
// playback once the engine wakes up. (globals are forward-declared at top.)

static int32_t __cdecl Hook_Wakeup(uint32_t delayMs) {
    Log("[MUSICMOD] *** AK::SoundEngine::WakeupFromSuspend(delay=%u)\n", delayMs);
    int32_t r = g_origWakeup(delayMs);
    Log("[MUSICMOD] *** Wakeup returned %d\n", r);
    g_engineSuspended = false;

    // resume stashed custom event (unused while Suspend/Wakeup hooks are
    // disabled - retained for when we figure out a crash-free hook path)
    return r;
}

static int32_t __cdecl Hook_PostTriggerNameA(const char* trig, uint64_t gameObjId) {
    Log("[MUSICMOD] PostTriggerA: \"%s\" gameObj=%llu\n",
        trig ? trig : "<null>", (unsigned long long)gameObjId);
    return g_origPostTriggerNameA(trig, gameObjId);
}

static int32_t __cdecl Hook_PostTriggerNameW(const wchar_t* trig, uint64_t gameObjId) {
    char buf[256] = {};
    if (trig) WideCharToMultiByte(CP_UTF8, 0, trig, -1, buf, 255, nullptr, nullptr);
    Log("[MUSICMOD] PostTriggerW: \"%s\" gameObj=%llu\n",
        buf[0] ? buf : "<null>", (unsigned long long)gameObjId);
    return g_origPostTriggerNameW(trig, gameObjId);
}

static int32_t __cdecl Hook_SetSwitchId(uint32_t groupId, uint32_t switchId, uint64_t gameObjId) {
    static uint32_t seenG[128] = {}, seenS[128] = {};
    static uint64_t seenO[128] = {};
    static int seenN = 0;
    bool isNew = true;
    for (int i = 0; i < seenN; i++) {
        if (seenG[i] == groupId && seenS[i] == switchId && seenO[i] == gameObjId) {
            isNew = false; break;
        }
    }
    if (isNew && seenN < 128) {
        seenG[seenN] = groupId; seenS[seenN] = switchId; seenO[seenN] = gameObjId; seenN++;
        Log("[MUSICMOD] SetSwitchId: grp=0x%08X sw=0x%08X gameObj=%llu (new, #%d)\n",
            groupId, switchId, (unsigned long long)gameObjId, seenN);
    }
    return g_origSetSwitchId(groupId, switchId, gameObjId);
}

// ============================================================
// WwiseSimpleSoundInstance hooks - find which instance maps to which track
// ============================================================
// IMPORTANT: these are HARDCODED OFFSETS for the current game build.
// They WILL break on game updates. This is a diagnostic-only setup.
// For the production hijack (when proven working), each of these must be
// replaced with byte-pattern signatures scanned from .text at runtime.
// See memory.md "Update-survival plan" for the conversion approach.
// Legacy offsets kept as documentation and fallback. Runtime values are
// resolved via byte-pattern signatures so updates to the game binary don't
// silently break the mod. See ResolveGameAddresses().
static const uintptr_t WSSI_FACTORY_OFFSET    = 0x269A710; // sub_14269a710
static const uintptr_t WSSI_FACTORY_B_OFFSET  = 0x028DB70; // sub_14028db70 (variant)
static const uintptr_t WSSI_PLAY_OFFSET       = 0x269B3D0; // vtable[0x108] Play
static const uintptr_t WSSI_GETPOS_OFFSET     = 0x269B960; // vtable[0xB0] GetPositionSeconds
static const uintptr_t WSSI_VTABLE_OFFSET     = 0x3440FA0; // class vtable
static const uintptr_t MUSIC_SYSTEM_PTR_OFFSET= 0x62591F8; // data_1462591f8 (singleton ptr)
static const uintptr_t ACTION_GATE_OFFSET     = 0x28F12A0; // sub_1428f12a0 (returns byte[arg1+0xc4])
// data_146259218 = audio resource manager singleton (live build). vtable[0x20]
// is the resolver: takes a SoundResource and writes an AudioNodeHolder
// out-param. Used by both WSSI factories. Note the binja .bndb is from an
// older build that placed this 72 bytes higher (0x6259260); we resolve the
// real address dynamically by reading factory B's `mov rcx, [rip+disp]`.
static const uintptr_t AUDIO_RESMGR_PTR_OFFSET = 0x6259218;

// Runtime-resolved addresses (filled by ResolveGameAddresses)
static uintptr_t g_wssiFactoryA = 0;
static uintptr_t g_wssiFactoryB = 0;
static uintptr_t g_wssiPlayFn   = 0;
static uintptr_t g_wssiGetPosFn = 0;
// Forward declarations of globals defined later (same translation unit).
// g_gameBase is declared near the top of this file (used by the
// InstallMenu heap scanner).
static uintptr_t g_wssiVtable;
static void**    g_musicSystemPtr;

// Pattern scanner - hex string with ?? for wildcards.
// Returns first match address in [start, start+size) or 0 if not found.
static uintptr_t PatternScan(uintptr_t start, size_t size, const char* pattern) {
    // parse pattern into byte+mask arrays
    uint8_t pat[256] = {};
    uint8_t msk[256] = {};
    int plen = 0;
    const char* p = pattern;
    while (*p && plen < 256) {
        while (*p == ' ') p++;
        if (!*p) break;
        if (*p == '?') {
            while (*p == '?') p++;
            pat[plen] = 0;
            msk[plen] = 0;
            plen++;
        } else {
            auto hexval = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            int hi = hexval(p[0]), lo = hexval(p[1]);
            if (hi < 0 || lo < 0) break;
            pat[plen] = (uint8_t)((hi << 4) | lo);
            msk[plen] = 0xFF;
            plen++;
            p += 2;
        }
    }
    if (plen == 0 || (size_t)plen > size) return 0;
    auto data = (const uint8_t*)start;
    size_t last = size - plen;
    for (size_t i = 0; i <= last; i++) {
        bool match = true;
        for (int j = 0; j < plen; j++) {
            if ((data[i + j] & msk[j]) != (pat[j] & msk[j])) { match = false; break; }
        }
        if (match) return start + i;
    }
    return 0;
}

// Extract target of a RIP-relative instruction. instrAddr points at the
// start of the instruction, instrLen is the total instruction length,
// dispOff is the offset within the instruction where the 4-byte disp sits.
static uintptr_t RipRelTarget(uintptr_t instrAddr, size_t instrLen, size_t dispOff) {
    int32_t disp = *(int32_t*)(instrAddr + dispOff);
    return instrAddr + instrLen + (intptr_t)disp;
}

// Get .text section bounds for a loaded PE. Returns true on success.
static bool GetTextSection(uintptr_t base, uintptr_t* outStart, size_t* outSize) {
    __try {
        if (*(uint16_t*)base != 0x5A4D) return false; // MZ
        uint32_t peOff = *(uint32_t*)(base + 0x3C);
        if (*(uint32_t*)(base + peOff) != 0x00004550) return false; // PE\0\0
        uint16_t numSections = *(uint16_t*)(base + peOff + 6);
        uint16_t optHdrSize  = *(uint16_t*)(base + peOff + 20);
        uintptr_t sections = base + peOff + 24 + optHdrSize;
        for (int i = 0; i < numSections; i++) {
            uintptr_t s = sections + i * 40;
            const char* name = (const char*)s;
            if (memcmp(name, ".text", 5) == 0) {
                uint32_t vsize = *(uint32_t*)(s + 8);
                uint32_t vaddr = *(uint32_t*)(s + 12);
                *outStart = base + vaddr;
                *outSize = vsize;
                return true;
            }
        }
    } __except(1) { return false; }
    return false;
}

// Scan the game module's .text for known function signatures and derive
// vtable / singleton addresses via RIP-relative references in Factory A.
// Called after g_gameBase is known. Logs what it finds.
static void ResolveGameAddresses() {
    if (!g_gameBase) { Log("[MUSICMOD] ResolveGameAddresses: no game base\n"); return; }

    uintptr_t textStart = 0;
    size_t textSize = 0;
    if (!GetTextSection(g_gameBase, &textStart, &textSize)) {
        Log("[MUSICMOD] ResolveGameAddresses: .text not found, falling back to hardcoded offsets\n");
        g_wssiFactoryA = g_gameBase + WSSI_FACTORY_OFFSET;
        g_wssiFactoryB = g_gameBase + WSSI_FACTORY_B_OFFSET;
        g_wssiPlayFn   = g_gameBase + WSSI_PLAY_OFFSET;
        g_wssiGetPosFn = g_gameBase + WSSI_GETPOS_OFFSET;
        g_wssiVtable   = g_gameBase + WSSI_VTABLE_OFFSET;
        g_musicSystemPtr = (void**)(g_gameBase + MUSIC_SYSTEM_PTR_OFFSET);
        return;
    }
    Log("[MUSICMOD] .text @ %p size 0x%llX\n", (void*)textStart, (unsigned long long)textSize);

    // WSSI Factory A: unique prologue (24 bytes)
    // 48 89 74 24 18 57 48 83 EC 50 48 8B 35 ?? ?? ?? ?? 48 8B F9 48 85 F6 75 0D
    g_wssiFactoryA = PatternScan(textStart, textSize,
        "48 89 74 24 18 57 48 83 EC 50 48 8B 35 ?? ?? ?? ?? 48 8B F9 48 85 F6 75 0D");
    Log("[MUSICMOD] sig WSSI factoryA -> %p (expected %p)\n",
        (void*)g_wssiFactoryA, (void*)(g_gameBase + WSSI_FACTORY_OFFSET));

    // WSSI Factory B
    g_wssiFactoryB = PatternScan(textStart, textSize,
        "48 89 6C 24 18 48 89 7C 24 20 41 56 48 83 EC 50 4C 8B 35 ?? ?? ?? ?? 48 8B E9");
    Log("[MUSICMOD] sig WSSI factoryB -> %p (expected %p)\n",
        (void*)g_wssiFactoryB, (void*)(g_gameBase + WSSI_FACTORY_B_OFFSET));

    // WSSI Play: reads AudioNodeHolder at +0x178 (unique Play behavior)
    g_wssiPlayFn = PatternScan(textStart, textSize,
        "40 53 48 83 EC 30 48 8B 81 78 01 00 00 48 8B D9 48 85 C0");
    Log("[MUSICMOD] sig WSSI Play -> %p (expected %p)\n",
        (void*)g_wssiPlayFn, (void*)(g_gameBase + WSSI_PLAY_OFFSET));

    // WSSI GetPositionSeconds (vtable[0xB0]): reads playingId from WSSI[+0x32C]
    // and calls GetSourcePlayPosition
    g_wssiGetPosFn = PatternScan(textStart, textSize,
        "40 53 48 83 EC 20 48 8B D9 48 8D 54 24 38 8B 89 2C 03 00 00 41 B0 01 E8");
    Log("[MUSICMOD] sig WSSI GetPos -> %p (expected %p)\n",
        (void*)g_wssiGetPosFn, (void*)(g_gameBase + WSSI_GETPOS_OFFSET));

    // Derive MusicPlayerSystem singleton pointer from Factory A's first
    // `mov rsi, [rip+disp32]` at function +0xA (7 bytes, disp at +0xD).
    // Target = factory + 0x11 + disp.
    if (g_wssiFactoryA) {
        g_musicSystemPtr = (void**)RipRelTarget(g_wssiFactoryA + 0xA, 7, 3);
        Log("[MUSICMOD] derived music system ptr -> %p (expected %p)\n",
            (void*)g_musicSystemPtr, (void*)(g_gameBase + MUSIC_SYSTEM_PTR_OFFSET));
    } else {
        g_musicSystemPtr = (void**)(g_gameBase + MUSIC_SYSTEM_PTR_OFFSET);
    }

    // Derive WSSI vtable from Factory A's `lea rax, [rip+vtable]` at +0x69
    // (7 bytes, disp at +0x6C). Immediately followed by `mov [rbx], rax`
    // which writes vtable to new instance +0x00.
    if (g_wssiFactoryA) {
        g_wssiVtable = RipRelTarget(g_wssiFactoryA + 0x69, 7, 3);
        Log("[MUSICMOD] derived WSSI vtable -> %p (expected %p)\n",
            (void*)g_wssiVtable, (void*)(g_gameBase + WSSI_VTABLE_OFFSET));
    } else {
        g_wssiVtable = g_gameBase + WSSI_VTABLE_OFFSET;
    }

    // fallbacks: if any sig missed, fall back to hardcoded
    if (!g_wssiFactoryA) g_wssiFactoryA = g_gameBase + WSSI_FACTORY_OFFSET;
    if (!g_wssiFactoryB) g_wssiFactoryB = g_gameBase + WSSI_FACTORY_B_OFFSET;
    if (!g_wssiPlayFn)   g_wssiPlayFn   = g_gameBase + WSSI_PLAY_OFFSET;
    if (!g_wssiGetPosFn) g_wssiGetPosFn = g_gameBase + WSSI_GETPOS_OFFSET;
}

// Validate a candidate function address looks like a real x64 function prologue.
// Used so that on a different game build (offsets shifted) we skip the hook
// instead of corrupting random bytes.
static bool LooksLikeFunctionPrologue(void* p) {
    if (!p) return false;
    auto b = (uint8_t*)p;
    // typical x64 prologues: push reg / sub rsp / mov [rsp+X], reg
    return b[0] == 0x40 || b[0] == 0x48 || b[0] == 0x44 || b[0] == 0x4C ||
           b[0] == 0x55 || b[0] == 0x53 || b[0] == 0x56 || b[0] == 0x57;
}

// pointer types for the hooks
typedef void* (__cdecl* WSSIFactoryFn)(void* resource);
typedef int64_t (__cdecl* WSSIPlayFn)(void* instance);
typedef uint32_t (*ActionGateFn)(void* action);
// Audio resource manager resolver. Signature inferred from factory disasm:
//   call qword [rax+0x20]   with rcx=resMgr, rdx=outHolder, r8=resource, r9b=flags
typedef void (__cdecl* ResolverFn)(void* resMgr, void* outHolder,
                                   void* resource, uint8_t flags);
typedef float (__cdecl* WSSIGetPosFn)(void* instance);

static WSSIFactoryFn g_origWSSIFactory   = nullptr;
static WSSIFactoryFn g_origWSSIFactoryB  = nullptr;
static WSSIPlayFn    g_origWSSIPlay      = nullptr;
static ActionGateFn  g_origActionGate    = nullptr;
static ResolverFn    g_origResolver      = nullptr;
static WSSIGetPosFn  g_origWSSIGetPos    = nullptr;
static void*         g_resolverAddr      = nullptr;

// Observation-only hook for sub_1428f12a0. Reads the original +0xC4 byte and
// returns it unchanged so game audio behaviour is preserved. Logs only type
// 0x403 (ActionPlay) calls — those are the ones that matter for our music
// chain — and rate-limits per-action-pointer so we don't drown in spam.
static uint32_t Hook_ActionGate(void* action) {
    if (!action) return 0;

    uint8_t actualByte = 0;
    uint16_t actionType = 0;
    __try {
        actualByte = *(uint8_t*)((uint8_t*)action + 0xC4);
        actionType = *(uint16_t*)((uint8_t*)action + 0x34);
    } __except(1) { return 0; }

    if (actionType == 0x0403) {
        // log first 200 type-0x403 calls so we cover the selftest window
        static volatile long s_play403Calls = 0;
        long n = InterlockedIncrement(&s_play403Calls);
        if (n <= 200) {
            // try to read action ulID - common Wwise layout has it at +0x10
            uint32_t actionUlId = 0;
            __try { actionUlId = *(uint32_t*)((uint8_t*)action + 0x10); } __except(1) {}
            // also try +0x18 (other Wwise layouts)
            uint32_t altId = 0;
            __try { altId = *(uint32_t*)((uint8_t*)action + 0x18); } __except(1) {}
            bool isOurs = ((actionUlId & 0xFFFFFF00u) == 0xAD300000u) ||
                          ((altId      & 0xFFFFFF00u) == 0xAD300000u);
            Log("[GATE] play#%ld action=%p +0x10=0x%08X +0x18=0x%08X +0xC4=%u%s\n",
                n, action, actionUlId, altId, actualByte,
                isOurs ? " *** OURS ***" : "");
        }
    }
    return actualByte;  // return ORIGINAL value, no override
}
// g_gameBase / g_wssiVtable / g_musicSystemPtr defined above (forward decls);
// they default to 0/nullptr. Earlier declarations at top of file.

// keep a map: resource_ptr -> instance_ptr. per-row factory calls happen when
// the user scrolls; with 36 custom tracks plus scrolling back and forth we
// need plenty of room.
struct ResInstMap {
    void* resource;
    void* instance;
    uint32_t triedOverride;
};
static ResInstMap g_resMap[512] = {};
static volatile int g_resMapCount = 0;

// returns -1 if the TrackResource doesn't belong to one of our custom tracks,
// otherwise the index into g_tracks. O(n) scan but n<=36.
static int FindCustomTrackIndex(void* trackResource) {
    if (!trackResource) return -1;
    for (size_t i = 0; i < g_tracks.size(); i++) {
        if (g_tracks[i].pTrackResource == trackResource) return (int)i;
    }
    return -1;
}

static void* __cdecl Hook_WSSIFactory(void* resource) {
    void* result = g_origWSSIFactory(resource);
    Log("[MUSICMOD] [FACTORY-A] resource=%p -> instance=%p\n", resource, result);
    if (result && resource && g_resMapCount < 512) {
        // dump first few qwords of the resource so we can recognize it
        char buf[256] = {};
        for (int i = 0; i < 8; i++) {
            uint64_t v = 0;
            __try { v = *((uint64_t*)resource + i); } __except(1) { v = 0xDEADBEEFDEADBEEFull; break; }
            char tmp[32]; snprintf(tmp, sizeof(tmp), "%016llX ", (unsigned long long)v);
            strncat_s(buf, tmp, _TRUNCATE);
        }
        Log("[MUSICMOD]   resource bytes: %s\n", buf);
        // also: try ObjTypeName if it looks like a Decima object
        const char* tname = ObjTypeName(resource);
        if (tname) Log("[MUSICMOD]   resource type: %s\n", tname);
        int idx = g_resMapCount++;
        g_resMap[idx].resource = resource;
        g_resMap[idx].instance = result;

        // check if any of our cloned tracks map here
        for (size_t t = 0; t < g_tracks.size(); t++) {
            if (!g_tracks[t].pTrackResource) continue;
            void* trackSound = *(void**)((uint8_t*)g_tracks[t].pTrackResource + 0x40);
            if (resource == g_tracks[t].pTrackResource || resource == trackSound) {
                Log("[MUSICMOD]   *** MATCH: resource=%p is track %zu (\"%s\"). Setting +0x334 override\n",
                    resource, t, g_tracks[t].title.c_str());
                *(uint32_t*)((uint8_t*)result + 0x334) = CUSTOM_EVENT_BASE + (uint32_t)t;
                g_resMap[idx].triedOverride = CUSTOM_EVENT_BASE + (uint32_t)t;
            }
        }
    }
    return result;
}

static void DumpResource(void* resource, const char* label) {
    if (!resource) return;
    char buf[256] = {};
    for (int i = 0; i < 8; i++) {
        uint64_t v = 0;
        __try { v = *((uint64_t*)resource + i); } __except(1) { v = 0xDEADBEEFDEADBEEFull; break; }
        char tmp[32]; snprintf(tmp, sizeof(tmp), "%016llX ", (unsigned long long)v);
        strncat_s(buf, tmp, _TRUNCATE);
    }
    Log("[MUSICMOD]   %s bytes: %s\n", label, buf);
    const char* tname = ObjTypeName(resource);
    if (tname) Log("[MUSICMOD]   %s type: %s\n", label, tname);
}

// fully-protected pair-of-qword read; returns true on success
static bool SafeRead2Q(void* base, size_t off, uint64_t* outLo, uint64_t* outHi) {
    if (!base) return false;
    __try {
        *outLo = *(uint64_t*)((uint8_t*)base + off);
        *outHi = *(uint64_t*)((uint8_t*)base + off + 8);
        return true;
    } __except(1) { return false; }
}

static void* SafeReadPtr(void* base, size_t off) {
    if (!base) return nullptr;
    __try {
        return *(void**)((uint8_t*)base + off);
    } __except(1) { return nullptr; }
}

static void TryMatchAndOverride(void* resource, void* result, int idx, const char* src) {
    if (!result || !resource) return;

    uint64_t resGuidLo = 0, resGuidHi = 0;
    bool resGuidOk = SafeRead2Q(resource, 0x10, &resGuidLo, &resGuidHi);

    for (size_t t = 0; t < g_tracks.size(); t++) {
        void* trackRes = g_tracks[t].pTrackResource;
        if (!trackRes) continue;

        // safely read pointers from our cloned track
        void* fullSound  = SafeReadPtr(trackRes, 0x40);
        void* trialSound = SafeReadPtr(trackRes, 0x48);

        bool ptrMatch = (resource == trackRes || resource == fullSound || resource == trialSound);

        bool guidMatch = false;
        if (resGuidOk) {
            uint64_t lo = 0, hi = 0;
            if (trialSound && SafeRead2Q(trialSound, 0x10, &lo, &hi) &&
                lo == resGuidLo && hi == resGuidHi) {
                guidMatch = true;
            }
            if (!guidMatch && fullSound && SafeRead2Q(fullSound, 0x10, &lo, &hi) &&
                lo == resGuidLo && hi == resGuidHi) {
                guidMatch = true;
            }
        }

        if (ptrMatch || guidMatch) {
            Log("[MUSICMOD]   *** MATCH(%s): resource=%p is track %zu \"%s\" (ptr=%d guid=%d).\n",
                src, resource, t, g_tracks[t].title.c_str(),
                ptrMatch ? 1 : 0, guidMatch ? 1 : 0);
            // OVERRIDE WRITE TEMPORARILY DISABLED while we verify match safety
            // *(uint32_t*)((uint8_t*)result + 0x334) = CUSTOM_EVENT_BASE + (uint32_t)t;
            if (idx >= 0 && idx < 64)
                g_resMap[idx].triedOverride = CUSTOM_EVENT_BASE + (uint32_t)t;
            return;
        }
    }
}

static void* __cdecl Hook_WSSIFactoryB(void* resource) {
    void* result = g_origWSSIFactoryB(resource);
    int customIdx = FindCustomTrackIndex(resource);
    if (customIdx >= 0) {
        Log("[MUSICMOD] [SAMPLE-scroll] custom track %d \"%s\" (resource=%p -> instance=%p)\n",
            customIdx, g_tracks[customIdx].title.c_str(), resource, result);
    } else {
        Log("[MUSICMOD] [FACTORY-B] resource=%p -> instance=%p (not a custom track)\n",
            resource, result);
    }
    if (result && resource && g_resMapCount < 512) {
        int idx = g_resMapCount++;
        g_resMap[idx].resource = resource;
        g_resMap[idx].instance = result;
        if (customIdx < 0) DumpResource(resource, "[FACTORY-B]");
        TryMatchAndOverride(resource, result, idx, "B");
    }
    return result;
}

static int64_t __cdecl Hook_WSSIPlay(void* instance) {
    uint32_t curOverride = 0;
    uint32_t playEventId = 0;  // at +0xD8 of audio_node (NOT +0x6c)
    uint32_t maybe6c     = 0;
    void* audioNode = nullptr;
    __try {
        curOverride = *(uint32_t*)((uint8_t*)instance + 0x334);
        void* holder = *(void**)((uint8_t*)instance + 0x178);
        if (holder) {
            void* holderTarget = *(void**)holder;
            if (holderTarget) {
                audioNode = *(void**)((uint8_t*)holderTarget + 0x20);
                if (audioNode) {
                    playEventId = *(uint32_t*)((uint8_t*)audioNode + 0xD8);
                    maybe6c     = *(uint32_t*)((uint8_t*)audioNode + 0x6C);
                }
            }
        }
    } __except(1) {}

    // map the WSSI instance back to the resource it was created for, then to
    // our custom-track index if it's one of ours. that tells us EXACTLY which
    // custom row the user is sampling and whether the event ID the game is
    // about to dispatch is our cloned event (0xAD100000+N) or the source's
    // original - a dead giveaway for "plays source" vs "plays custom".
    void* matchedRes = nullptr;
    for (int i = 0; i < g_resMapCount; i++) {
        if (g_resMap[i].instance == instance) {
            matchedRes = g_resMap[i].resource;
            break;
        }
    }
    int customIdx = FindCustomTrackIndex(matchedRes);
    if (customIdx >= 0) {
        uint32_t expectedEv = CUSTOM_EVENT_BASE + (uint32_t)customIdx;
        bool eventMatches = (playEventId == expectedEv);
        // include WEM size + duration so we can grep for the silent ones and
        // see if there's any size/duration boundary
        Log("[MUSICMOD] [SAMPLE-play] custom[%d] \"%s\" dispatch: event=0x%08X expected=0x%08X %s wem=%zu dur=%us node=%p inst=%p\n",
            customIdx, g_tracks[customIdx].title.c_str(),
            playEventId, expectedEv,
            eventMatches ? "OK" : "MISMATCH",
            g_tracks[customIdx].wemBytes.size(),
            g_tracks[customIdx].durationSec,
            audioNode, instance);
    } else {
        Log("[MUSICMOD] [PLAY] instance=%p override=%u node=%p event(+0xD8)=%u (+0x6C)=0x%08X\n",
            instance, curOverride, audioNode, playEventId, maybe6c);
    }
    return g_origWSSIPlay(instance);
}

// WSSI GetPositionSeconds hook (vtable[0xB0]).
// The original reads playingId from WSSI[+0x32C] and calls
// AK::GetSourcePlayPosition. For our custom tracks the WSSI never gets a
// real playingId stored at +0x32C (the resolver crashes on our cloned chain
// so the WSSI factory unwinds, no WSSI is registered for the custom voice).
// But our custom event IS posted via the music player's task queue path,
// and we stash that playingId in g_lastCustomPlayingId during Hook_PostEvent.
// So when the music player's UI queries position and the original returns 0,
// we fall back to GetSourcePlayPosition(g_lastCustomPlayingId) and feed
// the timer the right value.
typedef int32_t (__cdecl* GetSourcePlayPositionFn)(uint32_t playingId,
                                                   int32_t* posMs,
                                                   bool extrapolate);
static GetSourcePlayPositionFn g_getSourcePlayPosition = nullptr;
// CSEC = (1 / 1000.0f) factor used by the original GetPosition fn to convert
// ms to seconds (the original loads it from a global float at sub_14269B98B
// and multiplies). Same value here so our return matches.
static const float kMsToSec = 1.0f / 1000.0f;

static float __cdecl Hook_WSSIGetPos(void* instance) {
    float orig = g_origWSSIGetPos(instance);
    if (orig > 0.001f) return orig;  // original worked, use it

    // original returned ~0; check whether we have a known recent custom
    // playingId still active in Wwise
    uint32_t pid = g_lastCustomPlayingId;
    if (pid == 0 || !g_getSourcePlayPosition) return orig;

    int32_t posMs = 0;
    int32_t r = g_getSourcePlayPosition(pid, &posMs, true);
    if (r != 1) return orig;
    return (float)posMs * kMsToSec;
}

// helper used by the resolver hook to detect whether the input resource came
// from one of our cloned tracks
static int FindCustomTrackByClonedRes(void* res) {
    if (!res) return -1;
    for (size_t t = 0; t < g_tracks.size(); t++) {
        if (!g_tracks[t].pTrackResource) continue;
        void* gsr40 = nullptr; void* gsr48 = nullptr;
        __try {
            gsr40 = *(void**)((uint8_t*)g_tracks[t].pTrackResource + 0x40);
            gsr48 = *(void**)((uint8_t*)g_tracks[t].pTrackResource + 0x48);
        } __except(1) {}
        if (res == gsr40 || res == gsr48 || res == g_tracks[t].pTrackResource) {
            return (int)t;
        }
    }
    return -1;
}

// captures the first successful OG audio_node bytes so we can use them as a
// template for cloning a LocalizedSimpleSoundResource per custom track.
static uint8_t  g_ogLssrTemplate[0x400] = {};
static size_t   g_ogLssrTemplateSize = 0;
static uint32_t g_ogLssrOrigEvent = 0;
static void*    g_ogLssrSourceTrack = nullptr;
static volatile bool g_ogLssrCaptured = false;

// scan OG TrackResources (the ones already in DSMusicPlayerSystem.AllTracks
// before our injection) and check if `res` matches any of their +0x40/+0x48.
// Returns the OG track index, or -1.
static int FindOGTrackByRes(void* res, void* sysRes) {
    if (!res || !sysRes) return -1;
    auto* trackArr = (RawArray*)((uint8_t*)sysRes + 0x30);
    uint32_t total = trackArr->count;
    // skip the tail entries that are our injected customs
    uint32_t ogCount = (total > (uint32_t)g_tracks.size()) ?
                      total - (uint32_t)g_tracks.size() : total;
    for (uint32_t i = 0; i < ogCount; i++) {
        void* tr = trackArr->entries[i];
        if (!tr) continue;
        void* p40 = nullptr; void* p48 = nullptr;
        __try {
            p40 = *(void**)((uint8_t*)tr + 0x40);
            p48 = *(void**)((uint8_t*)tr + 0x48);
        } __except(1) {}
        if (res == p40 || res == p48 || res == tr) {
            return (int)i;
        }
    }
    return -1;
}


// Resource manager resolver hook. Game calls this to bind a SoundResource
// (either GSR or LSSR) into an AudioNodeHolder slot inside the WSSI being
// constructed. Logging-only first pass: we want to see whether the music
// player ever invokes the resolver with one of our cloned GSR pointers, and
// what the resulting audio_node looks like (event ID at +0xD8).
static void __cdecl Hook_Resolver(void* resMgr, void* outHolder,
                                  void* resource, uint8_t flags) {
    g_origResolver(resMgr, outHolder, resource, flags);

    int customIdx = FindCustomTrackByClonedRes(resource);

    // capture an OG track's resolved audio_node bytes once - we use it as a
    // template to clone an LSSR-style resource per custom track in a follow-up
    // build. Limit to the first OG match so the log stays small.
    if (customIdx < 0 && !g_ogLssrCaptured && g_pSysResource) {
        int ogIdx = FindOGTrackByRes(resource, g_pSysResource);
        if (ogIdx >= 0) {
            void* holder0 = nullptr;
            void* node = nullptr;
            uint32_t evId = 0;
            __try {
                holder0 = *(void**)outHolder;
                if (holder0) {
                    node = *(void**)((uint8_t*)holder0 + 0x20);
                    if (node) evId = *(uint32_t*)((uint8_t*)node + 0xD8);
                }
            } __except(1) {}
            // skip sentinel event IDs (0xFFFFFFxx pattern) - those are
            // probably special tracks (silent BGM, title music) without a
            // real Wwise event - their LSSRs aren't a useful template
            bool isSentinel = (evId == 0 || (evId >> 24) == 0xFF);
            if (node && evId != 0 && !isSentinel) {
                __try {
                    memcpy(g_ogLssrTemplate, node, sizeof(g_ogLssrTemplate));
                    g_ogLssrTemplateSize = sizeof(g_ogLssrTemplate);
                    g_ogLssrOrigEvent = evId;
                    g_ogLssrSourceTrack = (void*)(uintptr_t)ogIdx;
                    g_ogLssrCaptured = true;
                    Log("[MUSICMOD] [TEMPLATE] captured OG audio_node from track[%d] node=%p eventId=0x%08X (%u bytes)\n",
                        ogIdx, node, evId, (uint32_t)sizeof(g_ogLssrTemplate));
                    // dump first 0x80 bytes for inspection
                    for (int line = 0; line < 0x80; line += 0x20) {
                        char buf[256] = {};
                        for (int q = 0; q < 4; q++) {
                            char tmp[24]; snprintf(tmp, sizeof(tmp), "%016llX ",
                                                  (unsigned long long)*((uint64_t*)((uint8_t*)node + line) + q));
                            strncat_s(buf, tmp, _TRUNCATE);
                        }
                        Log("[MUSICMOD] [TEMPLATE]   +0x%03X: %s\n", line, buf);
                    }
                    // also dump bytes around +0xD8 (event id) so we can see context
                    for (int line = 0xC0; line < 0x100; line += 0x20) {
                        char buf[256] = {};
                        for (int q = 0; q < 4; q++) {
                            char tmp[24]; snprintf(tmp, sizeof(tmp), "%016llX ",
                                                  (unsigned long long)*((uint64_t*)((uint8_t*)node + line) + q));
                            strncat_s(buf, tmp, _TRUNCATE);
                        }
                        Log("[MUSICMOD] [TEMPLATE]   +0x%03X: %s\n", line, buf);
                    }
                } __except(1) {
                    Log("[MUSICMOD] [TEMPLATE] capture failed (read fault)\n");
                }
            } else if (node && isSentinel) {
                // log so we know we skipped this OG track for being sentinel
                static int s_skipLog = 0;
                if (s_skipLog++ < 3) {
                    Log("[MUSICMOD] [TEMPLATE] skipped OG track[%d] - sentinel event 0x%08X\n",
                        ogIdx, evId);
                }
            }
        }
        return;
    }

    if (customIdx < 0) {
        // skip non-custom traffic (very high volume - sounds, ambient, etc.)
        return;
    }

    // dump what original wrote into the holder
    void* holder0 = nullptr;
    void* audioNode = nullptr;
    uint32_t evId = 0;
    const char* nodeType = nullptr;
    __try {
        holder0 = *(void**)outHolder;
        if (holder0) {
            audioNode = *(void**)((uint8_t*)holder0 + 0x20);
            if (audioNode) {
                evId = *(uint32_t*)((uint8_t*)audioNode + 0xD8);
                nodeType = ObjTypeName(audioNode);
            }
        }
    } __except(1) {}

    uint32_t expectedEv = CUSTOM_EVENT_BASE + (uint32_t)customIdx;
    Log("[MUSICMOD] [RESOLVE] custom[%d] \"%s\" res=%p flags=%u "
        "-> holder=%p node=%p type=%s event=0x%08X (expected 0x%08X) %s\n",
        customIdx, g_tracks[customIdx].title.c_str(), resource, flags,
        holder0, audioNode, nodeType ? nodeType : "?",
        evId, expectedEv, (evId == expectedEv) ? "OK" : "MISMATCH");

    // dump first 0x100 bytes of the audio_node so we can identify its type
    // and find the right field to override
    if (audioNode) {
        for (int line = 0; line < 0x100; line += 0x20) {
            char buf[256] = {};
            __try {
                for (int q = 0; q < 4; q++) {
                    uint64_t v = *((uint64_t*)((uint8_t*)audioNode + line) + q);
                    char tmp[24]; snprintf(tmp, sizeof(tmp), "%016llX ",
                                          (unsigned long long)v);
                    strncat_s(buf, tmp, _TRUNCATE);
                }
            } __except(1) { strncat_s(buf, "<read fault>", _TRUNCATE); }
            Log("[MUSICMOD]   node+0x%03X: %s\n", line, buf);
        }
    }
    // also dump first 0x40 bytes of the holder
    if (holder0) {
        for (int line = 0; line < 0x40; line += 0x20) {
            char buf[256] = {};
            __try {
                for (int q = 0; q < 4; q++) {
                    uint64_t v = *((uint64_t*)((uint8_t*)holder0 + line) + q);
                    char tmp[24]; snprintf(tmp, sizeof(tmp), "%016llX ",
                                          (unsigned long long)v);
                    strncat_s(buf, tmp, _TRUNCATE);
                }
            } __except(1) { strncat_s(buf, "<read fault>", _TRUNCATE); }
            Log("[MUSICMOD]   holder+0x%03X: %s\n", line, buf);
        }
    }
}

// ============================================================
// Main initialization
// ============================================================

static bool TryScanModule(HMODULE hMod, const char* modName,
                          uintptr_t* outCtorAddr, uintptr_t* outInstAddr) {
    uintptr_t base = (uintptr_t)hMod;
    uintptr_t textStart, textEnd;
    if (!GetPESection(base, ".text", &textStart, &textEnd)) {
        Log("[MUSICMOD] no .text section in %s\n", modName);
        return false;
    }
    size_t textSize = textEnd - textStart;
    Log("[MUSICMOD] %s .text: %p - %p (%zu bytes)\n",
        modName, (void*)textStart, (void*)textEnd, textSize);

    *outCtorAddr = ScanPattern(textStart, textSize, SIG_STREAMING_CTOR);
    *outInstAddr = ScanPattern(textStart, textSize, SIG_STREAMING_INSTANCE);

    if (*outCtorAddr)
        Log("[MUSICMOD] StreamingManager::ctor found in %s @ %p (offset +0x%llX)\n",
            modName, (void*)*outCtorAddr, *outCtorAddr - base);
    if (*outInstAddr)
        Log("[MUSICMOD] StreamingManager::Instance sig found in %s @ %p\n",
            modName, (void*)*outInstAddr);

    return (*outCtorAddr != 0) || (*outInstAddr != 0);
}

static volatile LONG g_initGuard = 0;

// Loads albumjacket/fingerprints/large_*.bc7 into g_fingerprints. Kept in
// its own function because InitThread uses __try and can't have non-trivial
// destructors in the same body.

static DWORD WINAPI InitThread(LPVOID) {
    if (InterlockedCompareExchange(&g_initGuard, 1, 0) != 0) return 0;
    QueryPerformanceFrequency(&g_perfFreq);
    QueryPerformanceCounter(&g_perfStart);
    GetModuleFileNameA(nullptr, g_gameDir, MAX_PATH);
    char* sl = strrchr(g_gameDir, '\\');
    if (sl) *sl = '\0';

    // open log - use process basename in filename so DS2.exe and the
    // crs-handler.exe / crs-video.exe subprocesses each get their own log.
    // (Versione.dll loads our ASI into all 3 because they all link to
    // version.dll. With a shared log file each fopen("w") would truncate
    // the others.)
    char exeName[MAX_PATH] = {0};
    {
        char exePath[MAX_PATH];
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        const char* bs = strrchr(exePath, '\\');
        const char* base = bs ? bs + 1 : exePath;
        snprintf(exeName, sizeof(exeName), "%s", base);
        // strip .exe
        char* dot = strrchr(exeName, '.');
        if (dot) *dot = '\0';
    }
    char logPath[MAX_PATH];
    snprintf(logPath, sizeof(logPath), "%s\\ds2_musicplayer.%s.log",
             g_gameDir, exeName);
    g_log = fopen(logPath, "w");

    // register crash dumper FIRST-chance - any AV / illegal-instr / stack
    // overflow hits this before game SEH runs, so we always log the fault
    // before process dies.
    AddVectoredExceptionHandler(1, CrashDumpVEH);

    // heartbeat thread: one line every 30s so the tail of the log tells us
    // when the game died (and whether the mod was still running).
    CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        int hb = 0;
        while (true) {
            Sleep(30000);
            Log("[MUSICMOD] <hb %d>\n", ++hb);
            if (g_log) fflush(g_log);
        }
    }, nullptr, 0, nullptr);

    Log("[MUSICMOD] DS2 Custom Music Player Mod\n");
    Log("[MUSICMOD] game dir: %s\n", g_gameDir);




    // make sure sd_music/ exists so the user has somewhere to drop files
    {
        char musicDir[MAX_PATH];
        snprintf(musicDir, MAX_PATH, "%s\\sd_music", g_gameDir);
        if (CreateDirectoryA(musicDir, nullptr)) {
            Log("[MUSICMOD] created %s -- drop audio files here\n", musicDir);
        } else if (GetLastError() == ERROR_ALREADY_EXISTS) {
            Log("[MUSICMOD] sd_music/ ready: %s\n", musicDir);
        } else {
            Log("[MUSICMOD] couldn't create sd_music/ (err=%lu) at %s\n",
                GetLastError(), musicDir);
        }
    }

    // scan for music files
    ScanMusicFolder();
    if (g_tracks.empty()) {
        Log("[MUSICMOD] no tracks found. put audio files in: %s\\sd_music\\\n", g_gameDir);
        Log("[MUSICMOD] supported: wav, mp3, ogg, flac, m4a, opus\n");
        Log("[MUSICMOD] format: \"Artist - Title.ext\"\n");
        if (g_log) fclose(g_log);
        g_log = nullptr;
        return 0;
    }

    // try to find ffmpeg now; worker thread will download if missing
    FindFFmpeg();
    PruneStaleCache();
    CreateThread(nullptr, 0, DecodeWorker, nullptr, 0, nullptr);



    // template rebuilder: waits for audio bank to provide Sound template AND
    // for DecodeWorker to finish encoding WEMs, then rebuilds and reloads our
    // custom bank with proper structures. gating on g_wemsReady avoids the
    // race where SetMedia fires with empty wemBytes and Wwise's source-plugin
    // has no media to decode, so tracks play the source's audio (or nothing).
    CreateThread(nullptr, 0, [](LPVOID) -> DWORD {
        // wait up to 5 minutes for ALL of: Sound template, audio bank, WEMs.
        // decoding + encoding 36+ tracks can take a couple of minutes the
        // first time when the .cache/ folder is cold.
        for (int w = 0; w < 600; w++) {
            bool templatesReady = (g_realSoundSize != 0 && g_audioBank != nullptr);
            if (templatesReady && g_wemsReady) break;
            Sleep(500);
        }
        if (g_realSoundSize == 0) {
            Log("[MUSICMOD] template rebuilder: timeout waiting for Sound template\n");
            return 0;
        }
        if (!g_wemsReady) {
            Log("[MUSICMOD] template rebuilder: timeout waiting for WEMs; "
                "will proceed with whatever loaded so far\n");
        }
        // give the audio bank scan a beat to also capture Action/Event templates from it
        Sleep(2000);
        Log("[MUSICMOD] template rebuilder: ready (sound=%u action=%u event=%u audioBank=%u wemsReady=%d), rebuilding bank...\n",
            g_realSoundSize, g_realActionSize, g_realEventSize, g_audioBankSize, (int)g_wemsReady);

        if (!g_loadBankMemoryCopy || g_tracks.empty()) return 0;

        uint32_t bankSize = 0;
        // try the EXTENDED bank approach first (append items to the real audio bank
        // so our items inherit the working bus routing). fall back to standalone bank
        // if no real audio bank was captured.
        uint8_t* bankData = nullptr;
        bool extended = false;
        if (g_audioBank && g_audioBankSize > 0) {
            // Use the MINIMAL bank instead of the duplicated ExtendedBank: Wwise's
            // music engine apparently skips music-node registration for banks that
            // duplicate already-loaded content. The minimal bank has only our 6
            // new items per track.
            bankData = BuildMinimalMusicBank((int)g_tracks.size(), &bankSize, 0xAD000003u);
            extended = (bankData != nullptr);
        }
        if (!bankData) {
            bankData = BuildCustomBank((int)g_tracks.size(), &bankSize);
            if (bankData && bankSize > 16 && memcmp(bankData, "BKHD", 4) == 0) {
                *(uint32_t*)(bankData + 8 + 4) = 0xAD000002u;
            }
        }
        if (!bankData) return 0;

        // dump for inspection
        char bankPath[MAX_PATH];
        snprintf(bankPath, MAX_PATH, "%s\\sd_music\\.cache\\custom_%s.bnk",
            g_gameDir, extended ? "ext" : "min");
        FILE* bf = fopen(bankPath, "wb");
        if (bf) { fwrite(bankData, 1, bankSize, bf); fclose(bf); }

        // SetMedia with our PCM WEM bytes BEFORE bank load. The WEM is a
        // standard RIFF with wFormatTag=0xFFFE (EXTENSIBLE) that Wwise's
        // PCM source plugin reads directly.
        if (g_setMedia) {
            for (size_t i = 0; i < g_tracks.size(); i++) {
                if (!g_tracks[i].isReady || g_tracks[i].wemBytes.empty()) continue;
                AkSourceSettings ss = {};
                ss.sourceID = 0xAD400000u + (uint32_t)i;
                ss.pMediaMemory = g_tracks[i].wemBytes.data();
                ss.uMediaSize = (uint32_t)g_tracks[i].wemBytes.size();
                int32_t mr = g_setMedia(&ss, 1);
                Log("[MUSICMOD] (pre-load) SetMedia(media=%u, WEM size=%u) result=%d\n",
                    ss.sourceID, ss.uMediaSize, mr);
            }
        }

        // SAFE_MODE: if sd_music\.cache\NO_BANK exists, skip our bank load
        // entirely. UI tracks still show, but cloned audio chains have nothing
        // to resolve to, so playback will fall back to source. Use this to
        // isolate whether our bank causes the crash.
        char noBankPath[MAX_PATH];
        snprintf(noBankPath, MAX_PATH, "%s\\sd_music\\.cache\\NO_BANK", g_gameDir);
        bool skipBank = (GetFileAttributesA(noBankPath) != INVALID_FILE_ATTRIBUTES);
        uint32_t bankId = 0;
        int32_t result = 1;
        if (skipBank) {
            Log("[MUSICMOD] SAFE_MODE: skipping bank load (NO_BANK file present)\n");
        } else {
            result = g_loadBankMemoryCopy(bankData, bankSize, &bankId);
            Log("[MUSICMOD] %s bank load: result=%d bankId=%u size=%u\n",
                extended ? "EXTENDED" : "REBUILT", result, bankId, bankSize);
        }

        // Re-call SetMedia AFTER bank load too (defense in depth: some Wwise
        // variants register source ownership at bank-load and need the media
        // still present in their table afterward).
        if (result == 1 && g_setMedia) {
            for (size_t i = 0; i < g_tracks.size(); i++) {
                if (!g_tracks[i].isReady || g_tracks[i].wemBytes.empty()) continue;
                AkSourceSettings ss = {};
                ss.sourceID = 0xAD400000u + (uint32_t)i;
                ss.pMediaMemory = g_tracks[i].wemBytes.data();
                ss.uMediaSize = (uint32_t)g_tracks[i].wemBytes.size();
                int32_t mr = g_setMedia(&ss, 1);
                Log("[MUSICMOD] (post-load) SetMedia(media=%u, WEM size=%u) result=%d\n",
                    ss.sourceID, ss.uMediaSize, mr);
            }

        }
        return 0;
    }, nullptr, 0, nullptr);

    HMODULE hExe = GetModuleHandleA(nullptr);
    Log("[MUSICMOD] main module: %p (size: 0x%llX)\n",
        hExe, (unsigned long long)GetModuleImageSize((uintptr_t)hExe));

    // Game-module detection is deferred until Wwise exports resolve
    // successfully below. Previously this ran as a 30-sec retry loop at init
    // start, but Wwise gets forwarded through main AFTER DRM unpacks, so the
    // loop would time out with null results. Now we use g_postEventAddr
    // (resolved later) as the anchor for VirtualQuery + signature scan.
    // Game-base + WSSI hooks are ALWAYS deferred to after Wwise exports
    // resolve (below). Having a single installation path avoids the
    // double-install crash that happened when both the early path AND the
    // deferred path tried to hook the same functions.
    g_gameBase = 0;
    HMODULE hGame = (HMODULE)g_gameBase;

    // Legacy dead block left in place for easy revert if the deferred
    // approach breaks. Guarded by `if (g_gameBase != 0)` which is always
    // false here, so this never runs.
    if (g_gameBase != 0) {
        // Signature-scan for all function addresses + derive data symbols
        // (vtable, singleton) from RIP-relative refs. Robust to game updates
        // that shift absolute offsets but keep prologue bytes.
        ResolveGameAddresses();
        g_musicCallbackAddr = g_gameBase + 0x26B5080; // sub_1426B5080 music callback (TODO: sig this)

        Log("[MUSICMOD] WSSI resolved: factoryA=%p factoryB=%p play=%p vtable=%p musicSysPtr=%p\n",
            (void*)g_wssiFactoryA, (void*)g_wssiFactoryB, (void*)g_wssiPlayFn,
            (void*)g_wssiVtable, (void*)g_musicSystemPtr);

        // WSSI hooks via MinHook - safer than our 14-byte JMP trampoline because
        // MinHook uses HDE disassembly to relocate relative branches in the prologue.
        void* factoryA = (void*)g_wssiFactoryA;
        void* factoryB = (void*)g_wssiFactoryB;
        void* playFn   = (void*)g_wssiPlayFn;

        if (LooksLikeFunctionPrologue(factoryA)) {
            void* tr = InstallHookMH(factoryA, (void*)Hook_WSSIFactory, "WSSI factoryA");
            if (tr) g_origWSSIFactory = (WSSIFactoryFn)tr;
        } else {
            Log("[MUSICMOD] WSSI factoryA prologue mismatch at %p - SKIPPED\n", factoryA);
        }
        if (LooksLikeFunctionPrologue(factoryB)) {
            void* tr = InstallHookMH(factoryB, (void*)Hook_WSSIFactoryB, "WSSI factoryB");
            if (tr) g_origWSSIFactoryB = (WSSIFactoryFn)tr;
        } else {
            Log("[MUSICMOD] WSSI factoryB prologue mismatch at %p - SKIPPED\n", factoryB);
        }
        if (LooksLikeFunctionPrologue(playFn)) {
            void* tr = InstallHookMH(playFn, (void*)Hook_WSSIPlay, "WSSI Play");
            if (tr) g_origWSSIPlay = (WSSIPlayFn)tr;
        } else {
            Log("[MUSICMOD] WSSI Play prologue mismatch at %p - SKIPPED\n", playFn);
        }

        // WSSI GetPositionSeconds hook - fixes the music player UI timer for
        // custom tracks (it stays at 0:00 because our WSSI never gets a real
        // playingId stored at +0x32C; we override using g_lastCustomPlayingId)
        if (g_wssiGetPosFn && LooksLikeFunctionPrologue((void*)g_wssiGetPosFn)) {
            void* tr = InstallHookMH((void*)g_wssiGetPosFn, (void*)Hook_WSSIGetPos, "WSSI GetPos");
            if (tr) g_origWSSIGetPos = (WSSIGetPosFn)tr;
        }

    } else {
        Log("[MUSICMOD] skipping WSSI/vtable/music-ptr hooks (no game base)\n");
    }

    // --- Strategy: hook the streaming system ---
    // The UI only shows tracks registered with the streaming system.
    // Find StreamingManager via its instance-store pattern, register our listener.
    // OnFinishLoadGroup will fire when DSMusicPlayerSystemResource loads,
    // giving us the chance to inject tracks as registered objects.

    // Use hExe (main module) for the pattern scan — it's always valid even
    // when g_gameBase is 0. The streaming manager lives in main-module .text
    // regardless of DRM architecture.
    uintptr_t gameBase = g_gameBase ? g_gameBase : (uintptr_t)hExe;
    uintptr_t textStart = 0, textEnd = 0;
    GetPESection(gameBase, ".text", &textStart, &textEnd);
    size_t textSize = textEnd - textStart;
    Log("[MUSICMOD] .text: %p - %p (%llu bytes)\n",
        (void*)textStart, (void*)textEnd, (unsigned long long)textSize);

    // scan for StreamingManager instance store pattern
    uintptr_t instAddr = ScanPattern(textStart, textSize, SIG_STREAMING_INSTANCE);
    if (!instAddr) {
        Log("[MUSICMOD] StreamingManager instance pattern not found\n");
        goto resolve_wwise;
    }
    Log("[MUSICMOD] StreamingManager sig @ %p\n", (void*)instAddr);

    {
        uintptr_t globalPtrAddr = ResolveRip(instAddr, 3);
        Log("[MUSICMOD] StreamingManager global ptr @ %p\n", (void*)globalPtrAddr);

        void** pManager = (void**)globalPtrAddr;

        // poll until the StreamingManager instance exists
        Log("[MUSICMOD] waiting for StreamingManager...\n");
        for (int i = 0; i < 600 && !*pManager; i++) Sleep(100);

        if (!*pManager) {
            Log("[MUSICMOD] StreamingManager never created\n");
            goto resolve_wwise;
        }

        void* manager = *pManager;
        Log("[MUSICMOD] StreamingManager @ %p\n", manager);
        RegisterListener(manager);
    }
resolve_wwise:

    // resolve Wwise exports (all on DS2.exe, the main module)
    g_postEventAddr = (void*)GetProcAddress(hExe, WWISE_POSTEVENT_MANGLED);
    g_postEventNameAddr = (void*)GetProcAddress(hExe, WWISE_POSTEVENT_NAME_MANGLED);
    g_getIDFromString = (GetIDFromStringFn)GetProcAddress(hExe, WWISE_GETID_MANGLED);
    g_stopPlayingID = (StopPlayingIDFn)GetProcAddress(hExe, WWISE_STOPPLAYINGID_MANGLED);
    g_seekOnEvent = (SeekOnEventFn)GetProcAddress(hExe, WWISE_SEEKONEVENT_MANGLED);
    g_getSourcePlayPosition = (GetSourcePlayPositionFn)GetProcAddress(hExe,
        "?GetSourcePlayPosition@SoundEngine@AK@@YA?AW4AKRESULT@@IPEAH_N@Z");

    Log("[MUSICMOD] Wwise exports:\n");
    Log("[MUSICMOD]   PostEvent(ID)   = %p\n", g_postEventAddr);
    Log("[MUSICMOD]   PostEvent(name) = %p\n", g_postEventNameAddr);
    Log("[MUSICMOD]   GetIDFromString = %p\n", (void*)g_getIDFromString);
    Log("[MUSICMOD]   StopPlayingID   = %p\n", (void*)g_stopPlayingID);
    Log("[MUSICMOD]   SeekOnEvent     = %p\n", (void*)g_seekOnEvent);

    // resolve SetMedia for providing PCM data to our custom Sound objects
    g_setMedia = (SetMediaFn2)GetProcAddress(hExe, WWISE_SETMEDIA_MANGLED);
    Log("[MUSICMOD]   SetMedia        = %p\n", (void*)g_setMedia);

    // resolve and hook ALL LoadBank variants to capture template
    g_loadBankMemoryCopy = (LoadBankMemoryFn)GetProcAddress(hExe, WWISE_LOADBANKMEMCOPY_MANGLED);
    g_loadBankMemoryView = (LoadBankMemoryFn)GetProcAddress(hExe, WWISE_LOADBANKMEMVIEW_MANGLED);
    g_loadBankById = (LoadBankByIdFn)GetProcAddress(hExe, WWISE_LOADBANK_ID_MANGLED);
    Log("[MUSICMOD]   LoadBankMemCopy = %p\n", (void*)g_loadBankMemoryCopy);
    Log("[MUSICMOD]   LoadBankMemView = %p\n", (void*)g_loadBankMemoryView);
    Log("[MUSICMOD]   LoadBankById    = %p\n", (void*)g_loadBankById);

    auto tryHookLoadBank = [](void* fn, void* hook, void** outOrig, const char* name) {
        if (!fn) return;
        auto p = (uint8_t*)fn;
        if (p[0] == 0x48 || p[0] == 0x40 || p[0] == 0x44 || p[0] == 0x4C ||
            p[0] == 0x55 || p[0] == 0x53 || p[0] == 0x56 || p[0] == 0x57) {
            auto h = InstallHook(fn, hook, 16);
            if (h.original) { *outOrig = h.original; Log("[MUSICMOD] %s hooked\n", name); }
        }
    };
    tryHookLoadBank((void*)g_loadBankMemoryCopy, (void*)Hook_LoadBankMemoryCopy,
                    (void**)&g_origLoadBankMemoryCopy, "LoadBankMemoryCopy");
    tryHookLoadBank((void*)g_loadBankMemoryView, (void*)Hook_LoadBankMemoryView,
                    (void**)&g_origLoadBankMemoryView, "LoadBankMemoryView");
    tryHookLoadBank((void*)g_loadBankById, (void*)Hook_LoadBankById,
                    (void**)&g_origLoadBankById, "LoadBank(byId)");

    // hook PostEvent for audio redirection
    if (g_postEventAddr) {
        // check prologue to determine stolen bytes
        auto p = (uint8_t*)g_postEventAddr;
        Log("[MUSICMOD] PostEvent prologue: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\n",
            p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
            p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);

        // common prologue: mov [rsp+X],rbx; push rbp; sub rsp,... = 15+ bytes
        // we need at least 14 bytes for JMP [rip+0]
        // verify first bytes look like a function prologue
        if (p[0] == 0x48 || p[0] == 0x40 || p[0] == 0x44 || p[0] == 0x4C || p[0] == 0x55 || p[0] == 0x53) {
            auto hook = InstallHook(g_postEventAddr, (void*)Hook_PostEvent, 16);
            if (hook.original) {
                g_origPostEvent = (PostEventByIdFn)hook.original;
                Log("[MUSICMOD] PostEvent hooked\n");
            } else {
                Log("[MUSICMOD] PostEvent hook failed\n");
            }
        } else {
            Log("[MUSICMOD] PostEvent prologue unrecognized, skipping hook\n");
        }
    }

    // hook PostEvent by name too - see actual event name strings
    if (g_postEventNameAddr) {
        auto p = (uint8_t*)g_postEventNameAddr;
        if (p[0] == 0x48 || p[0] == 0x40 || p[0] == 0x44 || p[0] == 0x4C || p[0] == 0x55 || p[0] == 0x53) {
            auto hook = InstallHook(g_postEventNameAddr, (void*)Hook_PostEventName, 16);
            if (hook.original) {
                g_origPostEventName = (PostEventByNameFn)hook.original;
                Log("[MUSICMOD] PostEvent(name) hooked\n");
            }
        }
    }

    // hook PostTrigger + SetSwitch (theory: music player uses these, not PostEvent)
    struct HookSpec { const char* name; const char* mangled; void* detour; void** orig; };
    HookSpec extras[] = {
        // ExecActionOnEvt hook DISABLED - crashed game; function may be too short
        // for MinHook to safely instrument. Re-enable after Binja inspection.
        // { "ExecActionOnEvt",  WWISE_EXECUTEACTIONONEVENT_ID_MANGLED, (void*)Hook_ExecActionOnEvent, (void**)&g_origExecActionOnEvent },
        { "PostTriggerID",    WWISE_POSTTRIGGER_ID_MANGLED, (void*)Hook_PostTriggerId,    (void**)&g_origPostTriggerId },
        { "PostTriggerA",     WWISE_POSTTRIGGER_A_MANGLED,  (void*)Hook_PostTriggerNameA, (void**)&g_origPostTriggerNameA },
        { "PostTriggerW",     WWISE_POSTTRIGGER_W_MANGLED,  (void*)Hook_PostTriggerNameW, (void**)&g_origPostTriggerNameW },
        { "SetSwitchID",      WWISE_SETSWITCH_ID_MANGLED,   (void*)Hook_SetSwitchId,      (void**)&g_origSetSwitchId },
        { "StopPlayingID",    WWISE_STOPPLAYINGID_MANGLED,  (void*)Hook_StopPlayingID,    (void**)&g_origStopPlayingID },
        // SetState hook REMOVED - fires ~1400x/sec; our 14-byte trampoline crashes hot path.
        // Need MinHook for safely patching high-frequency internal calls.
    };

    for (auto& h : extras) {
        void* addr = (void*)GetProcAddress(hExe, h.mangled);
        if (!addr) {
            Log("[MUSICMOD]   %s export not found\n", h.name);
            continue;
        }
        Log("[MUSICMOD]   %s = %p\n", h.name, addr);
        auto p = (uint8_t*)addr;
        if (p[0] == 0x48 || p[0] == 0x40 || p[0] == 0x44 || p[0] == 0x4C || p[0] == 0x55 || p[0] == 0x53) {
            auto hook = InstallHook(addr, h.detour, 16);
            if (hook.original) {
                *h.orig = hook.original;
                Log("[MUSICMOD] %s hooked\n", h.name);
            } else {
                Log("[MUSICMOD] %s hook failed\n", h.name);
            }
        } else {
            Log("[MUSICMOD] %s prologue unrecognized: %02X %02X %02X %02X\n",
                h.name, p[0], p[1], p[2], p[3]);
        }
    }

    // DEFERRED_GAME_BASE: now that Wwise exports are resolved, use the
    // PostEvent address to find the game module base via VirtualQuery, then
    // signature-scan for WSSI factory/play/vtable and install hooks.
    if (g_postEventAddr) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQuery(g_postEventAddr, &mbi, sizeof(mbi)) && mbi.AllocationBase) {
            uintptr_t allocBase = (uintptr_t)mbi.AllocationBase;
            __try {
                if (*(uint16_t*)allocBase == 0x5A4D) {
                    uint32_t peOff = *(uint32_t*)(allocBase + 0x3C);
                    if (peOff < 0x1000 && *(uint32_t*)(allocBase + peOff) == 0x00004550) {
                        g_gameBase = allocBase;
                        Log("[MUSICMOD] (deferred) game base via VirtualQuery(PostEvent@%p) -> %p\n",
                            g_postEventAddr, (void*)allocBase);
                    }
                }
            } __except(1) {
                Log("[MUSICMOD] (deferred) AllocationBase %p unreadable\n", (void*)allocBase);
            }
        }
    }

    if (g_gameBase) {
        ResolveGameAddresses();
        g_musicCallbackAddr = g_gameBase + 0x26B5080;
        Log("[MUSICMOD] (deferred) WSSI resolved: factoryA=%p factoryB=%p play=%p vtable=%p musicSysPtr=%p\n",
            (void*)g_wssiFactoryA, (void*)g_wssiFactoryB, (void*)g_wssiPlayFn,
            (void*)g_wssiVtable, (void*)g_musicSystemPtr);

        if (g_wssiFactoryA && LooksLikeFunctionPrologue((void*)g_wssiFactoryA)) {
            void* tr = InstallHookMH((void*)g_wssiFactoryA, (void*)Hook_WSSIFactory, "WSSI factoryA");
            if (tr) g_origWSSIFactory = (WSSIFactoryFn)tr;
        }
        if (g_wssiFactoryB && LooksLikeFunctionPrologue((void*)g_wssiFactoryB)) {
            void* tr = InstallHookMH((void*)g_wssiFactoryB, (void*)Hook_WSSIFactoryB, "WSSI factoryB");
            if (tr) g_origWSSIFactoryB = (WSSIFactoryFn)tr;
        }
        if (g_wssiPlayFn && LooksLikeFunctionPrologue((void*)g_wssiPlayFn)) {
            void* tr = InstallHookMH((void*)g_wssiPlayFn, (void*)Hook_WSSIPlay, "WSSI Play");
            if (tr) g_origWSSIPlay = (WSSIPlayFn)tr;
        }
        if (g_wssiGetPosFn && LooksLikeFunctionPrologue((void*)g_wssiGetPosFn)) {
            void* tr = InstallHookMH((void*)g_wssiGetPosFn, (void*)Hook_WSSIGetPos, "WSSI GetPos");
            if (tr) g_origWSSIGetPos = (WSSIGetPosFn)tr;
        }

    } else {
        Log("[MUSICMOD] (deferred) no game base - skipping WSSI hooks\n");
    }

    Log("[MUSICMOD] init complete\n");
    return 0;
}

// ============================================================
// Entry point
// ============================================================

// CreateThread hook -- bumps every new thread's stack reserve to 4MB so
// DS2's sub_1411c7550 (which needs 1.27MB inline + nested usage) doesn't
// blow the guard page. Default Windows reserve is whatever's in the PE
// header (DS2 likely set 1MB or 2MB which leaves no slack). Without this
// fix, the game crashes ~50-150s into a session in __chkstk no matter how
// light our hooks are. Must be installed in DllMain BEFORE DS2 spawns its
// render threads.
typedef HANDLE (WINAPI *CreateThreadFn)(LPSECURITY_ATTRIBUTES, SIZE_T,
                                         LPTHREAD_START_ROUTINE, LPVOID,
                                         DWORD, LPDWORD);
static CreateThreadFn g_origCreateThread = nullptr;
static volatile LONG g_threadStackBumps = 0;

static HANDLE WINAPI Hook_CreateThread(LPSECURITY_ATTRIBUTES sa,
                                        SIZE_T dwStackSize,
                                        LPTHREAD_START_ROUTINE start,
                                        LPVOID param,
                                        DWORD flags,
                                        LPDWORD outId)
{
    // ONLY intervene when caller used default size AND didn't already
    // request a reservation. This avoids breaking 3rd party DLLs that
    // pre-size their threads (FidelityFX, AMD AGS, bink2 etc).
    SIZE_T useSize = dwStackSize;
    DWORD useFlags = flags;
    if (dwStackSize == 0 && (flags & 0x10000) == 0) {
        useSize = 4 * 1024 * 1024;  // 4MB reserve
        useFlags = flags | 0x10000;
        InterlockedIncrement(&g_threadStackBumps);
    }
    return g_origCreateThread(sa, useSize, start, param, useFlags, outId);
}

static void InstallCreateThreadHook() {
    HMODULE hKernel = GetModuleHandleA("kernel32.dll");
    if (!hKernel) { OutputDebugStringA("[MUSICMOD] no kernel32"); return; }
    void* fn = (void*)GetProcAddress(hKernel, "CreateThread");
    if (!fn) { OutputDebugStringA("[MUSICMOD] no CreateThread"); return; }
    if (!EnsureMinHook()) { OutputDebugStringA("[MUSICMOD] no MH"); return; }
    void* tramp = nullptr;
    MH_STATUS s = MH_CreateHook(fn, (void*)Hook_CreateThread, &tramp);
    if (s != MH_OK) { OutputDebugStringA("[MUSICMOD] CT hook create failed"); return; }
    s = MH_EnableHook(fn);
    if (s != MH_OK) { OutputDebugStringA("[MUSICMOD] CT hook enable failed"); return; }
    g_origCreateThread = (CreateThreadFn)tramp;
    // (Log is not yet open at DllMain time, use OutputDebugString)
    OutputDebugStringA("[MUSICMOD] CreateThread hook installed");
}

// Periodic diagnostic: log how many threads we bumped.

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        // Install CreateThread hook FIRST so DS2's render threads (created
        // shortly after our DllMain returns) all get bumped stacks.
        InstallCreateThreadHook();
        CreateThread(nullptr, 0, InitThread, nullptr, 0, nullptr);
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        // Quiet shutdown: stop logging immediately so the heartbeat / decode
        // worker / hooks don't fight the OS while it tears down our threads
        // and closes file handles. Don't fclose g_log - the OS handles it,
        // and racing fclose vs in-flight Log() can deadlock or crash.
        g_shuttingDown = true;
    }
    return TRUE;
}
