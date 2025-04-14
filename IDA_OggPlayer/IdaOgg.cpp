
// IdaOgg: A mini Vorbis Ogg clip player for IDA
// IDA Pro wrapper by Sirmabus 2015
#define WIN32_LEAN_AND_MEAN
#define WINVER       0x0A00 // _WIN32_WINNT_WIN10
#define _WIN32_WINNT 0x0A00
#include <Windows.h>
#include <exception>
#include <stdlib.h>
#include <mmsystem.h>
#include <intrin.h>
#pragma intrinsic(memcpy)

#include "IdaOgg.h"
#define STB_VORBIS_HEADER_ONLY
#include "stb_vorbis.c"

// IDA SDK
#pragma warning(push)
#pragma warning(disable:4267)  // 'argument': conversion from 'size_t' to 'uint32', possible loss of data
#include <ida.hpp>
#include <kernwin.hpp>
#pragma warning(pop)

// Required libs
#pragma comment(lib, "ida.lib")
#pragma comment(lib, "winmm.lib")

#undef MYCATCH
#define MYCATCH() catch (...) { msg("** Exception in ogg method: %s()! ***\n", __FUNCTION__); }

// Only 16bit samples are supported
const int BITS_PER_SAMPLE = 16;


// RIFF wave header
#pragma pack(push, 1)
struct WAVE_HEADER
{
    FOURCC	riffTag;
    DWORD   riffSize;
    //
    FOURCC	waveTag;
    FOURCC	fmtTag;
    int	    fmtSize;
    //
    WAVEFORMATEX wfm;
    //
    FOURCC	dataTag;
    int	    dataSize;
} static *g_buffer = NULL;
#pragma pack(pop)

// Play sound from memory
void OggPlay::playFromMemory(const PVOID source, int length, BOOL async /*= FALSE*/)
{
    PSHORT rawPcm = NULL;

    try
    {
        if (!g_buffer)
        {
            int nChannels = 0, nSamplesPerSec = 0;
            int samples = stb_vorbis_decode_memory((const unsigned char *) source, length, &nChannels, &nSamplesPerSec, &rawPcm);
            if (samples > 0)
            {
                // Space for WAV header + data
                UINT sampleSize = (samples * sizeof(short));
                if (g_buffer = (WAVE_HEADER *) _aligned_malloc((sizeof(WAVE_HEADER) + sampleSize + 64), 32))
                {
                    // Fill header
                    g_buffer->riffTag  = FOURCC_RIFF;
                    g_buffer->riffSize = ((sizeof(WAVE_HEADER) + sampleSize) - 8);  // Total file size, not including the first 8 bytes
                    //
                    g_buffer->waveTag = mmioFOURCC('W', 'A', 'V', 'E');
                    g_buffer->fmtTag  = mmioFOURCC('f', 'm', 't', ' ');
                    g_buffer->fmtSize = sizeof(WAVEFORMATEX);
                    //
                    g_buffer->wfm.wFormatTag      = WAVE_FORMAT_PCM;
                    g_buffer->wfm.nChannels       = nChannels;
                    g_buffer->wfm.nSamplesPerSec  = nSamplesPerSec;
                    g_buffer->wfm.nAvgBytesPerSec = ((nSamplesPerSec  * sizeof(short)) * nChannels);
                    g_buffer->wfm.nBlockAlign     = ((nChannels * BITS_PER_SAMPLE) / 8);
                    g_buffer->wfm.wBitsPerSample  = BITS_PER_SAMPLE;
                    g_buffer->wfm.cbSize = 0;
                    //
                    g_buffer->dataTag = mmioFOURCC('d', 'a', 't', 'a');
                    g_buffer->dataSize = sampleSize;

                    // Copy just PCM data then free the internal decode buffer
                    memcpy(&g_buffer[1], rawPcm, sampleSize);
                    free(rawPcm);
                    rawPcm = NULL;

                    // Play the decoded wave..
                    PlaySound((LPCTSTR) g_buffer, NULL, (SND_MEMORY | ((async == TRUE) ? SND_ASYNC : 0)));

                    /// Not async cleanup here
                    if (!async)
                        endPlay();
                }
            }
        }
        else
            msg(__FUNCTION__": An Ogg is already playing!\n");
    }
    MYCATCH()

    if (rawPcm)
    {
        free(rawPcm);
        rawPcm = NULL;
    }
}

// Stop the Ogg if it's still playing and do necessary clean up
void OggPlay::endPlay()
{
    try
    {
        // Stop the sound if it's playing
        PlaySound(NULL, NULL, SND_ASYNC);

        // While async mode
        if (g_buffer)
        {
            _aligned_free(g_buffer);
            g_buffer = NULL;
        }
    }
    MYCATCH()
}
