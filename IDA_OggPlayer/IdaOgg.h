
// IdaOgg: A mini Vorbis Ogg clip player for IDA
// Using Sean Barrett's "Ogg Vorbis decoder"
// http://nothings.org/stb_vorbis/
// IDA Pro wrapper by Sirmabus 2015
#pragma once

#ifndef _LIB
 #ifndef _DEBUG
  #pragma comment(lib, "IdaOggPlayer.LiB")
 #else
  #pragma comment(lib, "IdaOggPlayerD.LiB")
 #endif
#endif // _LIB

namespace OggPlay
{
    // Play Ogg from memory source, optionally asynchronously
    void  playFromMemory(const PVOID memory, int length, BOOL async = FALSE);

    // Stop the currently playing wave if there is one and clean up.
    // This needs to eb called after each playOggFromMemory() when done if async = TRUE
    void  endPlay();
};
