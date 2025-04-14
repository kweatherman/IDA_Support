
// SegSelect: IDA Pro Qt multi-segment select dialog
// By Sirmabus 2015
// Version 1.3
// Docs: http://www.macromonkey.com/ida-waitboxex/
// License: Qt LGPL
#pragma once

#include <vector>

#ifndef _LIB
 #ifndef _DEBUG
  #pragma comment(lib, "SegSelect.LiB")
 #else
  #pragma comment(lib, "SegSelectD.LiB")
 #endif
#endif

namespace SegSelect
{
    // Option flags
    constexpr UINT32 CODE_HINT  = (1 << 0); // Default check any code segment(s)
    constexpr UINT32 DATA_HINT  = (1 << 1); // Default check any ".data" segment(s)
    constexpr UINT32 RDATA_HINT = (1 << 2); // "" ".rdata" segment(s)
    constexpr UINT32 XTRN_HINT  = (1 << 3); // "" ".idata" type segment(s)

    typedef std::vector<segment_t> segments;

    // Do segment selection dialog
    void select(__out segments &segs, UINT32 flags, __in_opt LPCSTR title = "Choose Segments", __in_opt LPCSTR styleSheet = NULL, __in_opt LPCSTR icon = NULL);

    // Convenience wrapper of Qt function "QApplication::processEvents();" to tick IDA's main window
    void processIdaEvents();
};
