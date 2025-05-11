
// IDA utility support
#define WIN32_LEAN_AND_MEAN
#define WINVER		 0x0A00 // _WIN32_WINNT_WIN10
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <tchar.h>
#include <math.h>
#include <crtdbg.h>
#include <intrin.h>

#pragma intrinsic(memset, memcpy, strcat, strcmp, strcpy, strlen, abs, fabs, labs, atan, atan2, tan, sqrt, sin, cos)

// IDA libs
#define USE_DANGEROUS_FUNCTIONS
#define USE_STANDARD_FILE_FUNCTIONS
#define NO_OBSOLETE_FUNCS
#pragma warning(push)
#pragma warning(disable:4244) // conversion from 'ssize_t' to 'int', possible loss of data
#pragma warning(disable:4267) // conversion from 'size_t' to 'uint32', possible loss of data
#pragma warning(disable:4018) // warning C4018: '<': signed/unsigned mismatch
#include <ida.hpp>
#include <typeinf.hpp>
#pragma warning(pop)

#include <Utility.h>
#include <string>

#pragma comment(lib, "ida.lib")
#pragma comment(lib, "Winmm.lib")


static ALIGN(16) TIMESTAMP performanceFrequency = 0;
struct onInit
{
	onInit()
	{
		LARGE_INTEGER large2;
		QueryPerformanceFrequency(&large2);
		performanceFrequency = (TIMESTAMP)large2.QuadPart;
	}

} static _utilityInit;


// Get fractional floating elapsed seconds w/typically 100ns granularity
TIMESTAMP GetTimeStamp()
{
	LARGE_INTEGER large;
	QueryPerformanceCounter(&large);
	return((TIMESTAMP) large.QuadPart / performanceFrequency);
}

// Get elapsed seconds with millisecond resolution
TIMESTAMP GetTimeStampMS()
{
    // 64bit version requires Windows Vista or greater..
    return((TIMESTAMP) GetTickCount64() / (TIMESTAMP) 1000.0);
}

// Return a pretty comma formatted string for a given unsigned 64bit number number
LPSTR NumberCommaString(UINT64 n, __out_bcount_z(32) LPSTR buffer)
{
	int i = 0, c = 0;
	do
	{
		buffer[i] = ('0' + (n % 10)); i++;

		n /= 10;
		if ((c += (3 && n)) >= 3)
		{
			buffer[i] = ','; i++;
			c = 0;
		}

	} while (n);
	buffer[i] = 0;
	return _strrev(buffer);
}

// Get a pretty delta time string
LPCSTR TimeString(TIMESTAMP time)
{
	static char buffer[64];

	if(time >= HOUR)
		sprintf_s(buffer, sizeof(buffer), "%.2f hours", (time / (TIMESTAMP) HOUR));
	else
	if(time >= MINUTE)
		sprintf_s(buffer, sizeof(buffer), "%.2f minutes", (time / (TIMESTAMP) MINUTE));
	else
	if(time < (TIMESTAMP) 0.01)
		sprintf_s(buffer, sizeof(buffer), "%.2f milliseconds", (time * (TIMESTAMP) 1000.0));
	else
		sprintf_s(buffer, sizeof(buffer), "%.2f seconds", time);

	return buffer;
}

// Returns a pretty factional byte size string for given input size
LPCSTR byteSizeString(UINT64 bytes)
{
    static const UINT64 KILLOBYTE = 1024;
    static const UINT64 MEGABYTE = (KILLOBYTE * 1024); // 1048576
    static const UINT64 GIGABYTE = (MEGABYTE * 1024); // 1073741824
    static const UINT64 TERABYTE = (GIGABYTE * 1024); // 1099511627776

    #define BYTESTR(_Size, _Suffix) \
            { \
	    double fSize = ((double) bytes / (double) _Size); \
	    double fIntegral; double fFractional = modf(fSize, &fIntegral); \
	    if(fFractional > 0.05) \
		    sprintf_s(buffer, sizeof(buffer), ("%.1f " ## _Suffix), fSize); \
                                                                else \
		    sprintf_s(buffer, sizeof(buffer), ("%.0f " ## _Suffix), fIntegral); \
            }

    static char buffer[32];
    ZeroMemory(buffer, sizeof(buffer));

    if (bytes >= TERABYTE)
        BYTESTR(TERABYTE, "TB")
    else
    if (bytes >= GIGABYTE)
        BYTESTR(GIGABYTE, "GB")
    else
    if (bytes >= MEGABYTE)
        BYTESTR(MEGABYTE, "MB")
    else
    if (bytes >= KILLOBYTE)
        BYTESTR(KILLOBYTE, "KB")
    else
		sprintf_s(buffer, sizeof(buffer), "%u byte%c", (UINT32) bytes, (bytes == 1) ? 0 : 's');

    return(buffer);
}

// Make a bits dump string of 'bits' length up to 64bits
LPCSTR bitsStr(LPSTR buffer, int buffLen, ULONG64 value, int bits)
{
	char *strPtr = buffer;
	while ((--bits >= 0) && (--buffLen >= 1))
		*strPtr++ = ((char)((value >> bits) & 1) + '0');
	*strPtr = 0;
	return(buffer);
}

// Get an error string for a GetLastError() code
LPSTR GetErrorString(DWORD lastError, __out_bcount_z(1024) LPSTR buffer)
{
	if (!FormatMessageA((FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS), NULL, lastError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), buffer, 1024, NULL))
		strcpy_s(buffer, 1024, "Unknown");
	else
	{
		if (LPSTR lineFeed = strstr(buffer, "\r"))
			*lineFeed = 0;
	}
	return buffer;
}


// Dump byte range to debug output
void DumpData(LPCVOID ptr, int size, BOOL showAscii)
{
	#define RUN 16

	if(ptr && (size > 0))
	{
		__try
		{
			PBYTE pSrc = (PBYTE) ptr;
			char lineStr[256] = {0};
			int  uOffset = 0;

			// Create offset string based on input size
			char offsetStr[16];
			int iDigits = (int) strlen(_itoa(size, offsetStr, 16));
			sprintf(offsetStr, "[%%0%dX]: ", max(iDigits, 2));

			// Do runs
			char valueStr[(RUN + 1) * 3];
			while(size >= RUN)
			{
				sprintf(lineStr, offsetStr, uOffset);

				// Hex
				BYTE *pLine = pSrc;
				for(int i = 0; i < RUN; i++)
				{
					sprintf(valueStr, "%02X ", *pLine);
					strcat(lineStr, valueStr);
					++pLine;
				}

				// ASCII
				if (showAscii)
				{
					strcat(lineStr, "  ");

					pLine = pSrc;
					for (int i = 0; i < RUN; i++)
					{
						sprintf(valueStr, "%c", (*pLine >= ' ') ? *pLine : '.');
						strcat(lineStr, valueStr);
						++pLine;
					}
				}

				msg("%s\n", lineStr);
				uOffset += RUN, pSrc += RUN, size -= RUN;
			};

			// Final if not an even run line
			if(size > 0)
			{
				sprintf(lineStr, offsetStr, uOffset);

				// Hex
				BYTE *pLine = pSrc;
				for(int i = 0; i < size; i++)
				{
					sprintf(valueStr, "%02X ", *pLine);
					strcat(lineStr, valueStr);
					++pLine;
				}

				if (showAscii)
				{
					// Pad out line
					for (int i = 0; i < (RUN - size); i++) strcat(lineStr, "   ");
					strcat(lineStr, "  ");

					// ASCII
					pLine = pSrc;
					for (int i = 0; i < size; i++)
					{
						sprintf(valueStr, "%c", (*pLine >= ' ') ? *pLine : '.');
						strcat(lineStr, valueStr);
						++pLine;
					}
				}

				msg("%s\n", lineStr);
			}

		}__except(TRUE){}
	}
	#undef RUN
}


qstring &GetVersionString(UINT32 version, qstring &version_string)
{
	version_string.sprnt("%u.%u.%u", GET_VERSION_MAJOR(version), GET_VERSION_MINOR(version), GET_VERSION_PATCH(version));
	VERSION_STAGE stage = GET_VERSION_STAGE(version);
	switch (GET_VERSION_STAGE(version))
	{
		case VERSION_ALPHA:	version_string += "-alpha";	break;
		case VERSION_BETA: version_string += "-beta"; break;
	};
	return version_string;
}


// Create a ea_t format string for display purposes, w/optional leading zeros
// formatBuffer needs to be at least 16+1 plus leadingZeros character count in size
LPSTR GetEaFormatString(ea_t largestAddress, __out_bcount_z(17) LPSTR formatBuffer, BOOL leadingZero)
{	
	UINT32 digits = (UINT32) strlen(_ui64toa(largestAddress, formatBuffer, 16));	
	sprintf(formatBuffer, leadingZero ? "%%0%ullX" : "%%%ullX", digits);
	return formatBuffer;
}



// Get character size of string at given address
// Note: Byte size encoding like UTF-8 not considered
UINT32 getChracterLength(int strtype, UINT32 byteCount)
{
    return(byteCount / get_strtype_bpu(strtype));
}


// Output formated text to debugger channel
void trace(const char *format, ...)
{
    if (format)
    {
        va_list vl;
		// The OS buffer for these messages is a page/4096 size max
        char buffer[4096];
        va_start(vl, format);
        _vsntprintf_s(buffer, sizeof(buffer), SIZESTR(buffer), format, vl);
        va_end(vl);
        OutputDebugString(buffer);
    }
}

// Get a nice line of disassembled code text sans color tags
void getDisasmText(ea_t ea, __out qstring &s)
{
    s.clear();
	generate_disasm_line(&s, ea, (GENDSM_FORCE_CODE | GENDSM_REMOVE_TAGS));
}

// Return true if passed string is only hex digits
BOOL isHexStr(LPCSTR str)
{
    char c;
    while (c = *str++)
    {
        if (!isxdigit(c))
            return(FALSE);
    };
    return(TRUE);
}

// Return file size for given file handle
// Returns -1 on error
long fsize(FILE *fp)
{
    long psave, endpos;
    long result = -1;

    if ((psave = ftell(fp)) != -1L)
    {
        if (fseek(fp, 0, SEEK_END) == 0)
        {
            if ((endpos = ftell(fp)) != -1L)
            {
                fseek(fp, psave, SEEK_SET);
                result = endpos;
            }
        }
    }

    return(result);
}

// Replace or add a file extension in a path.
LPSTR replaceExtInPath(__inout_bcount(MAX_PATH) LPSTR path, __in_z LPSTR pathNew)
{
    char szDrive[_MAX_DRIVE], szDir[_MAX_DIR], szName[_MAX_FNAME];
    _splitpath_s(path, szDrive, _MAX_DRIVE, szDir, _MAX_DIR, szName, _MAX_FNAME, NULL, 0);
    _makepath_s(path, MAX_PATH, szDrive, szDir, szName, pathNew);
    return path;
}

LPSTR ReplaceNameInPath(__inout_bcount(MAX_PATH) LPSTR path, __in_z LPSTR newName)
{
	char drive[_MAX_DRIVE];
	char dir[_MAX_DIR];
	_splitpath(path, drive, dir, NULL, NULL);
	_makepath(path, drive, dir, newName, NULL);
	return path;
}


// Pattern in style IDA binary search style "48 8D 15 ?? ?? ?? ?? 48 8D 0D" helper
ea_t FindBinary(ea_t start_ea, ea_t end_ea, LPCSTR pattern, LPCSTR file, int lineNumber)
{
	compiled_binpat_vec_t searchVec;	
	qstring errorStr;
	if (parse_binpat_str(&searchVec, start_ea, pattern, 16, PBSENC_DEF1BPU, &errorStr))	
		return bin_search(start_ea, end_ea, searchVec, (BIN_SEARCH_FORWARD | BIN_SEARCH_NOBREAK | BIN_SEARCH_NOSHOW));	
	else
		msg("** parse_binpat_str() failed! Reason: \"%s\" @ %s, line #%d **", errorStr.c_str(), __FILE__, __LINE__);
	return BADADDR;
}


// ----------------------------------------------------------------------------

void PLAT::Configure()
{
	is64 = inf_is_64bit();
	ptrSize = (is64 ? sizeof(UINT64) : sizeof(UINT32));

	MaxAddress = inf_get_max_ea();
	MinAddress = inf_get_min_ea();
}

// Get address/pointer value
ea_t PLAT::getEa(ea_t ea)
{
	if (is64)
		return (ea_t) get_64bit(ea);
	else
		return (ea_t) get_32bit(ea);
}

// Returns TRUE if ea_t sized value flags
BOOL PLAT::isEa(flags64_t f)
{
	if (is64)
		return is_qword(f);
	else
		return is_dword(f);
}

// Single global instance
PLAT plat;

// ================================================================================================
// IDA flag dumping utility

// Duplicated from IDA SDK "bytes.hpp" since using these directly makes the code possible or just simpler
// * Type
#define FF_CODE 0x00000600	// Code
#define FF_DATA 0x00000400    // Data
#define FF_TAIL 0x00000200    // Tail; second, third (tail) byte of instruction or data
#define FF_UNK  0x00000000    // Unexplored

// * Data F0000000
#define DT_TYPE		0xF0000000	// Data type mask
#define FF_BYTE     0x00000000	// byte
#define FF_WORD     0x10000000	// word
#define FF_DWORD    0x20000000  // double word
#define FF_QWORD    0x30000000  // quad word
#define FF_TBYTE    0x40000000  // triple byte
#define FF_STRLIT   0x50000000  // string literal
#define FF_STRUCT   0x60000000  // struct variable
#define FF_OWORD    0x70000000  // octal word/XMM word (16 bytes/128 bits)
#define FF_FLOAT    0x80000000  // float
#define FF_DOUBLE   0x90000000  // double
#define FF_PACKREAL 0xA0000000  // packed decimal real
#define FF_ALIGN    0xB0000000  // alignment directive
//                  0xC0000000  // reserved
#define FF_CUSTOM   0xD0000000  // custom data type
#define FF_YWORD    0xE0000000  // YMM word (32 bytes/256 bits)
#define FF_ZWORD    0xF0000000  // ZMM word (64 bytes/512 bits)

// * Code F0000000
#define MS_CODE 0xF0000000	// Code type mask
#define FF_FUNC 0x10000000	// Function start
//              0x20000000    // Reserved
#define FF_IMMD 0x40000000    // Has Immediate value
#define FF_JUMP 0x80000000    // Has jump table or switch_info

// * Instruction/Data operands 0F000000
#define MS_1TYPE 0x0F000000   // Mask for the type of other operands
#define FF_1VOID 0x00000000   // Void (unknown)
#define FF_1NUMH 0x01000000   // Hexadecimal number
#define FF_1NUMD 0x02000000   // Decimal number
#define FF_1CHAR 0x03000000   // Char ('x')
#define FF_1SEG  0x04000000   // Segment
#define FF_1OFF  0x05000000   // Offset
#define FF_1NUMB 0x06000000   // Binary number
#define FF_1NUMO 0x07000000   // Octal number
#define FF_1ENUM 0x08000000   // Enumeration
#define FF_1FOP  0x09000000   // Forced operand
#define FF_1STRO 0x0A000000   // Struct offset
#define FF_1STK  0x0B000000   // Stack variable
#define FF_1FLT  0x0C000000   // Floating point number
#define FF_1CUST 0x0D000000   // Custom representation

#define MS_0TYPE 0x00F00000	// Mask for 1st arg typing
#define FF_0VOID 0x00000000   // Void (unknown)
#define FF_0NUMH 0x00100000   // Hexadecimal number
#define FF_0NUMD 0x00200000   // Decimal number
#define FF_0CHAR 0x00300000   // Char ('x')
#define FF_0SEG  0x00400000   // Segment
#define FF_0OFF  0x00500000   // Offset
#define FF_0NUMB 0x00600000   // Binary number
#define FF_0NUMO 0x00700000   // Octal number
#define FF_0ENUM 0x00800000   // Enumeration
#define FF_0FOP  0x00900000   // Forced operand
#define FF_0STRO 0x00A00000   // Struct offset
#define FF_0STK  0x00B00000   // Stack variable
#define FF_0FLT  0x00C00000   // Floating point number
#define FF_0CUST 0x00D00000   // Custom representation

// * State information 000FF800
#define MS_COMM   0x000FF800    // Mask of common bits
#define FF_FLOW   0x00010000    // Exec flow from prev instruction
#define FF_SIGN   0x00020000    // Inverted sign of operands
#define FF_BNOT   0x00040000    // Bitwise negation of operands
#define FF_UNUSED 0x00080000    // unused bit (was used for variable bytes)
#define FF_COMM   0x00000800    // Has comment 
#define FF_REF    0x00001000    // has references
#define FF_LINE   0x00002000    // Has next or prev lines 
#define FF_NAME   0x00004000    // Has name 
#define FF_LABL   0x00008000    // Has dummy name
// 000001FF
#define FF_IVL  0x00000100	// Has byte value in 000000FF

// Decode IDA address flags value into a readable string
void idaFlags2String(flags64_t f, __out qstring &s, BOOL withValue)
{
	s.clear();
    #define FTEST(_f) if(f & _f){ if(!first) s += ", "; s += #_f; first = FALSE; }

	// F0000000
	BOOL first = TRUE;
	if(is_data(f))
	{
		switch(f & DT_TYPE)
		{
			case FF_BYTE    : s += "FF_BYTE";     break;
			case FF_WORD    : s += "FF_WORD";     break;
			case FF_DWORD	: s += "FF_DWORD";    break;
			case FF_QWORD	: s += "FF_QWORD";    break;
			case FF_TBYTE	: s += "FF_TBYTE";    break;
			case FF_STRLIT	: s += "FF_STRLIT";   break;
			case FF_STRUCT  : s += "FF_STRUCT";   break;
			case FF_OWORD	: s += "FF_OWORD";    break;
			case FF_FLOAT   : s += "FF_FLOAT";	  break;
			case FF_DOUBLE  : s += "FF_DOUBLE";   break;
			case FF_PACKREAL: s += "FF_PACKREAL"; break;
			case FF_ALIGN   : s += "FF_ALIGN";    break;

			case FF_CUSTOM	: s += "FF_CUSTOM";   break;
			case FF_YWORD	: s += "FF_YWORD";    break;
			case FF_ZWORD	: s += "FF_ZWORD";    break;

		};
		first = FALSE;
	}
	else
	if(is_code(f))
	{
		if(f & MS_CODE)
		{
			FTEST(FF_FUNC);
			FTEST(FF_IMMD);
			FTEST(FF_JUMP);
		}
	}

	// 0F000000
	if(f & MS_1TYPE)
	{
		if(!first) s += ", ";
		switch(f & MS_1TYPE)
		{
			//default: s += ",FF_1VOID"; break;
			case FF_1NUMH: s += "FF_1NUMH"; break;
			case FF_1NUMD: s += "FF_1NUMD"; break;
			case FF_1CHAR: s += "FF_1CHAR"; break;
			case FF_1SEG:  s += "FF_1SEG";  break;
			case FF_1OFF:  s += "FF_1OFF";  break;
			case FF_1NUMB: s += "FF_1NUMB"; break;
			case FF_1NUMO: s += "FF_1NUMO"; break;
			case FF_1ENUM: s += "FF_1ENUM"; break;
			case FF_1FOP:  s += "FF_1FOP";  break;
			case FF_1STRO: s += "FF_1STRO"; break;
			case FF_1STK:  s += "FF_1STK";  break;
			case FF_1FLT:  s += "FF_1FLT";  break;
			case FF_1CUST: s += "FF_1CUST"; break;
		};
		first = FALSE;
	}

	// 00F00000
	if(f & MS_0TYPE)
	{
		if(!first) s += ", ";
		switch(f & MS_0TYPE)
		{
			//default: s += ",FF_0VOID"; break;
			case FF_0NUMH: s += "FF_0NUMH"; break;
			case FF_0NUMD: s += "FF_0NUMD"; break;
			case FF_0CHAR: s += "FF_0CHAR"; break;
			case FF_0SEG : s += "FF_0SEG";  break;
			case FF_0OFF : s += "FF_0OFF";  break;
			case FF_0NUMB: s += "FF_0NUMB"; break;
			case FF_0NUMO: s += "FF_0NUMO"; break;
			case FF_0ENUM: s += "FF_0ENUM"; break;
			case FF_0FOP : s += "FF_0FOP";  break;
			case FF_0STRO: s += "FF_0STRO"; break;
			case FF_0STK : s += "FF_0STK";  break;
			case FF_0FLT : s += "FF_0FLT";  break;
			case FF_0CUST: s += "FF_0CUST"; break;
		};
		first = FALSE;
	}

	// 000F0000
	if(f & 0xF0000)
	{
		FTEST(FF_FLOW);
		FTEST(FF_SIGN);
		FTEST(FF_BNOT);
		FTEST(FF_UNUSED);
	}

	// 0000F000
	if(f & 0xF000)
	{
		FTEST(FF_REF);
		FTEST(FF_LINE);
		FTEST(FF_NAME);
		FTEST(FF_LABL);
	}

	// 00000F00
	if(!first) s += ", ";
	switch(f & (FF_CODE | FF_DATA | FF_TAIL))
	{
		case FF_CODE: s += "FF_CODE"; break;
		case FF_DATA: s += "FF_DATA"; break;
		case FF_TAIL: s += "FF_TAIL"; break;
		default: s += "FF_UNK";	   break;
	};
	first = FALSE;
	if(f & FF_COMM) s += ", FF_COMM";
	if(f & FF_IVL)  s += ", FF_IVL";

	// 000000FF optional value dump
    if (withValue && (f & FF_IVL))
	{
        char buffer[16];
        sprintf_s(buffer, sizeof(buffer), ", value: %02X", (UINT32) (f & 0xFF));
		s += buffer;
	}

	#undef FTEST
}

// Dump flags at address w/optional byte value dump
void dumpFlags(ea_t ea, BOOL withValue)
{
    qstring s;
    idaFlags2String(get_flags(ea), s, withValue);
    msg("%llX Flags: %s\n", ea, s.c_str());
}
