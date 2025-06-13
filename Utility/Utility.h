
// IDA utility support
#pragma once

typedef double TIMESTAMP;
#define SECOND 1
#define MINUTE (60 * SECOND)
#define HOUR   (60 * MINUTE)
#define DAY    (HOUR * 24)

// Now you can use the #pragma message to add the location of the message:
// Examples:
// #pragma message(__LOC2__ "error C9901: wish that error would exist")
#define __STR2__(x) #x
#define __STR1__(x) __STR2__(x)
#define __LOC2__ __FILE__ "("__STR1__(__LINE__)") : "

void trace(const char *format, ...);
TIMESTAMP GetTimeStamp();
TIMESTAMP GetTimeStampMS();
LPCSTR  TimeString(TIMESTAMP Time);
LPSTR   NumberCommaString(UINT64 n, __bcount(32) LPSTR buffer);
LPCSTR  bitsStr(LPSTR buffer, int buffLen, ULONG64 value, int bits);
LPCTSTR byteSizeString(UINT64 uSize);
UINT32 getChracterLength(int strtype, UINT32 byteCount);
void getDisasmText(ea_t ea, __out qstring &s);
BOOL SetClipboard(LPCSTR text);
void idaFlags2String(flags64_t f, __out qstring &s, BOOL withValue = FALSE);
void dumpFlags(ea_t ea, BOOL withValue = FALSE);
LPSTR GetErrorString(DWORD lastError, __out_bcount_z(1024) LPSTR buffer);
void DumpData(LPCVOID ptr, int size, BOOL showAscii = TRUE);
BOOL isHexStr(LPCSTR str);
long fsize(FILE *fp);
LPSTR ReplaceNameInPath(__inout_bcount(MAX_PATH) LPSTR path, __in_z LPSTR newName);
LPSTR replaceExtInPath(__inout_bcount(MAX_PATH) LPSTR path, __in_z LPSTR pathNew);
LPSTR GetEaFormatString(ea_t largestAddress, __out_bcount_z(17) LPSTR formatBuffer, BOOL leadingZero = TRUE);

// Semantic versioning for storage 32bit UINT32, using 10 bits (for 0 to 1023) for major, minor, and patch numbers
// Then 2 bits to (for up to 4 states) to indicate alpha, beta, etc.
enum VERSION_STAGE
{
	VERSION_RELEASE,
	VERSION_ALPHA,
	VERSION_BETA
};
#define MAKE_SEMANTIC_VERSION(_stage, _major, _minor, _patch) ((((UINT32)(_stage) & 3) << 30) | (((UINT32)(_major) & 0x3FF) << 20) | (((UINT32)(_minor) & 0x3FF) << 10) | ((UINT32)(_patch) & 0x3FF))
#define GET_VERSION_STAGE(_version) ((VERSION_STAGE)(((UINT32) (_version)) >> 30))
#define GET_VERSION_MAJOR(_version) ((((UINT32) (_version)) >> 20) & 0x3FF)
#define GET_VERSION_MINOR(_version) ((((UINT32) (_version)) >> 10) & 0x3FF)
#define GET_VERSION_PATCH(_version) (((UINT32) (_version)) & 0x3FF)

qstring &GetVersionString(UINT32 version, qstring& version_string);


ea_t FindBinary(ea_t start_ea, ea_t end_ea, LPCSTR pattern, LPCSTR file, int lineNumber);
#define FIND_BINARY(_start, _end, _pattern) FindBinary((_start), (_end), (_pattern), __FILE__, __LINE__)
//#define FIND_BINARY(_start, _end, _pattern) find_binary((_start), (_end), (_pattern), 16, (SEARCH_DOWN | SEARCH_NOBRK | SEARCH_NOSHOW));

// Return TRUE if at address is a string (ASCII, Unicode, etc.)
inline BOOL isString(ea_t ea){ return is_strlit(get_flags(ea)); }

// Get string type by address
// Should process the result with "get_str_type_code()" to filter any
// potential string encoding from the base type.
inline int getStringType(ea_t ea)
{
    opinfo_t oi;
    if (get_opinfo(&oi, ea, 0, get_flags(ea)))
        return(oi.strtype);
    else
        return(STRTYPE_C);
}

// Size of string sans terminator
#define SIZESTR(_x) (((sizeof(_x) / sizeof(_x[0])) - 1) - 1)

// Set object (data or function) alignment
#define ALIGN(_x_) __declspec(align(_x_))

#undef CATCH
#define CATCH() \
	catch(std::exception &ex) \
	{ \
		msg("** STD C++ exception!: What: \"%s\", Function: \"%s\" **\n", ex.what(), __FUNCTION__); \
	} \
	catch(...) \
	{ \
		msg("** C/C++ exception! Function: \"%s\" **\n", __FUNCTION__); \
	}

// Stack alignment trick, based on Douglas Walker's post
// http://www.gamasutra.com/view/feature/3975/data_alignment_part_2_objects_on_.php
#define STACKALIGN(name, type) \
	BYTE space_##name[sizeof(type) + (16-1)]; \
	type &name = *reinterpret_cast<type *>((UINT_PTR) (space_##name + (16-1)) & ~(16-1))

// Disable copy and assign in object definitions
#define DISALLOW_COPY_AND_ASSIGN(TypeName) \
    TypeName(TypeName&) = delete;          \
    void operator=(TypeName) = delete;

template <class T> inline void swap_t(T &a, T &b)
{
    T c = a;
    a = b;
    b = c;
}


// ----------------------------------------------------------------------------

// Helpers now that IDA 9+ is flat ea_t is always 64bit to us
typedef UINT32 EA_32;   // To indicate we mean a 32bit "ea_t"
typedef ea_t   EA_64;

// With IDA 9 should always be __EA64__ now
static_assert(sizeof(ea_t) == sizeof(UINT64));

// Platform helper
struct PLAT
{
    void Configure();

    BOOL isEa(flags64_t f);
	ea_t getEa(ea_t ea);
    inline EA_32 getEa32(ea_t ea){ return get_32bit(ea); }
    inline ea_t getEa64(ea_t ea){ return get_64bit(ea); }
    // Return TRUE if address is outside of IDB
    inline BOOL isBadAddress(ea_t addr) { return (addr < MinAddress || addr > MaxAddress); }
  
    BOOL is64;       // TRUE if IDB is 64bit
    UINT32 ptrSize;  // Size of pointer for this IDB
    ea_t MinAddress; // Cache of minimum known IDB address 
    ea_t MaxAddress; // "" max
};
extern PLAT plat;

#define IS_VALID_ADDR(_addr) (!plat.isBadAddress(_addr) && is_loaded(_addr))

// ----------------------------------------------------------------------------


// Critical section lock helper
class CLock
{
public:
	CLock() { InitializeCriticalSectionAndSpinCount(&m_CritSec, 20); };
	~CLock() { DeleteCriticalSection(&m_CritSec); };

	inline void lock() { EnterCriticalSection(&m_CritSec); };
	inline void unlock() { LeaveCriticalSection(&m_CritSec); };

private:
	ALIGN(16) CRITICAL_SECTION m_CritSec;
};


// Simple cache aligned expanding buffer
// For the performance benefit of skipping of alloc/free calls plus base cache alignment
template <class T, const size_t t_reserveElementCount = 0, const size_t t_elementExpandSize = 1024> class SlideBuffer
{
public:
    SlideBuffer() : m_dataPtr(NULL), m_elementCount(0)
    {
        // Initial reserved buffer size if any
        if (t_reserveElementCount)
            get(t_reserveElementCount);
    }
    ~SlideBuffer(){ clear(); }

    // Get buffer expanding the size as needed, or NULL on allocation failure
    T *get(size_t wantedElementCount = 0)
    {
        if (wantedElementCount > m_elementCount)
        {
            // Attempt to create or expand as needed
            wantedElementCount += ((m_dataPtr == NULL) ? 0 : t_elementExpandSize);
            //msg("GrowBuffer: %08X expand from %u to %u element count.\n", m_dataPtr, m_elementCount, wantedElementCount);
            if (T *dataPtr = (T *) _aligned_realloc(m_dataPtr, (sizeof(T) * wantedElementCount), 16))
            {
                m_dataPtr = dataPtr;
                m_elementCount = wantedElementCount;
            }
            else
                clear();
            _ASSERT(m_dataPtr);
        }
        return(m_dataPtr);
    }

    // Free up buffer, a clear/reset operation
    void clear()
    {
        if (m_dataPtr)
            _aligned_free(m_dataPtr);
        m_dataPtr = NULL;
        m_elementCount = 0;
    }

    // Return element size of current buffer
    size_t size(){ return(m_elementCount); }

private:
    DISALLOW_COPY_AND_ASSIGN(SlideBuffer);

    T *m_dataPtr;
    size_t m_elementCount;
};

