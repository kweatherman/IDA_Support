
// WaitBoxEx: Custom IDA Pro wait box
// By Sirmabus
#define WIN32_LEAN_AND_MEAN
#define WINVER       0x0601 // _WIN32_WINNT_WIN7
#define _WIN32_WINNT 0x0601
#include <Windows.h>
#include <exception>

#include <QtWidgets/QMainWindow>

#include <QtCore/QTextStream>
#include <QtCore/QFile>
#include <QtWidgets/QApplication>
#include <QtWidgets/QProgressDialog>
#include <QtWidgets/QLabel>
#include <QtWidgets/QPushButton>
// IDA SDK Qt libs
#pragma comment(lib, "Qt5Core.lib")
#pragma comment(lib, "Qt5Gui.lib")
#pragma comment(lib, "Qt5Widgets.lib")

// Nix the many warnings about int type conversions
#pragma warning(push)
#pragma warning(disable:4244) // conversion from 'ssize_t' to 'int', possible loss of data
#pragma warning(disable:4267) // conversion from 'size_t' to 'uint32', possible loss of data
#include <ida.hpp>
#include <kernwin.hpp>
#pragma warning(pop)

#include "WaitBoxEx.h"
#include "WinTaskProgress.h"
#include "MyQProgressDialog.h"

// Alternate "Material design" inspired style
#ifdef MATERIAL_DESIGN_STYLE
#pragma message("* Material design style build *")
#endif

static const int  DAILOG_WIDTH = 250, DAILOG_HEIGHT = 105;
static const int  BUTTON_WIDTH = 90, BUTTON_HEIGHT = 25;
static const char FONT[] = { "Tahoma" };
static const UINT SHOW_DELAY = (2 * 1000);
static const UINT TARGET_UPDATE_MS = 100;
#ifndef MATERIAL_DESIGN_STYLE
static const LPCSTR CANCEL = "Cancel";
#else
static const LPCSTR CANCEL = "CANCEL";
#endif

static BOOL showState = FALSE, isUpdateReady = TRUE;
static MyQProgressDialog *prgDlg = NULL;

#undef MYCATCH
#define MYCATCH() catch (...) { msg("** Exception in WaitBoxEx method: %s()! ***\n", __FUNCTION__); }


static HWND getIdaHwnd()
{
	static HWND mainHwnd = nullptr;
	if (!mainHwnd)
	{
		foreach(QWidget *w, QApplication::topLevelWidgets())
		{
			if (QMainWindow *mw = qobject_cast<QMainWindow*>(w))
			{
				mainHwnd = HWND(mw->winId());
				break;
			}
		}
	}
	return mainHwnd;
}


static void CALLBACK timerTick(PVOID lpParam, BOOLEAN TimerOrWaitFired)
{
    isUpdateReady = TRUE;
}

// Consume mouse clicks on title bar to make it undraggable and disable the right click move and resize options
// #TODO: This doesn't catch the hotkey combinations for the move and resize functions
static LRESULT CALLBACK mouseHook(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION)
        if (((wParam == WM_NCLBUTTONDOWN) || (wParam == WM_NCRBUTTONDOWN)) && (((LPMOUSEHOOKSTRUCT) lParam)->wHitTestCode == HTCAPTION))
            return TRUE;

    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

// Hook to catch windows events to sync IDA to our wait dialog (or visa versa) since while they are on
// the same thread, they are independent.
// Hack to make our dialog act as a parent to IDA's Window since we can't actually make it one
static LRESULT CALLBACK msgHook(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION)
    {
		if (prgDlg)
		{
            LPCWPSTRUCT ms = (LPCWPSTRUCT) lParam;
            if (ms->message == WM_SIZE)
            {
                // Our Window?
                if (ms->hwnd == HWND(prgDlg->winId()))
                {
                    // Yes, make IDA Window reflect it's state
                    if (ms->wParam == SIZE_MINIMIZED)
                        ::ShowWindow(getIdaHwnd(), SW_MINIMIZE);
                    else
                    if (ms->wParam == SIZE_RESTORED)
                        ::ShowWindow(getIdaHwnd(), SW_SHOW);
                }
                else
                // Main IDA Window?
                if (ms->hwnd == getIdaHwnd())
                {
                    // Yes, make our dialog reflect the IDA Window state
                    switch (ms->wParam)
                    {
                        case SIZE_MINIMIZED:
                        ::ShowWindow(HWND(prgDlg->winId()), SW_MINIMIZE);
                        break;

					    case SIZE_RESTORED:
                        case SIZE_MAXIMIZED:
                        {
                            ::ShowWindowAsync(HWND(prgDlg->winId()), SW_SHOWNORMAL);
                            ::SetWindowPos(HWND(prgDlg->winId()), HWND_TOP, 0, 0, 0, 0, (SWP_ASYNCWINDOWPOS | SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW));
                        }
					    break;
                    };
                }
            }
        }
    }

    return CallNextHookEx(NULL, nCode, wParam, lParam);
}


// Subclass QProgressDialog()
MyQProgressDialog::MyQProgressDialog(LPCSTR titleText, LPCSTR labelText, LPCSTR styleSheet, LPCSTR icon) :
	QProgressDialog(labelText, CANCEL, 0, 100, QApplication::activeWindow()),
	m_isCanceled(FALSE),
	m_indeterminateMode(FALSE),
	m_lastProgress(-1),
	m_hMouseHook(NULL),
	m_hWinHook(NULL),
	m_hTimerQueue(NULL),
	m_hUpdateTimer(NULL)
{
    setWindowTitle(titleText);
    setAutoReset(FALSE);
    setAutoClose(FALSE);
    setWindowModality(Qt::WindowModal);
    setFixedSize(DAILOG_WIDTH, DAILOG_HEIGHT);
    setSizeGripEnabled(FALSE);

    // Qt::Tool      -- Smaller title bar with smaller 'X'
    // Qt::Popup     -- Boarderless
    // Qt::SubWindow -- Nonmodal on top with no background
    //setWindowFlags(Qt::Tool);
    // Nix the title bar help button
    setWindowFlags((windowFlags() & ~Qt::WindowContextHelpButtonHint) | Qt::WindowMinimizeButtonHint);

    // This time must elapse before dialog shows (default 4sec)
    setMinimumDuration(SHOW_DELAY);

    // Set dialog font (and children inherit)
    QFont fnt(FONT, 10, QFont::Normal);
    fnt.setStyleStrategy(QFont::PreferAntialias);
    setFont(fnt);

    // Put the progress text in the middle
    if (QProgressBar *bar = findChild<QProgressBar *>())
        bar->setAlignment(Qt::AlignCenter);

    // Optionally set Qt style sheet
    if (styleSheet && styleSheet[0])
    {
        // From a file?
        if (strncmp(styleSheet, "url(", 4) == 0)
        {
            QString fn(styleSheet + (sizeof("url(") - 1));
            fn.chop(1);

            QFile f(fn);
            if (f.open(QFile::ReadOnly | QFile::Text))
                setStyleSheet(QTextStream(&f).readAll());
        }
        else
            // No, string
            setStyleSheet(styleSheet);
    }

    // Optionally set title bar icon
    if (icon && icon[0])
        setWindowIcon(QIcon(icon));

    // Progress 0 for the control to setup internally
    setValue(0);

    // Start update interval timer
    if (m_hTimerQueue = CreateTimerQueue())
        CreateTimerQueueTimer(&m_hUpdateTimer, m_hTimerQueue, (WAITORTIMERCALLBACK) timerTick, NULL, TARGET_UPDATE_MS, TARGET_UPDATE_MS, 0);
    _ASSERT(m_hUpdateTimer != NULL);
}

MyQProgressDialog::~MyQProgressDialog()
{
    if (m_hUpdateTimer)
    {
        DeleteTimerQueueTimer(m_hTimerQueue, m_hUpdateTimer, NULL);
        m_hUpdateTimer = NULL;
    }

    if (m_hTimerQueue)
    {
        DeleteTimerQueueEx(m_hTimerQueue, NULL);
        m_hTimerQueue = NULL;
    }

    if (m_hWinHook)
    {
        UnhookWindowsHookEx(m_hWinHook);
        m_hWinHook = NULL;
    }

    if (m_hMouseHook)
    {
        UnhookWindowsHookEx(m_hMouseHook);
        m_hMouseHook = NULL;
    }
}


// Have to wait till the dialog is actually shown to tweak some things
void MyQProgressDialog::showEvent(QShowEvent *event)
{
    QProgressDialog::showEvent(event);

    // Size and position cancel button
    if (QPushButton *button = findChild<QPushButton *>())
    {
        button->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        button->setFixedSize(BUTTON_WIDTH, BUTTON_HEIGHT);
        #ifndef MATERIAL_DESIGN_STYLE
        const int FROM_BOTTOM = 6;
        #else
        const int FROM_BOTTOM = 10;
        #endif
        button->move(((DAILOG_WIDTH - BUTTON_WIDTH) / 2), ((DAILOG_HEIGHT - BUTTON_HEIGHT) - FROM_BOTTOM));
    }

    // Size and position progress bar
    if (QProgressBar *bar = findChild<QProgressBar *>())
    {
        bar->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        const int BAR_WIDTH = 232;
        #ifndef MATERIAL_DESIGN_STYLE
        bar->setFixedSize(BAR_WIDTH, 21);
        #else
        bar->setFixedSize(BAR_WIDTH, 4);
        #endif
        bar->move(((DAILOG_WIDTH - BAR_WIDTH) / 2), 40); // 41
    }

    // Hook locally some windows events
    m_hMouseHook = SetWindowsHookEx(WH_MOUSE, mouseHook, NULL, GetCurrentThreadId());
    m_hWinHook = SetWindowsHookEx(WH_CALLWNDPROC, msgHook, NULL, GetCurrentThreadId());
    _ASSERTE((m_hMouseHook != NULL) && (m_hWinHook != NULL));
    // Should be the same threads
    _ASSERTE(GetCurrentThreadId() == GetWindowThreadProcessId(getIdaHwnd(), NULL));

    // Center dialog in IDA's Window
    // Get our actual Windows size which isn't the same as DAILOG_WIDTH,DAILOG_HEIGHT
	RECT myRect;
	GetWindowRect(HWND(winId()), &myRect);
	int width  = (myRect.right - myRect.left);
	int height = (myRect.bottom - myRect.top);

	RECT idaRect;
    GetWindowRect(getIdaHwnd(), &idaRect);
	int x = idaRect.left + (((idaRect.right - idaRect.left) / 2) - (width / 2));
	int y = idaRect.top + (((idaRect.bottom - idaRect.top) / 2) - (height / 2));
    move(x, y);
}


// Show the modal wait box dialog
void WaitBox::show(LPCSTR titleText, LPCSTR labelText, LPCSTR styleSheet, LPCSTR icon)
{
    if (!showState)
    {
        try
        {
            // Create the dialog
            if (prgDlg = new MyQProgressDialog(titleText, labelText, styleSheet, icon))
            {
                // Task bar progress
                showState = isUpdateReady = TRUE;
                TaskProgress::start(getIdaHwnd());
                TaskProgress::setTrackingWindow((HWND) prgDlg->winId());
            }
        }
        MYCATCH()
    }
}

// Stop the wait box
void WaitBox::hide()
{
    if (showState)
    {
        showState = FALSE;
        try
        {
            TaskProgress::end();
            if (prgDlg)
            {
                prgDlg->close();
                delete prgDlg;
                prgDlg = NULL;
            }
        }
        MYCATCH()
    }
}

// Returns TRUE if wait box is up
BOOL WaitBox::isShowing()
{
    return (showState && (prgDlg && !prgDlg->isCanceled()));
}

// Returns TRUE if wait box is up
BOOL WaitBox::isUpdateTime(){ return isUpdateReady; }

// Set the label text
void WaitBox::setLabelText(LPCSTR labelText)
{
    try
    {
        if (prgDlg && labelText)
            prgDlg->setLabelText(labelText);
    }
    MYCATCH()
}

// Convenience export of the static Qt function "QApplication::processEvents();" to tick IDA's main msg pump
void WaitBox::processIdaEvents()
{
	try
	{
        QApplication::processEvents();
	}
	MYCATCH()
}


BOOL MyQProgressDialog::updateAndCancelCheck(int progress)
{
    if (!m_isCanceled && isUpdateReady)
    {
        if (wasCanceled())
        {
            m_isCanceled = isUpdateReady = TRUE;
            TaskProgress::end();
        }
        else
        {
            isUpdateReady = FALSE;
            if (m_indeterminateMode || (progress == -1))
            {
                if (!m_indeterminateMode)
                {
                    // Switch to indeterminateMode mode
                    m_indeterminateMode = TRUE;
                    TaskProgress::setProgress(-1);
                    setRange(0, 0);
                    m_lastProgress = 1;
                }

                // Progress value has to fluctuate for Qt animations to occur
                setValue(m_lastProgress++);
				WaitBox::processIdaEvents();
            }
            else
            {
                if (progress > 100)
                    progress = 100;
                else
                // progress 0 is a special case
                if (progress < 1)
                    progress = 1;

                if (progress != m_lastProgress)
                {
                    setValue(progress);
                    TaskProgress::setProgress(progress);
                    m_lastProgress = progress;
                }
            }

            // Let Qt event queue have a tick
			WaitBox::processIdaEvents();
        }
    }

    return m_isCanceled;
}

// Check if user canceled and optionally the update progress too w/built-in timed update limiter.
BOOL WaitBox::updateAndCancelCheck(int progress)
{
    if (showState)
    {
        if (prgDlg)
        {
            if (isUpdateReady)
                return prgDlg->updateAndCancelCheck(progress);
            else
                return FALSE;
        }
    }
	return FALSE;
}
