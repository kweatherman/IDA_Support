
// Windows 7+ task bar progress
// Sirmabus 2015
#pragma once

namespace TaskProgress
{
    void start(HWND hwnd);
    void end();

    // Set current progress (from 0 to 100), or -1 to switch to indeterminate mode
    // Note: Indeterminate animation will not occur if animations are unchecked in Windows "Performance Options"
    void setProgress(int progress);

    // Set task bar tracking/view window source
    void setTrackingWindow(HWND hwnd);
};
